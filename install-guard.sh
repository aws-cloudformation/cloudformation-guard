#!/bin/sh
# This script downloads and installs cfn-guard from GitHub releases.
# It uses the latest release by default, but can be used to install a specific version using the -v option.
# It detects platforms, downloads the pre-built binary for the specified version (default latest), installs
# it in the ~/.guard/$MAJOR_VER/cfn-guard-v$MAJOR_VER-$OS_TYPE-latest/cfn-guard and symlinks ~/.guard/bin
# to the last installed binary.
#
# Environment:
#   GITHUB_TOKEN, GH_TOKEN  when set, authenticates the release lookup; GITHUB_TOKEN wins if both
#                           are. The anonymous GitHub API allows 60 requests per hour per source IP,
#                           shared by everyone behind the same address, so a corporate NAT, a VPN or
#                           a CI runner can exhaust it through no fault of the caller. An
#                           authenticated request is counted against the token instead. The `gh`
#                           CLI, if installed and logged in, is preferred over both and needs no
#                           setup -- GH_TOKEN is read because that is the variable `gh` itself
#                           documents, so a caller who set it up for `gh` has already set it.
#   GUARD_DOWNLOAD_BASE_URL overrides where release archives are fetched from. Defaults to the
#                           GitHub releases URL. Set it to a file:// or https:// prefix to install
#                           an archive built locally, which is how the install scripts are tested
#                           against the code under review rather than against the last release, and
#                           what makes an air-gapped install possible. A file:// prefix is read
#                           directly with cp, so it needs neither curl nor wget. An http:// origin also works
#                           but nothing here verifies a checksum or a signature, so whatever this
#                           points at is installed as-is: over plaintext that is anyone on the
#                           network path, not just the host you meant.
#   GUARD_API_BASE_URL      overrides where the release tag is looked up. Defaults to the GitHub
#                           REST API. Its reason to exist is the same as the variable above's:
#                           the retry and backoff below run only for responses the real API sends
#                           when its quota is already spent, which is not a state a test can ask
#                           for, so the responses have to come from somewhere a test controls.
#                           GITHUB_TOKEN is deliberately NOT sent when this points anywhere other
#                           than api.github.com -- see api_token_for. A file:// value is read
#                           directly, and setting this variable skips the `gh` lookup.

# Total seconds we are willing to spend waiting across all retries. A primary rate limit can be up
# to an hour from reset, and an installer that appears to hang for an hour is worse than one that
# fails with an explanation, so past this we stop and say what to do about it.
MAX_TOTAL_WAIT=300
# Attempts per request, and the first backoff delay when the server tells us nothing more specific.
MAX_ATTEMPTS=5
BASE_DELAY=2

DEFAULT_GITHUB_API="https://api.github.com/repos/aws-cloudformation/cloudformation-guard"
GITHUB_API="${GUARD_API_BASE_URL:-$DEFAULT_GITHUB_API}"
DEFAULT_DOWNLOAD_BASE_URL="https://github.com/aws-cloudformation/cloudformation-guard/releases/download"

main() {
	if ! (check_cmd curl || check_cmd wget); then
		err "need 'curl' or 'wget' (command not found)"
	fi
	need_cmd awk
	need_cmd mkdir
	need_cmd rm
	need_cmd uname
	need_cmd tar
	need_cmd ln

	get_os_type
	get_arch_type

	# Assigned rather than piped into a `while read` loop. err() exits, but when it was reached
	# from the left side of a pipeline it only exited that subshell: the pipeline's status came
	# from the loop, which had simply read nothing, so a failed release lookup left this script
	# exiting 0 with nothing installed.
	#
	# Command substitution propagates a nonzero status, and that is what catches get_version's own
	# failures, an unusable -v argument being the one to hand. It does not catch a failed release
	# lookup. get_latest_release ends in a pipeline whose last command is awk, awk exits 0 having
	# read nothing, and so get_version returns 0 with empty output and the `|| exit 1` below does
	# not fire. The empty check is what turns an unresolved version into a nonzero exit, so it has
	# to stay: without it, an exhausted API quota gets as far as requesting an archive from a URL
	# built out of an empty version, and reports that 404 instead of the quota that caused it.
	VERSION=$(get_version "$@") || exit 1
	if [ -z "$VERSION" ]; then
		err "unable to determine which cfn-guard version to install"
	fi

	echo "Installing cfn-guard version '${VERSION}'..."
	MAJOR_VER=$(echo "$VERSION" | awk -F '.' '{ print $1 }')
	# Versions up to and including 3.0.0 were published as an x86_64-only archive whose name carries
	# no architecture, so those are fetched by that name and refused on any other architecture.
	if [ "$MAJOR_VER" -le 2 ] || [ "$VERSION" = "3.0.0" ]; then
		if [ "$ARCH_TYPE" != "x86_64" ]; then
			err "cfn-guard version $VERSION is not available for architecture $ARCH_TYPE"
		fi
		FILENAME="cfn-guard-v$MAJOR_VER-$OS_TYPE-latest"
	else
		FILENAME="cfn-guard-v$MAJOR_VER-$ARCH_TYPE-$OS_TYPE-latest"
	fi
	mkdir -p ~/.guard/"$MAJOR_VER" ~/.guard/bin ||
		err "unable to make directories ~/.guard/$MAJOR_VER, ~/.guard/bin"

	_base_url="${GUARD_DOWNLOAD_BASE_URL:-$DEFAULT_DOWNLOAD_BASE_URL}"
	_url="${_base_url}/${VERSION}/${FILENAME}.tar.gz"

	download "$_url" /tmp/guard.tar.gz ||
		err "unable to download $_url"
	tar -C ~/.guard/"$MAJOR_VER" -xzf /tmp/guard.tar.gz ||
		err "unable to untar /tmp/guard.tar.gz"
	# Validate the extracted binary before it is linked into ~/.guard/bin.
	GUARD_BINARY="$HOME/.guard/$MAJOR_VER/$FILENAME/cfn-guard"
	"$GUARD_BINARY" help ||
		err "downloaded cfn-guard version $VERSION failed validation"
	ln -sf "$GUARD_BINARY" ~/.guard/bin ||
		err "unable to symlink to ~/.guard/bin directory"
	echo "Remember to SET PATH include PATH=\${PATH}:~/.guard/bin"
}

get_os_type() {
	_ostype="$(uname -s)"
	case "$_ostype" in
	Darwin)
		OS_TYPE="macos"
		;;

	Linux)
		# IS this RIGHT, we need to build for different ARCH as well.
		# Need more ARCH level detections
		OS_TYPE="ubuntu"
		;;

	*)
		err "unsupported OS type $_ostype"
		;;
	esac
}

get_version() {
	# Get the version from the -v option, if provided.
	while getopts 'v:' OPTION; do
		case "$OPTION" in
		v)
			VERSION="$OPTARG"
			;;
		?)
			err "Usage: install-guard.sh [-v <version>]"
			;;
		esac
	done
	# If version is not provided default to the latest version.
	if [ -z "$VERSION" ]; then
		get_latest_release
	else
		echo "$VERSION"
	fi
}

# Resolve the latest release tag, preferring whichever mechanism needs the least from the caller.
#
# 1. `gh`, if installed and authenticated, and GUARD_API_BASE_URL is unset (a configured mirror is
#    never bypassed). It reuses credentials the caller already has.
# 2. The REST API with GITHUB_TOKEN, when one is in the environment.
# 3. The REST API anonymously, which is the path subject to the 60/hour per-IP limit.
get_latest_release() {
	if [ -z "${GUARD_API_BASE_URL:-}" ] && check_cmd gh && gh auth status >/dev/null 2>&1; then
		if _tag=$(gh release view --repo aws-cloudformation/cloudformation-guard \
			--json tagName --jq '.tagName' 2>/dev/null) && [ -n "$_tag" ]; then
			echo "$_tag"
			return 0
		fi
		# Fall through rather than fail: gh being present does not guarantee it can reach the
		# API, and the plain HTTP paths below may still work.
		echo "gh was available but did not return a release; falling back to the REST API" >&2
	fi

	github_api "${GITHUB_API}/releases/latest" |
		awk -F '"' '/tag_name/ { print $4; exit }'
}

# GET a GitHub API URL to stdout, honouring the API's own backoff signals.
#
# The API tells us how long to wait and we listen, rather than guessing: `retry-after` on a
# secondary limit, and `x-ratelimit-reset` when the primary limit is exhausted. Blind exponential
# backoff would retry straight into an empty quota and report a network error for what is really a
# quota problem.
github_api() {
	_url="$1"
	_attempt=1
	_delay="$BASE_DELAY"
	_waited=0

	# A file:// origin is read directly, so it works without curl or wget.
	case "$_url" in
	file://*)
		cat -- "${_url#file://}"
		return $?
		;;
	esac

	# Resolved before the wget branch so both transports authenticate.
	_token=$(api_token_for "$_url")

	# Header-driven backoff needs curl; with only wget we retry transient failures without it.
	if ! check_cmd curl; then
		_body=$(retry_wget "$_url" "$_token") || return 1
		printf '%s\n' "$_body"
		return 0
	fi

	_hdr=$(mktemp) || err "unable to create a temporary file"
	_body=$(mktemp) || err "unable to create a temporary file"

	while :; do
		# The token goes in a config file on stdin rather than on the command line. An
		# Authorization header in argv is readable from `ps` by anyone else on the host for
		# the life of the request, which matters on shared build machines.
		#
		# `--` before the URL, so a value of GUARD_API_BASE_URL that begins with a dash is read as
		# an operand rather than as a curl option. Caller-controlled rather than remote, so this is
		# tidiness rather than a hole, but the terminator is free.
		#
		# No `-L`. A redirect out of api.github.com would otherwise carry the Authorization header
		# to whatever host the Location named; the archive download is a separate function and
		# sends no token, so nothing here needs to follow one.
		if [ -n "$_token" ]; then
			_code=$(printf 'header = "Authorization: Bearer %s"\n' "$_token" |
				curl -sS --connect-timeout 10 --max-time 60 -K - -o "$_body" -D "$_hdr" -w '%{http_code}' -- "$_url" 2>/dev/null)
		else
			_code=$(curl -sS --connect-timeout 10 --max-time 60 -o "$_body" -D "$_hdr" -w '%{http_code}' -- "$_url" 2>/dev/null)
		fi

		if [ "$_code" = "200" ]; then
			cat "$_body"
			rm -f "$_hdr" "$_body"
			return 0
		fi

		# A rejected token is not retried: drop it and ask once anonymously.
		if [ "$_code" = "401" ] && [ -n "$_token" ]; then
			echo "GitHub rejected the token (HTTP 401); retrying without it" >&2
			_token=""
			continue
		fi

		# Only transient failures are retried: no response, 429, 5xx, and a 403 that is a rate limit
		# (remaining 0 or a retry-after). Any other 4xx will not change on retry.
		_retry=0
		if is_transient_status "$_code"; then
			_retry=1
		elif [ "$_code" = "403" ]; then
			_remaining=$(header_value "$_hdr" x-ratelimit-remaining)
			_retry_after=$(header_value "$_hdr" retry-after)
			if [ "$_remaining" = "0" ] || [ -n "$_retry_after" ]; then
				_retry=1
			fi
		fi

		_sleep=$(backoff_seconds "$_hdr" "$_delay")

		if [ "$_retry" -eq 0 ] || [ "$_attempt" -ge "$MAX_ATTEMPTS" ] ||
			[ $((_waited + _sleep)) -gt "$MAX_TOTAL_WAIT" ]; then
			echo "GitHub API request failed with HTTP $_code after ${_attempt} attempt(s)." >&2
			if [ "$_retry" -eq 1 ] && { [ "$_code" = "403" ] || [ "$_code" = "429" ]; }; then
				echo "This is a rate limit rather than a problem with the release." >&2
				echo "Authenticate to raise it: set GITHUB_TOKEN, or run 'gh auth login'," >&2
				echo "or pass an explicit version with -v to skip the lookup entirely." >&2
			fi
			rm -f "$_hdr" "$_body"
			return 1
		fi

		echo "attempt ${_attempt} of ${MAX_ATTEMPTS} got HTTP ${_code}; retrying in ${_sleep}s" >&2
		sleep "$_sleep"
		_waited=$((_waited + _sleep))
		_attempt=$((_attempt + 1))
		_delay=$((_delay * 2))
	done
}

# The bearer token to send to $1, which is empty for every host but the GitHub API.
#
# The host is checked rather than assumed. GUARD_API_BASE_URL can point this script's release lookup
# at any origin, and a token that followed it there would be handed to whoever controls that origin
# -- so the check is what keeps that variable a testing and mirroring convenience rather than a way
# to exfiltrate a credential. The same reasoning already kept the token away from the archive
# download, which redirects to a separate storage host.
#
# The prefix match is on `https://api.github.com/` with the trailing slash: without it,
# `https://api.github.com.example.invalid/` would match.
api_token_for() {
	case "$1" in
	https://api.github.com/*)
		printf '%s' "${GITHUB_TOKEN:-${GH_TOKEN:-}}"
		;;
	*) ;;
	esac
}

# True when $1 is a run of digits and nothing else, so `$(( ))` on it cannot abort.
#
# A `case` pattern rather than `[ "$x" -ge 0 ]`: ksh evaluates `[` operands as arithmetic, so a
# non-numeric value can pass that test. The empty string is rejected too.
is_digits() {
	case "${1:-}" in
	'' | *[!0-9]*) return 1 ;;
	*) return 0 ;;
	esac
}

# Seconds to wait before the next attempt, from the response headers when they say, else $2.
backoff_seconds() {
	_hdrfile="$1"
	_fallback="$2"

	# retry-after is authoritative and is what a secondary limit returns.
	_retry_after=$(header_value "$_hdrfile" retry-after)
	if is_digits "$_retry_after" && [ "$_retry_after" -gt 0 ]; then
		echo "$_retry_after"
		return 0
	fi

	# A primary limit is exhausted when remaining is 0; reset is an epoch second.
	#
	# `_reset` is a response header, so it is checked as digits before the arithmetic. dash and ksh
	# abort `$(( ))` on a non-number, which would kill the command substitution, return an empty
	# delay, and fire every retry back to back against an exhausted quota.
	_remaining=$(header_value "$_hdrfile" x-ratelimit-remaining)
	_reset=$(header_value "$_hdrfile" x-ratelimit-reset)
	if [ "$_remaining" = "0" ] && is_digits "$_reset"; then
		_now=$(date +%s)
		_until=$((_reset - _now + 1))
		if [ "$_until" -gt 0 ]; then
			echo "$_until"
			return 0
		fi
	fi

	echo "$_fallback"
}

# One header's value from a `curl -D` dump, by lowercased name.
#
# Split on the first colon rather than on whitespace. HTTP allows no space after the colon, so
# `Retry-After:120` is a valid spelling -- and taking awk's `$2` on a whitespace split returned empty
# for it, which the callers above read as "the header is absent" and answered with exponential backoff
# instead of the delay the server had just named. Leading and trailing whitespace and the trailing CR
# are stripped here so the callers can compare the value directly.
header_value() {
	awk -v name="$2" '
		BEGIN { pattern = "^" name ":" }
		tolower($0) ~ pattern {
			value = substr($0, index($0, ":") + 1)
			gsub(/\r/, "", value)
			gsub(/^[ \t]+|[ \t]+$/, "", value)
			print value
			exit
		}
	' "$1"
}

# The HTTP status of the last response in a `wget -S` stderr dump $1, empty when there was none.
wget_status() {
	awk '/^ *HTTP\// { code = $2 } END { print code }' "$1"
}

# True when the `wget -S` dump $1 shows an exhausted rate limit (remaining 0, or a retry-after).
wget_rate_limited() {
	awk 'tolower($0) ~ /x-ratelimit-remaining: *0/ || tolower($0) ~ /retry-after:/ { f = 1 } END { exit !f }' "$1"
}

# Fetch $1 to stdout with wget. $2 is the bearer token, empty for none. Retries transient failures
# only, without the server's backoff hints since wget does not expose them. The token is visible to
# `ps` here because wget can only take it as an argument; this path is reached only without curl.
retry_wget() {
	_url="$1"
	_wget_token="$2"
	_attempt=1
	_delay="$BASE_DELAY"
	_waited=0
	_errf=$(mktemp) || err "unable to create a temporary file"
	while :; do
		# The exit status decides, not emptiness; `$?` is captured on the next line.
		if [ -n "$_wget_token" ]; then
			_out=$(wget -S -qO- --timeout=30 --tries=1 --header="Authorization: Bearer $_wget_token" -- "$_url" 2>"$_errf")
			_rc=$?
		else
			_out=$(wget -S -qO- --timeout=30 --tries=1 -- "$_url" 2>"$_errf")
			_rc=$?
		fi
		if [ "$_rc" -eq 0 ]; then
			rm -f "$_errf"
			printf '%s\n' "$_out"
			return 0
		fi
		_code=$(wget_status "$_errf")
		if [ "$_code" = "401" ] && [ -n "$_wget_token" ]; then
			echo "GitHub rejected the token (HTTP 401); retrying without it" >&2
			_wget_token=""
			continue
		fi
		_retry=0
		if [ -z "$_code" ] || is_transient_status "$_code"; then
			_retry=1
		elif [ "$_code" = "403" ] && wget_rate_limited "$_errf"; then
			_retry=1
		fi
		if [ "$_retry" -eq 0 ] ||
			[ "$_attempt" -ge "$MAX_ATTEMPTS" ] || [ $((_waited + _delay)) -gt "$MAX_TOTAL_WAIT" ]; then
			echo "unable to fetch $_url after ${_attempt} attempt(s) (HTTP ${_code:-none})" >&2
			rm -f "$_errf"
			return 1
		fi
		echo "attempt ${_attempt} of ${MAX_ATTEMPTS} failed; retrying in ${_delay}s" >&2
		sleep "$_delay"
		_waited=$((_waited + _delay))
		_attempt=$((_attempt + 1))
		_delay=$((_delay * 2))
	done
}

err() {
	echo "$1" >&2
	exit 1
}

need_cmd() {
	if ! check_cmd "$1"; then
		err "need '$1' (command not found)"
	fi
}

check_cmd() {
	command -v "$1" >/dev/null 2>&1
}

# True when HTTP status $1 is worth retrying: no response (000), 429, or any 5xx.
is_transient_status() {
	case "$1" in
	000 | 429 | 5??) return 0 ;;
	*) return 1 ;;
	esac
}

# Fetch a release archive to the given path. Never authenticated: the archive redirects to a
# separate download host and a credential has no business travelling there. Only transient
# failures are retried; a 404 or other client error fails at once. The destination is a path, not a
# redirect, so each retry truncates it instead of appending to a partial transfer.
download() {
	_url="$1"
	_out="$2"
	_attempt=1
	_delay="$BASE_DELAY"
	_waited=0
	case "$_url" in
	file://*)
		cp -- "${_url#file://}" "$_out"
		return $?
		;;
	esac
	while :; do
		_retry=0
		if check_cmd curl; then
			# No overall --max-time: a large archive on a slow link must finish. A stall is bounded
			# instead, as under 1 KiB/s for 30 seconds.
			_code=$(curl -sSL --connect-timeout 10 --speed-limit 1024 --speed-time 30 -o "$_out" -w '%{http_code}' -- "$_url" 2>/dev/null)
			_rc=$?
			if [ "$_rc" -eq 0 ]; then
				case "$_code" in
				2??) return 0 ;;
				esac
				is_transient_status "$_code" && _retry=1
			else
				# Transport failures: resolve, connect, timeout, TLS, reset mid-transfer.
				case "$_rc" in
				6 | 7 | 18 | 28 | 35 | 52 | 55 | 56) _retry=1 ;;
				esac
			fi
		else
			_errf=$(mktemp) || err "unable to create a temporary file"
			wget -S -qO "$_out" --timeout=30 --tries=1 -- "$_url" 2>"$_errf" && {
				rm -f "$_errf"
				return 0
			}
			_code=$(wget_status "$_errf")
			rm -f "$_errf"
			# No parseable status (busybox wget, a connection that never answered) is treated as transient.
			if [ -z "$_code" ] || is_transient_status "$_code"; then
				_retry=1
			fi
		fi
		if [ "$_retry" -eq 0 ]; then
			echo "error attempting to download from the github repository: $_url" >&2
			return 1
		fi
		if [ "$_attempt" -ge "$MAX_ATTEMPTS" ] || [ $((_waited + _delay)) -gt "$MAX_TOTAL_WAIT" ]; then
			echo "error attempting to download from the github repository: $_url" >&2
			return 1
		fi
		echo "attempt ${_attempt} of ${MAX_ATTEMPTS} failed; retrying in ${_delay}s" >&2
		sleep "$_delay"
		_waited=$((_waited + _delay))
		_attempt=$((_attempt + 1))
		_delay=$((_delay * 2))
	done
}

get_arch_type() {
	_archtype="$(uname -m)"
	case "$_archtype" in
	arm64)
		ARCH_TYPE="aarch64"
		;;
	aarch64)
		ARCH_TYPE="aarch64"
		;;
	x86_64)
		ARCH_TYPE="x86_64"
		;;

	*)
		err "unsupported architecture type $_archtype"
		;;
	esac
}

# Pass any arguments provided to main function.
main "$@"
