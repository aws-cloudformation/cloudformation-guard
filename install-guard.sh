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
#                           what makes an air-gapped install possible. An http:// origin also works
#                           but nothing here verifies a checksum or a signature, so whatever this
#                           points at is installed as-is: over plaintext that is anyone on the
#                           network path, not just the host you meant.
#   GUARD_API_BASE_URL      overrides where the release tag is looked up. Defaults to the GitHub
#                           REST API. Its reason to exist is the same as the variable above's:
#                           the retry and backoff below run only for responses the real API sends
#                           when its quota is already spent, which is not a state a test can ask
#                           for, so the responses have to come from somewhere a test controls.
#                           GITHUB_TOKEN is deliberately NOT sent when this points anywhere other
#                           than api.github.com -- see api_token_for.

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
	mkdir -p ~/.guard/"$MAJOR_VER" ~/.guard/bin ||
		err "unable to make directories ~/.guard/$MAJOR_VER, ~/.guard/bin"

	_base_url="${GUARD_DOWNLOAD_BASE_URL:-$DEFAULT_DOWNLOAD_BASE_URL}"
	_archive="cfn-guard-v${MAJOR_VER}-${ARCH_TYPE}-${OS_TYPE}-latest.tar.gz"
	_url="${_base_url}/${VERSION}/${_archive}"

	download "$_url" /tmp/guard.tar.gz ||
		err "unable to download $_url"
	tar -C ~/.guard/"$MAJOR_VER" -xzf /tmp/guard.tar.gz ||
		err "unable to untar /tmp/guard.tar.gz"
	ln -sf ~/.guard/"$MAJOR_VER"/cfn-guard-v"$MAJOR_VER"-"$ARCH_TYPE"-"$OS_TYPE"-latest/cfn-guard ~/.guard/bin ||
		err "unable to symlink to ~/.guard/bin directory"
	~/.guard/bin/cfn-guard help ||
		err "cfn-guard was not installed properly"
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
# 1. `gh`, if installed and authenticated. It reuses credentials the caller already has, so it is
#    both authenticated and free of any setup on our part.
# 2. The REST API with GITHUB_TOKEN, when one is in the environment.
# 3. The REST API anonymously, which is the path subject to the 60/hour per-IP limit.
get_latest_release() {
	if check_cmd gh && gh auth status >/dev/null 2>&1; then
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

	# Resolved before the wget branch below, not after it. This used to sit under that branch, so a
	# host with wget and no curl never read it: the request went out anonymously with GITHUB_TOKEN set
	# in the environment, kept the 60-per-hour anonymous quota, and then failed with a message telling
	# the caller to set the variable they had already set.
	_token=$(api_token_for "$_url")

	# Header inspection needs curl. With only wget available we still retry, just without the
	# server's guidance, which is strictly better than one attempt.
	if ! check_cmd curl; then
		_body=$(retry_wget "$_url" "$_token") || return 1
		echo "$_body"
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
				curl -sS -K - -o "$_body" -D "$_hdr" -w '%{http_code}' -- "$_url" 2>/dev/null)
		else
			_code=$(curl -sS -o "$_body" -D "$_hdr" -w '%{http_code}' -- "$_url" 2>/dev/null)
		fi

		if [ "$_code" = "200" ]; then
			cat "$_body"
			rm -f "$_hdr" "$_body"
			return 0
		fi

		_sleep=$(backoff_seconds "$_hdr" "$_delay")

		if [ "$_attempt" -ge "$MAX_ATTEMPTS" ] ||
			[ $((_waited + _sleep)) -gt "$MAX_TOTAL_WAIT" ]; then
			echo "GitHub API request failed with HTTP $_code after ${_attempt} attempt(s)." >&2
			if [ "$_code" = "403" ] || [ "$_code" = "429" ]; then
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
# A `case` pattern rather than `[ "$x" -ge 0 ] 2>/dev/null`, which is not a portable numeric test.
# `[` compares its operands arithmetically, and what happens to a non-numeric one is per-shell:
#
#   bash, dash   `[` fails, so the guard rejects the value. This is the case that was measured, and
#                it is why the numeric-test spelling looked like it worked.
#   ksh          `[` evaluates the operands as arithmetic expressions. `not-a-number` parses as the
#                three unset names `not - a - number`, sums to 0, and `0 -ge 0` is true -- so the
#                guard returned success for exactly the input it existed to reject, the `2>/dev/null`
#                swallowed the only hint, and the fatal arithmetic below ran anyway. Measured: five
#                attempts in 22ms against a quota that was already spent, which is the same loss of
#                backoff the guard was added to prevent, reached through the guard rather than past
#                it.
#
# A pattern match reads the value as text and asks nothing of the shell's arithmetic, so all three
# agree. The empty string is rejected here, which is what lets the callers drop their separate
# `[ -n ... ]` test.
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
	# `_reset` is checked for being a number before it reaches the arithmetic below, the same way
	# `_retry_after` is above. It is a response header, so it is text this script did not write.
	#
	# What this guard prevents is the loss of the backoff itself, and the harm is bigger than the
	# diagnostic. Both halves are now measured.
	#
	# Under bash, `$((_reset - _now + 1))` with `_reset=not-a-number` evaluates the words as unset names
	# and yields a negative result, so the fallback runs and removing this guard changes nothing. Under
	# dash -- which is `#!/bin/sh` on Debian and Ubuntu, so most Linux callers and most CI runners --
	# the same expression is `Illegal number: not-a-number` and the arithmetic aborts. Under ksh it
	# aborts too, with `not: parameter not set`.
	#
	# So the guard is what has to be portable, not just present, and see is_digits for why the numeric
	# test this used to be was not: ksh admitted the value through it and aborted anyway.
	#
	# The abort is contained, which is what makes it dangerous rather than loud. It happens inside the
	# command substitution that calls this function, so the subshell dies, the caller gets an empty
	# string, and the retry loop carries on. The rate-limit guidance still prints. What is gone is the
	# wait: `sleep ""` fails, and all five attempts fire back to back in under a second against a quota
	# that is already spent. So the script hammers the limiter it exists to respect while its output
	# still reads as correct. Measured, unguarded under dash, four times over:
	#
	#     install-guard.sh: Illegal number: not-a-number
	#     attempt 2 of 5 got HTTP 403; retrying in s
	#     sleep: invalid time interval ''
	#
	# That is why the test asserts the measured gap between requests and not just that the guidance
	# appeared -- the guidance survives the defect intact, so watching it cannot detect this. The dash
	# CI job is what exercises the case; removing this guard makes the first retry arrive in about 27ms
	# where roughly 2000ms is required.
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

# Fetch $1 to stdout with wget, retrying blind. $2 is the bearer token, empty for none.
#
# Authenticated when a token is passed, which it was not before: the caller resolved the token after
# choosing this branch, so a host without curl always asked anonymously and kept the per-IP quota that
# a token exists to raise.
#
# The token goes on the command line here, where curl's `-K -` lets it go on stdin instead. `wget` has
# no equivalent that avoids argv -- `--header` is the only way to set one -- so on a shared host the
# value is briefly visible to `ps`. That is worse than the curl path and better than sending no token
# at all, and it is reached only when curl is absent.
retry_wget() {
	_url="$1"
	_wget_token="$2"
	_attempt=1
	_delay="$BASE_DELAY"
	_waited=0
	while :; do
		# The exit status decides, not whether anything came back. Reading emptiness as failure
		# would misreport a successful fetch of an empty body, and `$?` has to be captured on the
		# line after the assignment because the assignment itself resets it.
		if [ -n "$_wget_token" ]; then
			_out=$(wget -qO- --header="Authorization: Bearer $_wget_token" -- "$_url" 2>/dev/null)
			_rc=$?
		else
			_out=$(wget -qO- -- "$_url" 2>/dev/null)
			_rc=$?
		fi
		if [ "$_rc" -eq 0 ]; then
			echo "$_out"
			return 0
		fi
		if [ "$_attempt" -ge "$MAX_ATTEMPTS" ] || [ $((_waited + _delay)) -gt "$MAX_TOTAL_WAIT" ]; then
			echo "unable to fetch $_url after ${_attempt} attempt(s)" >&2
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

# Fetch a release archive to the given path. Retried, and never authenticated: the archive
# redirects to a separate download host and a credential has no business travelling there.
#
# The destination is an argument rather than a redirect on the caller's side. A redirect is opened
# once, before this function is entered, so every attempt would write to the same already-advanced
# descriptor: a retry after a transfer that died partway would append to the bytes the failed
# attempt left behind and hand back a corrupt archive. Passing the path lets each attempt truncate
# it, which is the only way the retry helps for the failure it exists for.
download() {
	_url="$1"
	_out="$2"
	_attempt=1
	_delay="$BASE_DELAY"
	_waited=0
	while :; do
		if check_cmd curl; then
			curl -fsSL -o "$_out" "$_url" && return 0
		else
			wget -qO "$_out" "$_url" && return 0
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
