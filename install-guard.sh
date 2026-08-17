#!/bin/sh
# This script downloads and installs cfn-guard from GitHub releases.
# It uses the latest release by default, but can be used to install a specific version using the -v option.
# It detects platforms, downloads the pre-built binary for the specified version (default latest), installs
# it in the ~/.guard/$MAJOR_VER/cfn-guard-v$MAJOR_VER-$OS_TYPE-latest/cfn-guard and symlinks ~/.guard/bin
# to the last installed binary.
#
# Environment:
#   GITHUB_TOKEN            when set, authenticates the release lookup. The anonymous GitHub API
#                           allows 60 requests per hour per source IP, shared by everyone behind the
#                           same address, so a corporate NAT, a VPN or a CI runner can exhaust it
#                           through no fault of the caller. An authenticated request is counted
#                           against the token instead. The `gh` CLI, if installed and logged in, is
#                           preferred over this and needs no setup.
#   GUARD_DOWNLOAD_BASE_URL overrides where release archives are fetched from. Defaults to the
#                           GitHub releases URL. Set it to a file:// or http:// prefix to install an
#                           archive built locally, which is how the install scripts are tested
#                           against the code under review rather than against the last release, and
#                           what makes an air-gapped install possible.

# Total seconds we are willing to spend waiting across all retries. A primary rate limit can be up
# to an hour from reset, and an installer that appears to hang for an hour is worse than one that
# fails with an explanation, so past this we stop and say what to do about it.
MAX_TOTAL_WAIT=300
# Attempts per request, and the first backoff delay when the server tells us nothing more specific.
MAX_ATTEMPTS=5
BASE_DELAY=2

GITHUB_API="https://api.github.com/repos/aws-cloudformation/cloudformation-guard"
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
	# exiting 0 with nothing installed. Command substitution propagates the status instead.
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

	download "$_url" >/tmp/guard.tar.gz ||
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

	# Header inspection needs curl. With only wget available we still retry, just without the
	# server's guidance, which is strictly better than one attempt.
	if ! check_cmd curl; then
		_body=$(retry_wget "$_url") || return 1
		echo "$_body"
		return 0
	fi

	_hdr=$(mktemp) || err "unable to create a temporary file"
	_body=$(mktemp) || err "unable to create a temporary file"

	while :; do
		# The token goes in a config file on stdin rather than on the command line. An
		# Authorization header in argv is readable from `ps` by anyone else on the host for
		# the life of the request, which matters on shared build machines. Only ever sent to
		# api.github.com: the release archive redirects to a separate download host and a
		# credential has no business travelling there.
		if [ -n "${GITHUB_TOKEN:-}" ]; then
			_code=$(printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN" |
				curl -sS -K - -o "$_body" -D "$_hdr" -w '%{http_code}' "$_url" 2>/dev/null)
		else
			_code=$(curl -sS -o "$_body" -D "$_hdr" -w '%{http_code}' "$_url" 2>/dev/null)
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

# Seconds to wait before the next attempt, from the response headers when they say, else $2.
backoff_seconds() {
	_hdrfile="$1"
	_fallback="$2"

	# retry-after is authoritative and is what a secondary limit returns.
	_retry_after=$(awk 'tolower($1) ~ /^retry-after:/ { gsub(/\r/, "", $2); print $2; exit }' "$_hdrfile")
	if [ -n "$_retry_after" ] && [ "$_retry_after" -gt 0 ] 2>/dev/null; then
		echo "$_retry_after"
		return 0
	fi

	# A primary limit is exhausted when remaining is 0; reset is an epoch second.
	_remaining=$(awk 'tolower($1) ~ /^x-ratelimit-remaining:/ { gsub(/\r/, "", $2); print $2; exit }' "$_hdrfile")
	_reset=$(awk 'tolower($1) ~ /^x-ratelimit-reset:/ { gsub(/\r/, "", $2); print $2; exit }' "$_hdrfile")
	if [ "$_remaining" = "0" ] && [ -n "$_reset" ]; then
		_now=$(date +%s)
		_until=$((_reset - _now + 1))
		if [ "$_until" -gt 0 ]; then
			echo "$_until"
			return 0
		fi
	fi

	echo "$_fallback"
}

retry_wget() {
	_url="$1"
	_attempt=1
	_delay="$BASE_DELAY"
	_waited=0
	while :; do
		if _out=$(wget -qO- "$_url" 2>/dev/null); then
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

# Fetch a release archive to stdout. Retried, but never authenticated: see auth_header_args.
download() {
	_url="$1"
	_attempt=1
	_delay="$BASE_DELAY"
	_waited=0
	while :; do
		if check_cmd curl; then
			curl -fsSL "$_url" && return 0
		else
			wget -qO- "$_url" && return 0
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
