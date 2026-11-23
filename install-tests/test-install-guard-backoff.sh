#!/bin/sh
# Holds install-guard.sh's rate-limit handling to the behavior it was written for.
#
# Why this exists: the installer job that already runs in CI passes an explicit version and points
# GUARD_DOWNLOAD_BASE_URL at a locally built archive. That makes get_version return early, so
# get_latest_release, github_api and backoff_seconds are never entered -- a regression in
# `Retry-After` handling, in `X-RateLimit-Reset` handling, or in the retry ceiling would leave that
# job green. Everything below drives the real entry point with no -v, so the lookup is taken.
#
# Why a stub rather than the real API: the code under test only runs on responses the API sends when
# its quota is spent. A test cannot ask api.github.com for a 429, and one that waited for a real
# limit would be neither fast nor deterministic. GUARD_API_BASE_URL exists so the response sequence
# can be an input.
#
# The assertions are on the delays the script announces AND on the request arrival gaps the stub
# measures. The announced value alone would pass if the script printed the right number and slept
# for the wrong one; the measured gap alone is a lower bound that cannot distinguish 1s from 2s
# reliably on a loaded runner. Together they pin both.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
SCRIPT="$REPO/install-guard.sh"

PYTHON=python3
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python

# curl is what reads the response headers; the wget fallback retries blind and none of the header
# assertions below apply to it. Fail loudly rather than pass vacuously on a host without curl.
command -v curl >/dev/null 2>&1 || {
	echo "FAIL: curl is required -- without it install-guard.sh takes the wget path, which does" >&2
	echo "      not read backoff headers, and every assertion here would be vacuous." >&2
	exit 1
}

WORK=$(mktemp -d)
FAILURES=0

cleanup() {
	# Kill anything still listening before the directory holding its port file goes away.
	if [ -n "${STUB_PID:-}" ]; then
		kill "$STUB_PID" 2>/dev/null || true
		wait "$STUB_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $1" >&2
	FAILURES=$((FAILURES + 1))
}

pass() {
	echo "ok: $1"
}

# `gh` is installed and authenticated on a GitHub runner, and get_latest_release prefers it over the
# REST API -- so without this the stub would never be contacted and every case would pass without
# testing anything. A stub `gh` that fails `auth status` puts the script on the REST path, which is
# the path with the backoff in it.
#
# Placed on PATH ahead of the real one rather than removing it, so the test does not depend on how
# the runner installed gh.
make_gh_absent() {
	mkdir -p "$WORK/bin"
	printf '#!/bin/sh\nexit 1\n' >"$WORK/bin/gh"
	chmod +x "$WORK/bin/gh"
	PATH="$WORK/bin:$PATH"
	export PATH
}

# Start the stub on an OS-chosen port and wait until it is listening. Sets STUB_URL and STUB_LOG.
start_stub() {
	_scenario="$1"
	_dir="$WORK/$_scenario"
	mkdir -p "$_dir"
	STUB_LOG="$_dir/requests.log"
	: >"$STUB_LOG"
	_portfile="$_dir/port"

	"$PYTHON" "$HERE/stub_github_api.py" \
		--scenario "$_scenario" \
		--port-file "$_portfile" \
		--log-file "$STUB_LOG" \
		2>"$_dir/stub.err" &
	STUB_PID=$!

	# The port file is written only after the socket is listening, so its appearance means a
	# request will not be refused. 100 x 0.1s is 10s, which is far longer than an interpreter
	# start and still bounded.
	#
	# The diagnostic reports whether the process is still alive, because the two ways this can
	# fail need different fixes and an empty stderr does not tell them apart: a stub that died
	# has a traceback to read, while a stub that is still running has stalled inside startup --
	# which is what a reverse DNS lookup in HTTPServer.server_bind did on macOS, silently, until
	# StubServer overrode it.
	_tries=0
	while [ ! -s "$_portfile" ]; do
		_tries=$((_tries + 1))
		if [ "$_tries" -gt 100 ]; then
			if kill -0 "$STUB_PID" 2>/dev/null; then
				echo "stub for $_scenario is still running but never became ready:" >&2
				echo "  it is stalled before writing $_portfile, not crashed." >&2
			else
				echo "stub for $_scenario exited before becoming ready." >&2
			fi
			echo "its stderr was:" >&2
			cat "$_dir/stub.err" >&2
			exit 1
		fi
		sleep 0.1
	done

	STUB_URL="http://127.0.0.1:$(cat "$_portfile")"
}

stop_stub() {
	[ -n "${STUB_PID:-}" ] || return 0
	kill "$STUB_PID" 2>/dev/null || true
	wait "$STUB_PID" 2>/dev/null || true
	STUB_PID=""
}

# A release archive matching what the stub's tag_name implies, so a lookup that recovers goes on to
# a successful install instead of failing on a 404 and hiding the thing under test.
#
# The payload is a shell script rather than the real binary: this test is about the release lookup,
# and building cfn-guard to prove that a tarball untars would make it depend on a compile.
stage_archive() {
	_version="$1"
	_major=${_version%%.*}
	case "$(uname -s)" in
	Darwin) _os=macos ;;
	*) _os=ubuntu ;;
	esac
	_arch=$(uname -m)
	[ "$_arch" = "arm64" ] && _arch=aarch64
	_name="cfn-guard-v${_major}-${_arch}-${_os}-latest"

	mkdir -p "$WORK/stage/$_name" "$WORK/artifacts/$_version"
	printf '#!/bin/sh\necho "cfn-guard %s (test stub)"\n' "$_version" >"$WORK/stage/$_name/cfn-guard"
	chmod +x "$WORK/stage/$_name/cfn-guard"
	tar -czf "$WORK/artifacts/$_version/${_name}.tar.gz" -C "$WORK/stage" "$_name"
}

# Run install-guard.sh with no -v, against the stub, in a throwaway HOME.
#
# HOME is redirected because the script installs into ~/.guard unconditionally. Without this the
# test would overwrite whatever cfn-guard the caller already has installed, which is not a thing a
# test may do to a developer's machine.
#
# GITHUB_TOKEN is set deliberately. The stub is not api.github.com, so a correct script sends no
# Authorization header to it, and the log records whether one arrived.
run_installer() {
	_outdir="$1"
	mkdir -p "$_outdir/home"
	set +e
	HOME="$_outdir/home" \
		GUARD_API_BASE_URL="$STUB_URL" \
		GUARD_DOWNLOAD_BASE_URL="file://$WORK/artifacts" \
		GITHUB_TOKEN="stub-token-must-not-be-sent-to-a-non-github-host" \
		sh "$SCRIPT" >"$_outdir/stdout" 2>"$_outdir/stderr"
	RUN_STATUS=$?
	set -e
}

# Announced delays, in order, from the "retrying in Ns" lines the script writes to stderr.
announced_delays() {
	awk 'match($0, /retrying in [0-9]+s/) {
		s = substr($0, RSTART, RLENGTH)
		gsub(/[^0-9]/, "", s)
		print s
	}' "$1/stderr" | tr '\n' ' ' | sed 's/ $//'
}

# Gaps in milliseconds between consecutive requests as the stub timed them.
request_gaps_ms() {
	awk 'NR > 1 { print $1 - prev } { prev = $1 }' "$1"
}

request_count() {
	awk 'END { print NR }' "$1"
}

# Assert every request arrived without an Authorization header.
assert_no_auth_reached_stub() {
	_label="$1"
	_log="$2"
	_authed=$(awk '$3 == "auth" { n++ } END { print n + 0 }' "$_log")
	if [ "$_authed" -ne 0 ]; then
		fail "$_label: GITHUB_TOKEN was sent to the stub host on $_authed request(s). The token \
must only ever go to api.github.com; GUARD_API_BASE_URL pointing elsewhere must not carry it."
	else
		pass "$_label: no Authorization header reached the non-GitHub host"
	fi
}

# ---------------------------------------------------------------------------------------------
# Retry-After is honoured, and it wins over the exponential fallback.
#
# Two 403s carrying `Retry-After: 1`, then success. The delays must be 1 and 1. Exponential backoff
# would have chosen 2 and 4, so this fails if the header is ignored -- which a `sleep $_delay` in
# place of `sleep $_sleep` would do, and nothing else in CI would catch.
# ---------------------------------------------------------------------------------------------
test_retry_after_is_honoured() {
	start_stub retry-after
	run_installer "$WORK/retry-after"

	if [ "$RUN_STATUS" -ne 0 ]; then
		fail "retry-after: expected the install to recover and exit 0, got $RUN_STATUS; stderr:
$(cat "$WORK/retry-after/stderr")"
		stop_stub
		return
	fi

	_delays=$(announced_delays "$WORK/retry-after")
	if [ "$_delays" != "1 1" ]; then
		fail "retry-after: announced delays were '$_delays', expected '1 1'. 2 and 4 would mean \
Retry-After was ignored and the exponential fallback used instead."
	else
		pass "retry-after: announced delays were 1s then 1s, not the 2s/4s fallback"
	fi

	# Each gap must be at least the second it was told to wait, and short of the 2s the fallback
	# would have produced. 900ms rather than 1000 for the lower bound: sleep(1) is permitted to
	# return marginally early and the stub timestamps the response, not the sleep.
	_i=0
	for _gap in $(request_gaps_ms "$STUB_LOG"); do
		_i=$((_i + 1))
		if [ "$_gap" -lt 900 ]; then
			fail "retry-after: gap $_i was ${_gap}ms, expected at least ~1000ms -- the script \
did not actually wait the second it announced."
		elif [ "$_gap" -ge 2000 ]; then
			fail "retry-after: gap $_i was ${_gap}ms, which is the exponential fallback's 2s \
rather than the 1s Retry-After asked for."
		fi
	done
	if [ "$_i" -ne 2 ]; then
		fail "retry-after: the stub saw $((_i + 1)) requests, expected 3 (two 403s then a 200)"
	else
		pass "retry-after: both measured gaps were ~1s, matching the header"
	fi

	if ! grep -q "3.1.4-stub" "$WORK/retry-after/stdout"; then
		fail "retry-after: the resolved version did not come from the stub's tag_name; stdout:
$(cat "$WORK/retry-after/stdout")"
	else
		pass "retry-after: installed the tag the stub returned after the limit cleared"
	fi

	assert_no_auth_reached_stub "retry-after" "$STUB_LOG"
	stop_stub
}

# ---------------------------------------------------------------------------------------------
# X-RateLimit-Reset is honoured when there is no Retry-After.
#
# One 403 with `X-RateLimit-Remaining: 0` and a reset one second out. The delay has to be derived
# from that epoch. A script that only looked at Retry-After would fall back to 2.
# ---------------------------------------------------------------------------------------------
test_ratelimit_reset_is_honoured() {
	start_stub ratelimit-reset
	run_installer "$WORK/ratelimit-reset"

	if [ "$RUN_STATUS" -ne 0 ]; then
		fail "ratelimit-reset: expected the install to recover and exit 0, got $RUN_STATUS; stderr:
$(cat "$WORK/ratelimit-reset/stderr")"
		stop_stub
		return
	fi

	# reset is now+4 and the script adds a second of margin, so 4 and 5 are both correct
	# arithmetic depending on which side of a second the two clock reads fall. 2 is the value
	# BASE_DELAY would give, and it is excluded: that is the whole point of putting the reset
	# four seconds out rather than one.
	_delays=$(announced_delays "$WORK/ratelimit-reset")
	case "$_delays" in
	4 | 5) pass "ratelimit-reset: announced a ${_delays}s wait derived from the reset epoch" ;;
	2) fail "ratelimit-reset: announced '2', which is BASE_DELAY -- the reset epoch was not read \
and the exponential fallback was used instead." ;;
	*) fail "ratelimit-reset: announced delays were '$_delays', expected '4' or '5'" ;;
	esac

	_gap=$(request_gaps_ms "$STUB_LOG" | head -n 1)
	if [ -z "$_gap" ]; then
		fail "ratelimit-reset: the stub saw only one request, so no retry happened"
	elif [ "$_gap" -lt 3500 ]; then
		fail "ratelimit-reset: retried after only ${_gap}ms for a reset four seconds out. Below \
3500ms the wait is the 2s fallback rather than the reset, and retrying before the quota resets \
walks straight back into the same empty quota."
	elif [ "$_gap" -gt 9000 ]; then
		fail "ratelimit-reset: waited ${_gap}ms for a reset four seconds out, which means the \
epoch was misread -- an hour-long primary limit would hang the installer this way."
	else
		pass "ratelimit-reset: waited ~${_gap}ms, consistent with the reset epoch and well clear \
of the 2s fallback"
	fi

	assert_no_auth_reached_stub "ratelimit-reset" "$STUB_LOG"
	stop_stub
}

# ---------------------------------------------------------------------------------------------
# With no backoff headers, the delay doubles from BASE_DELAY.
#
# This is the fallback the two cases above must NOT take, so it needs its own positive control:
# without it, a script that always slept 1s would pass both of them.
# ---------------------------------------------------------------------------------------------
test_exponential_fallback() {
	start_stub exponential
	run_installer "$WORK/exponential"

	if [ "$RUN_STATUS" -ne 0 ]; then
		fail "exponential: expected the install to recover and exit 0, got $RUN_STATUS; stderr:
$(cat "$WORK/exponential/stderr")"
		stop_stub
		return
	fi

	_delays=$(announced_delays "$WORK/exponential")
	if [ "$_delays" != "2 4" ]; then
		fail "exponential: announced delays were '$_delays', expected '2 4' -- with no header to \
read the delay must double from BASE_DELAY."
	else
		pass "exponential: announced delays doubled, 2s then 4s"
	fi

	assert_no_auth_reached_stub "exponential" "$STUB_LOG"
	stop_stub
}

# ---------------------------------------------------------------------------------------------
# Retries are bounded, and exhaustion is reported as a rate limit.
#
# A 429 to every request. The script must stop at MAX_ATTEMPTS -- exactly 5 requests, not 4 and not
# a loop -- exit nonzero, and say the cause was a quota rather than a missing release, because that
# distinction is the whole reason a caller knows to authenticate.
# ---------------------------------------------------------------------------------------------
test_exhaustion_is_bounded_and_explained() {
	start_stub exhaustion
	run_installer "$WORK/exhaustion"

	if [ "$RUN_STATUS" -eq 0 ]; then
		fail "exhaustion: the script exited 0 with nothing installed. An unresolved version must \
be a nonzero exit; exiting 0 is how a failed lookup used to pass unnoticed."
	else
		pass "exhaustion: exited $RUN_STATUS after the retries ran out"
	fi

	_requests=$(request_count "$STUB_LOG")
	if [ "$_requests" -ne 5 ]; then
		fail "exhaustion: the stub saw $_requests requests, expected exactly 5 (MAX_ATTEMPTS). \
Fewer means the ceiling is too low to survive a transient limit; more means it does not stop."
	else
		pass "exhaustion: stopped after exactly 5 attempts"
	fi

	if ! grep -q "rate limit rather than a problem with the release" "$WORK/exhaustion/stderr"; then
		fail "exhaustion: stderr did not say the failure was a rate limit; stderr:
$(cat "$WORK/exhaustion/stderr")"
	else
		pass "exhaustion: named the cause as a rate limit"
	fi

	# The three remedies, because a message that says "rate limit" without saying what to do
	# about it leaves the caller where they started.
	for _remedy in GITHUB_TOKEN "gh auth login" "\-v"; do
		if ! grep -q -- "$_remedy" "$WORK/exhaustion/stderr"; then
			fail "exhaustion: stderr did not offer '$_remedy' as a way out; stderr:
$(cat "$WORK/exhaustion/stderr")"
		fi
	done
	pass "exhaustion: offered the token, gh and explicit-version remedies"

	assert_no_auth_reached_stub "exhaustion" "$STUB_LOG"
	stop_stub
}

# ---------------------------------------------------------------------------------------------
# A single 429 is survived.
#
# The narrowest case separating "retries" from "reports the first failure", which is what the
# script did before any of this was added.
# ---------------------------------------------------------------------------------------------
test_single_429_is_survived() {
	start_stub succeed-after-one-429
	run_installer "$WORK/succeed-after-one-429"

	if [ "$RUN_STATUS" -ne 0 ]; then
		fail "single-429: one 429 must not fail the install, got exit $RUN_STATUS; stderr:
$(cat "$WORK/succeed-after-one-429/stderr")"
	elif ! grep -q "3.1.4-stub" "$WORK/succeed-after-one-429/stdout"; then
		fail "single-429: recovered but did not install the stub's tag; stdout:
$(cat "$WORK/succeed-after-one-429/stdout")"
	else
		pass "single-429: retried once and installed the tag the stub then returned"
	fi

	assert_no_auth_reached_stub "single-429" "$STUB_LOG"
	stop_stub
}

make_gh_absent
stage_archive 3.1.4-stub

test_retry_after_is_honoured
test_ratelimit_reset_is_honoured
test_exponential_fallback
test_exhaustion_is_bounded_and_explained
test_single_429_is_survived

echo
if [ "$FAILURES" -ne 0 ]; then
	echo "$FAILURES assertion(s) failed" >&2
	exit 1
fi
echo "all install-guard.sh backoff assertions passed"
