#!/usr/bin/env python3
"""A stand-in for api.github.com's releases endpoint that returns a scripted response sequence.

The install scripts' backoff exists for responses only the real API produces, and only when its
quota is already spent -- which is not a state a test can ask for. Pointing the scripts at this
instead makes the sequence an input: the Nth request gets the Nth response in the scenario,
so `Retry-After`, `X-RateLimit-Reset` and retry exhaustion each become a deterministic case.

Every request is appended to the log file as `<monotonic_ms> <status> <auth|noauth>`, one line per
request. The gaps between those timestamps are what the delay assertions read, and they are
measured on this side rather than the caller's so they cannot be confused with process startup.

The third field records whether an Authorization header arrived. Overriding the API base URL is
also a way to send a bearer token somewhere it does not belong, so the scripts refuse to attach one
to any host but api.github.com -- and this is what lets a test hold them to that with a token
actually set in the environment.

Usage:
    stub_github_api.py --scenario <name> --port-file <path> --log-file <path>

The port is chosen by the OS and written to --port-file once the socket is listening, so
concurrent jobs on one runner cannot collide on a fixed number. A caller waits for that file to
appear before making its first request.
"""

import argparse
import json
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Each scenario is a list of responses, applied in order. The last entry repeats once the list is
# exhausted, which is what lets `exhaustion` return 403 to every attempt without knowing how many
# attempts the caller will make.
#
# `reset_in` is seconds from the moment the response is sent, converted to the absolute epoch
# second the real header carries. Relative, because an absolute value baked in here would go stale.
SCENARIOS = {
    # Two secondary-limit responses naming their own delay, then success. `Retry-After` is
    # authoritative, so the two delays must be 1s and 1s -- not the 2s and 4s that exponential
    # backoff would have chosen. That difference is the assertion.
    "retry-after": [
        {"status": 403, "headers": {"Retry-After": "1"}},
        {"status": 403, "headers": {"Retry-After": "1"}},
        {"status": 200},
    ],
    # A primary limit with no `Retry-After`: exhausted quota, and a reset four seconds out. The
    # caller has to compute the delay from the reset epoch rather than fall back to `BASE_DELAY`.
    #
    # Four seconds, not one, and this is load-bearing. A reset one second out yields a delay of 1-2s
    # once the script's one-second margin is added, and `BASE_DELAY` is 2 -- so the correct answer
    # and the fallback are the same number, and a script that ignored the header entirely passed.
    # That was measured: mutating the reset lookup to match nothing left the suite green. Four
    # seconds puts the derived delay at 4-5s, which no fallback produces on the first retry.
    "ratelimit-reset": [
        {"status": 403, "headers": {"X-RateLimit-Remaining": "0"}, "reset_in": 4},
        {"status": 200},
    ],
    # No backoff headers at all, so the caller has nothing to read and must fall back to doubling
    # from BASE_DELAY. Success on the third attempt keeps this to 2s + 4s; going all the way to
    # exhaustion here would add 8s and 16s to prove nothing further about the progression.
    "exponential": [
        {"status": 403},
        {"status": 403},
        {"status": 200},
    ],
    # Never succeeds. The caller must stop at MAX_ATTEMPTS and fail rather than loop, and must say
    # the failure was a rate limit. `Retry-After: 1` keeps the whole run to about four seconds; the
    # exponential fallback would make the same case take thirty.
    "exhaustion": [
        {"status": 429, "headers": {"Retry-After": "1"}},
    ],
    # 429 answered on the first retry. The narrowest case that distinguishes "retries at all" from
    # "reports the first failure", which is what the scripts did before the backoff was added.
    "succeed-after-one-429": [
        {"status": 429, "headers": {"Retry-After": "1"}},
        {"status": 200},
    ],
    # A reset header that is not a number. The scripts must fall back to exponential backoff and still
    # reach their rate-limit guidance, rather than failing on the arithmetic.
    #
    # This is the shape that mattered on PowerShell: Get-BackoffDelay is called from inside a `catch`,
    # so a throw raised there escapes the function instead of being handled, and the caller never
    # prints the guidance. The failure looked like a type-conversion complaint about Int32, for a
    # condition whose remedy is to set a token.
    "reset-not-a-number": [
        {
            "status": 403,
            "headers": {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "not-a-number"},
        },
    ],
    # A reset header past what a 32-bit signed integer can hold. Same requirement, different cause:
    # the value parses as digits and then overflows the cast. An epoch second fits Int32 only until
    # 2038, so this is also the shape that starts arriving on its own.
    "reset-overflows-int32": [
        {
            "status": 403,
            "headers": {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "99999999999"},
        },
    ],
    # `Retry-After` with no space after the colon, which HTTP permits. The delay must be honoured
    # rather than discarded: a whitespace-split parse returned an empty field for this and the callers
    # read that as "no header", falling back to a delay the server had not asked for.
    "retry-after-no-space": [
        {"status": 429, "raw_headers": [("Retry-After", "1")], "no_space": True},
        {"status": 200},
    ],
    # A redirect naming a different host. It must not be followed, because an Authorization header
    # that travelled with it would be handed to whoever controls the target. The shell script never
    # followed one -- it passes no `-L` on this call -- while `Invoke-RestMethod` follows by default and
    # PowerShell 5.1 does not strip the header across hosts, so this is the case
    # `-MaximumRedirection 0` closes.
    #
    # The target is a name reserved for documentation, so a run that did follow the redirect fails to
    # resolve rather than reaching anything.
    "redirect-elsewhere": [
        {
            "status": 302,
            "headers": {"Location": "https://example.invalid/elsewhere"},
        },
    ],
}

# The tag a 200 carries. Asserted by the callers, so a body that parsed but came from somewhere
# else would still fail the test.
STUB_TAG = "3.1.4-stub"


class StubServer(ThreadingHTTPServer):
    """ThreadingHTTPServer without the reverse DNS lookup its bind performs.

    `HTTPServer.server_bind` calls `socket.getfqdn()` on the bind address to fill in
    `server_name`. That is a reverse DNS lookup, and on a macOS CI runner 127.0.0.1 has no PTR
    record to find, so the call blocks until the resolver gives up -- measured as longer than the
    ten seconds the callers were willing to wait for the port file, with nothing on stderr because
    nothing had failed yet. It just had not returned.

    `server_name` is only used to build the CGI environment, which nothing here does, so the
    lookup buys this stub nothing and is skipped.

    Fixed here rather than by waiting it out. The callers' readiness timeout was later raised to
    30s for an unrelated reason -- a cold interpreter start on a Windows runner -- which would
    have hidden this stall instead of removing it, and a resolver that took longer than 30s would
    have brought it straight back.
    """

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


def build_handler(responses, log_path, counter):
    class Handler(BaseHTTPRequestHandler):
        # Quiet: the default logs every request to stderr, which the callers capture and assert on.
        #
        # The parameter is `format`, shadowing the builtin, because that is what the base class
        # calls it and a name mismatch in an override is a finding for a type checker that compares
        # them positionally by name. Nothing here reads it.
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            with counter["lock"]:
                index = counter["n"]
                counter["n"] += 1
            spec = responses[min(index, len(responses) - 1)]
            status = spec["status"]

            body = b""
            if status == 200:
                body = json.dumps({"tag_name": STUB_TAG}).encode()

            self.send_response(status)
            for name, value in spec.get("headers", {}).items():
                self.send_header(name, value)

            # `Name:value` with no space, which HTTP permits and `send_header` cannot produce -- it
            # always writes `Name: value`. Appended to the same buffer `send_header` fills, so it goes
            # out in order with the rest and `end_headers` flushes it.
            if spec.get("no_space"):
                for name, value in spec.get("raw_headers", []):
                    self._headers_buffer.append(
                        f"{name}:{value}\r\n".encode("latin-1", "strict")
                    )
            if "reset_in" in spec:
                self.send_header("X-RateLimit-Reset", str(int(time.time()) + spec["reset_in"]))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

            # Presence only. The value is a credential and this file is read by the test and
            # printed on failure, so recording it would put a token in a CI log.
            auth = "auth" if self.headers.get("Authorization") else "noauth"

            # Written after the response so the recorded time is when the caller could first have
            # seen it, and flushed because the caller reads this file while the server still runs.
            with counter["lock"], open(log_path, "a", encoding="utf-8") as log:
                log.write(f"{int(time.monotonic() * 1000)} {status} {auth}\n")
                log.flush()

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--log-file", required=True)
    args = parser.parse_args()

    counter = {"n": 0, "lock": threading.Lock()}
    handler = build_handler(SCENARIOS[args.scenario], args.log_file, counter)

    # Port 0 lets the OS pick, so two of these can run at once on one runner.
    server = StubServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]

    # Written last, and only once the socket is already listening, so its existence is the caller's
    # signal that a request will not be refused.
    with open(args.port_file, "w", encoding="utf-8") as handle:
        handle.write(str(port))

    print(f"stub api listening on 127.0.0.1:{port} ({args.scenario})", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
