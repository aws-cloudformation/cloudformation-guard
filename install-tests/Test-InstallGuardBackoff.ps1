# Holds install-guard.ps1's rate-limit handling to the behavior it was written for.
#
# The PowerShell counterpart to test-install-guard-backoff.sh, and it exists for the same reason: the
# installer job that already runs in CI passes -Version and points GUARD_DOWNLOAD_BASE_URL at a
# locally built archive, so Get-GuardVersion returns before Invoke-GitHubApiWithBackoff and
# Get-BackoffDelay are ever entered. A regression in Retry-After handling, in X-RateLimit-Reset
# handling, or in the retry ceiling would leave that job green.
#
# Everything below launches install-guard.ps1 with no -Version, so the lookup is taken, and points it
# at a stub via GUARD_API_BASE_URL because the code under test only runs on responses the real API
# sends when its quota is spent -- which is not a state a test can ask for.
#
# The assertions are on the delays the script announces AND on the request arrival gaps the stub
# measures. The announced value alone would pass if the script printed the right number and slept for
# the wrong one; the measured gap alone cannot reliably separate adjacent values on a loaded runner.
#
# The installer is launched as a child process rather than dot-sourced. install-guard.ps1 ends in
# `main -RequestedVersion $Version`, so sourcing it would run an install rather than define its
# functions, and `err` throws -- which in-process would abort this script instead of being an outcome
# it can assert on.
#
# The helpers below are snake_case, matching install-guard.ps1's own side-effecting helpers
# (extract_tar, check_admin, update_path, download_file_to_path). That is also what keeps the
# PSScriptAnalyzer gate clean: UseApprovedVerbs, UseSingularNouns and
# UseShouldProcessForStateChangingFunctions are all always-enabled warnings that only inspect
# hyphenated Verb-Noun names, and a test harness's internal helpers are not a cmdlet surface for
# those conventions to be about.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Here = $PSScriptRoot
$script:InstallScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'install-guard.ps1'
$script:Failures = 0

# The tag the stub's 200 carries. Asserted, so a version that came from anywhere else fails.
$script:StubTag = '3.1.4-stub'

$script:Python = if (Get-Command python3 -ErrorAction SilentlyContinue) { 'python3' } else { 'python' }

$script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("guard-backoff-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $script:Work | Out-Null

function fail {
    param([string]$Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
    $script:Failures = $script:Failures + 1
}

function pass {
    param([string]$Message)
    Write-Host "ok: $Message"
}

# `gh` is installed and authenticated on a GitHub runner, and Get-TagFromGhCli prefers it over the
# REST API -- so without this the stub would never be contacted and every case below would pass
# without testing anything. A shim that fails `auth status` puts the script on the REST path, which
# is the path with the backoff in it. Prepended to PATH rather than removing the real gh, so the test
# does not depend on how the runner installed it.
function disable_gh_cli {
    $binDir = Join-Path $script:Work 'bin'
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    Set-Content -Path (Join-Path $binDir 'gh.cmd') -Value "@echo off`r`nexit /b 1" -Encoding ASCII
    $env:PATH = "$binDir$([System.IO.Path]::PathSeparator)$env:PATH"
}

# A release archive matching what the stub's tag_name implies, so a lookup that recovers goes on to a
# successful install instead of failing on a 404 and hiding the thing under test. The payload is a
# batch file rather than the real binary: this test is about the release lookup, and building
# cfn-guard to prove a tarball untars would make it depend on a compile.
function stage_archive {
    param([string]$Version)

    $major = $Version.Split('.')[0]
    $arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        'Arm64' { 'aarch64' }
        'X64' { 'x86_64' }
        'X86' { 'i686' }
        default { 'x86_64' }
    }
    $name = "cfn-guard-v$major-$arch-windows-latest"

    $stage = Join-Path $script:Work 'stage'
    $artifacts = Join-Path $script:Work "artifacts/$Version"
    New-Item -ItemType Directory -Force -Path (Join-Path $stage $name), $artifacts | Out-Null
    Set-Content -Path (Join-Path (Join-Path $stage $name) 'cfn-guard.cmd') `
        -Value "@echo off`r`necho cfn-guard $Version (test stub)" -Encoding ASCII
    tar -czf (Join-Path $artifacts "$name.tar.gz") -C $stage $name
}

# Start the stub on an OS-chosen port and wait until it is listening.
function start_stub {
    param([string]$Scenario)

    $dir = Join-Path $script:Work $Scenario
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $logFile = Join-Path $dir 'requests.log'
    Set-Content -Path $logFile -Value '' -NoNewline
    $portFile = Join-Path $dir 'port'
    $stubErr = Join-Path $dir 'stub.err'
    $stubOut = Join-Path $dir 'stub.out'

    # stdout is captured as well as stderr. A python that cannot start says so on either channel
    # depending on why -- the Windows Store interpreter alias writes its "not found, install from
    # the Store" notice to stdout -- and a diagnostic that reports only stderr prints an empty
    # string for a failure that did explain itself.
    $proc = Start-Process -FilePath $script:Python -PassThru -NoNewWindow `
        -RedirectStandardError $stubErr -RedirectStandardOutput $stubOut `
        -ArgumentList @(
        (Join-Path $script:Here 'stub_github_api.py'),
        '--scenario', $Scenario,
        '--port-file', $portFile,
        '--log-file', $logFile
    )

    # The port file is written only once the socket is listening, so its appearance means a request
    # will not be refused.
    #
    # 300 x 100ms is 30s. It was 10s, which a cold interpreter start on windows-latest exceeded once
    # -- the process was alive and had simply not got there yet, on a commit whose diff touched
    # nothing before the port file is written. 30s still reports a genuinely dead stub quickly, and
    # the reason for keeping it tight is gone: that was to avoid masking a stall inside
    # HTTPServer.server_bind, which StubServer now fixes at the source rather than waiting out.
    #
    # The diagnostic distinguishes a stub that died from one still starting, because an empty stderr
    # does not: a crash leaves a traceback, while a stall leaves nothing at all.
    $tries = 0
    while (-not (Test-Path $portFile) -or -not "$(Get-Content $portFile -Raw)".Trim()) {
        # A stub that has exited is never going to become ready, so there is nothing to wait for.
        # The port file is re-tested first because the process could in principle have written it
        # and then died between the loop condition and here.
        $dead = $proc.HasExited -and -not (Test-Path $portFile)
        $tries = $tries + 1
        if ($dead -or $tries -gt 300) {
            $err = if (Test-Path $stubErr) { Get-Content $stubErr -Raw } else { '(no stderr)' }
            $out = if (Test-Path $stubOut) { Get-Content $stubOut -Raw } else { '(no stdout)' }
            $state = if ($proc.HasExited) {
                "exited with $($proc.ExitCode) before becoming ready"
            }
            else {
                'still running after 30s, so stalled before becoming ready rather than crashed'
            }
            throw "stub for $Scenario never came up ($state);`nstdout was:`n$out`nstderr was:`n$err"
        }
        Start-Sleep -Milliseconds 100
    }

    return [pscustomobject]@{
        Process = $proc
        Uri     = "http://127.0.0.1:$("$(Get-Content $portFile -Raw)".Trim())"
        Log     = $logFile
        Dir     = $dir
    }
}

function stop_stub {
    param($Stub)
    if ($Stub -and $Stub.Process -and -not $Stub.Process.HasExited) {
        Stop-Process -Id $Stub.Process.Id -Force -ErrorAction SilentlyContinue
    }
}

# Run install-guard.ps1 with no -Version, against the stub, with USERPROFILE redirected.
#
# USERPROFILE is redirected because the script installs into $env:USERPROFILE\.guard
# unconditionally. Without this the test would overwrite whatever cfn-guard the caller already has
# installed, which is not a thing a test may do to a developer's machine.
#
# GITHUB_TOKEN is set deliberately. The stub is not api.github.com, so a correct script sends no
# Authorization header to it, and the log records whether one arrived.
function run_installer {
    param($Stub)

    $installHome = Join-Path $Stub.Dir 'home'
    New-Item -ItemType Directory -Force -Path $installHome | Out-Null
    $stdoutPath = Join-Path $Stub.Dir 'stdout'
    $stderrPath = Join-Path $Stub.Dir 'stderr'
    $artifactsUri = 'file://' + ((Join-Path $script:Work 'artifacts') -replace '\\', '/')

    # Set on this process and restored afterwards, rather than passed with Start-Process
    # -Environment: that parameter arrived in PowerShell 7.4 and this script has to run on whatever
    # pwsh the runner ships. A child process inherits the parent's environment either way.
    $vars = @{
        USERPROFILE             = $installHome
        GUARD_API_BASE_URL      = $Stub.Uri
        GUARD_DOWNLOAD_BASE_URL = $artifactsUri
        GITHUB_TOKEN            = 'stub-token-must-not-be-sent-to-a-non-github-host'
    }
    $saved = @{}
    $proc = $null

    try {
        foreach ($name in $vars.Keys) {
            $saved[$name] = [System.Environment]::GetEnvironmentVariable($name)
            Set-Item -Path "env:$name" -Value $vars[$name]
        }

        $proc = Start-Process -FilePath (Get-Process -Id $PID).Path -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath `
            -ArgumentList @('-NoProfile', '-File', $script:InstallScript)
    }
    finally {
        foreach ($name in $vars.Keys) {
            if ($null -eq $saved[$name]) {
                Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue
            }
            else {
                Set-Item -Path "env:$name" -Value $saved[$name]
            }
        }
    }

    return [pscustomobject]@{
        ExitCode = $proc.ExitCode
        Stdout   = if (Test-Path $stdoutPath) { Get-Content $stdoutPath -Raw } else { '' }
        Stderr   = if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw } else { '' }
    }
}

# Announced delays, in order, from the "retrying in N s" lines the script writes.
#
# Note the space before the s: install-guard.ps1 interpolates "$sleep s" where the shell script
# writes "${_sleep}s". Matching the shell spelling here would silently find nothing and make every
# delay assertion vacuous.
function announced_delays {
    param($Run)
    $text = "$($Run.Stdout)`n$($Run.Stderr)"
    return @([regex]::Matches($text, 'retrying in (\d+) s') |
        ForEach-Object { [int]$_.Groups[1].Value })
}

# The three collection helpers below are each called as `@(helper ...)`, and the `@()` is not
# decoration. PowerShell unrolls a returned array into the pipeline, so a one-element array comes
# back as a bare scalar no matter that the function wrote `return @(...)`; under
# `Set-StrictMode -Version Latest` the `.Count` the callers then read throws
# ParentContainsErrorRecordException rather than answering 1. That is measured, not theoretical: it
# is how the ratelimit-reset case failed on windows-latest, where two requests yield exactly one
# gap. Wrapping at the call site is what guarantees an array of any length, including zero.
function stub_requests {
    param($Stub)
    $lines = @(Get-Content $Stub.Log -ErrorAction SilentlyContinue | Where-Object { $_.Trim() })
    return @($lines | ForEach-Object {
            $parts = $_ -split '\s+'
            [pscustomobject]@{ Ms = [int]$parts[0]; Status = [int]$parts[1]; Auth = $parts[2] }
        })
}

function request_gaps_ms {
    param($Requests)
    $gaps = @()
    for ($i = 1; $i -lt $Requests.Count; $i++) {
        $gaps += ($Requests[$i].Ms - $Requests[$i - 1].Ms)
    }
    return $gaps
}

function assert_no_auth_reached_stub {
    param([string]$Label, $Requests)
    $authed = @($Requests | Where-Object { $_.Auth -eq 'auth' }).Count
    if ($authed -ne 0) {
        fail "${Label}: GITHUB_TOKEN was sent to the stub host on $authed request(s). The token must only ever go to api.github.com; GUARD_API_BASE_URL pointing elsewhere must not carry it."
    }
    else {
        pass "${Label}: no Authorization header reached the non-GitHub host"
    }
}

# -------------------------------------------------------------------------------------------------
# Retry-After is honoured, and it wins over the exponential fallback.
#
# Two 403s carrying Retry-After: 1, then success. The delays must be 1 and 1. Exponential backoff
# would have chosen 2 and 4, so this fails if the header is ignored.
# -------------------------------------------------------------------------------------------------
function test_retry_after_is_honoured {
    $stub = start_stub 'retry-after'
    try {
        $run = run_installer $stub
        $requests = @(stub_requests $stub)

        if ($run.ExitCode -ne 0) {
            fail "retry-after: expected the install to recover and exit 0, got $($run.ExitCode); output:`n$($run.Stdout)`n$($run.Stderr)"
            return
        }

        $delays = @(announced_delays $run)
        if (($delays -join ' ') -ne '1 1') {
            fail "retry-after: announced delays were '$($delays -join ' ')', expected '1 1'. 2 and 4 would mean Retry-After was ignored and the exponential fallback used instead."
        }
        else {
            pass 'retry-after: announced delays were 1s then 1s, not the 2s/4s fallback'
        }

        if ($requests.Count -ne 3) {
            fail "retry-after: the stub saw $($requests.Count) requests, expected 3 (two 403s then a 200)"
        }
        else {
            # Each gap must be at least the second it was told to wait, and short of the 2s the
            # fallback would have produced. 900ms rather than 1000 for the lower bound: Start-Sleep
            # may return marginally early and the stub timestamps the response.
            $index = 0
            $allOk = $true
            foreach ($gap in @(request_gaps_ms $requests)) {
                $index = $index + 1
                if ($gap -lt 900) {
                    fail "retry-after: gap $index was ${gap}ms, expected at least ~1000ms -- the script did not actually wait the second it announced."
                    $allOk = $false
                }
                elseif ($gap -ge 2000) {
                    fail "retry-after: gap $index was ${gap}ms, which is the exponential fallback's 2s rather than the 1s Retry-After asked for."
                    $allOk = $false
                }
            }
            if ($allOk) { pass 'retry-after: both measured gaps were ~1s, matching the header' }
        }

        if ($run.Stdout -notmatch [regex]::Escape($script:StubTag)) {
            fail "retry-after: the resolved version did not come from the stub's tag_name; output:`n$($run.Stdout)"
        }
        else {
            pass 'retry-after: installed the tag the stub returned after the limit cleared'
        }

        assert_no_auth_reached_stub 'retry-after' $requests
    }
    finally { stop_stub $stub }
}

# -------------------------------------------------------------------------------------------------
# X-RateLimit-Reset is honoured when there is no Retry-After.
#
# One 403 with X-RateLimit-Remaining: 0 and a reset four seconds out. The delay has to be derived
# from that epoch. Four seconds, not one, because a reset one second out yields 1-2s once the
# script's margin is added and BaseDelaySeconds is 2 -- so the correct answer and the fallback would
# be the same number and a script that ignored the header would pass. That was measured on the shell
# side: mutating the reset lookup to match nothing left the suite green until the reset moved out.
# -------------------------------------------------------------------------------------------------
function test_ratelimit_reset_is_honoured {
    $stub = start_stub 'ratelimit-reset'
    try {
        $run = run_installer $stub
        $requests = @(stub_requests $stub)

        if ($run.ExitCode -ne 0) {
            fail "ratelimit-reset: expected the install to recover and exit 0, got $($run.ExitCode); output:`n$($run.Stdout)`n$($run.Stderr)"
            return
        }

        $announced = @(announced_delays $run) -join ' '
        if ($announced -eq '2') {
            fail 'ratelimit-reset: announced 2, which is BaseDelaySeconds -- the reset epoch was not read and the exponential fallback was used instead.'
        }
        elseif ($announced -eq '4' -or $announced -eq '5') {
            pass "ratelimit-reset: announced a ${announced}s wait derived from the reset epoch"
        }
        else {
            fail "ratelimit-reset: announced delays were '$announced', expected '4' or '5'"
        }

        $gaps = @(request_gaps_ms $requests)
        if ($gaps.Count -lt 1) {
            fail 'ratelimit-reset: the stub saw only one request, so no retry happened'
        }
        elseif ($gaps[0] -lt 3500) {
            fail "ratelimit-reset: retried after only $($gaps[0])ms for a reset four seconds out. Below 3500ms the wait is the 2s fallback rather than the reset, and retrying before the quota resets walks straight back into the same empty quota."
        }
        elseif ($gaps[0] -gt 9000) {
            fail "ratelimit-reset: waited $($gaps[0])ms for a reset four seconds out, which means the epoch was misread -- an hour-long primary limit would hang the installer this way."
        }
        else {
            pass "ratelimit-reset: waited ~$($gaps[0])ms, consistent with the reset epoch and well clear of the 2s fallback"
        }

        assert_no_auth_reached_stub 'ratelimit-reset' $requests
    }
    finally { stop_stub $stub }
}

# -------------------------------------------------------------------------------------------------
# With no backoff headers, the delay doubles from BaseDelaySeconds.
#
# The positive control for the two cases above: without it, a script that always slept 1s would pass
# both of them.
# -------------------------------------------------------------------------------------------------
function test_exponential_fallback {
    $stub = start_stub 'exponential'
    try {
        $run = run_installer $stub
        $requests = @(stub_requests $stub)

        if ($run.ExitCode -ne 0) {
            fail "exponential: expected the install to recover and exit 0, got $($run.ExitCode); output:`n$($run.Stdout)`n$($run.Stderr)"
            return
        }

        $delays = @(announced_delays $run)
        if (($delays -join ' ') -ne '2 4') {
            fail "exponential: announced delays were '$($delays -join ' ')', expected '2 4' -- with no header to read the delay must double from BaseDelaySeconds."
        }
        else {
            pass 'exponential: announced delays doubled, 2s then 4s'
        }

        assert_no_auth_reached_stub 'exponential' $requests
    }
    finally { stop_stub $stub }
}

# -------------------------------------------------------------------------------------------------
# Retries are bounded, and exhaustion is reported as a rate limit.
#
# A 429 to every request. The script must stop at MaxAttempts -- exactly 5 requests, not 4 and not a
# loop -- fail, and say the cause was a quota rather than a missing release, because that distinction
# is the whole reason a caller knows to authenticate.
# -------------------------------------------------------------------------------------------------
function test_exhaustion_is_bounded_and_explained {
    $stub = start_stub 'exhaustion'
    try {
        $run = run_installer $stub
        $requests = @(stub_requests $stub)
        $output = "$($run.Stdout)`n$($run.Stderr)"

        if ($run.ExitCode -eq 0) {
            fail 'exhaustion: the script exited 0 with nothing installed. An unresolved version must be a nonzero exit.'
        }
        else {
            pass "exhaustion: exited $($run.ExitCode) after the retries ran out"
        }

        if ($requests.Count -ne 5) {
            fail "exhaustion: the stub saw $($requests.Count) requests, expected exactly 5 (MaxAttempts). Fewer means the ceiling is too low to survive a transient limit; more means it does not stop."
        }
        else {
            pass 'exhaustion: stopped after exactly 5 attempts'
        }

        if ($output -notmatch 'rate limit rather than a problem with the release') {
            fail "exhaustion: output did not say the failure was a rate limit; output:`n$output"
        }
        else {
            pass 'exhaustion: named the cause as a rate limit'
        }

        # The three remedies, because a message that says "rate limit" without saying what to do
        # about it leaves the caller where they started.
        $missing = @()
        foreach ($remedy in @('GITHUB_TOKEN', 'gh auth login', '-Version')) {
            if ($output -notmatch [regex]::Escape($remedy)) { $missing += $remedy }
        }
        if ($missing.Count -gt 0) {
            fail "exhaustion: output did not offer $($missing -join ', ') as a way out; output:`n$output"
        }
        else {
            pass 'exhaustion: offered the token, gh and explicit-version remedies'
        }

        assert_no_auth_reached_stub 'exhaustion' $requests
    }
    finally { stop_stub $stub }
}

# -------------------------------------------------------------------------------------------------
# A single 429 is survived.
#
# The narrowest case separating "retries" from "reports the first failure", which is what the script
# did before any of this was added.
# -------------------------------------------------------------------------------------------------
function test_single_429_is_survived {
    $stub = start_stub 'succeed-after-one-429'
    try {
        $run = run_installer $stub
        $requests = @(stub_requests $stub)

        if ($run.ExitCode -ne 0) {
            fail "single-429: one 429 must not fail the install, got exit $($run.ExitCode); output:`n$($run.Stdout)`n$($run.Stderr)"
        }
        elseif ($run.Stdout -notmatch [regex]::Escape($script:StubTag)) {
            fail "single-429: recovered but did not install the stub's tag; output:`n$($run.Stdout)"
        }
        else {
            pass 'single-429: retried once and installed the tag the stub then returned'
        }

        assert_no_auth_reached_stub 'single-429' $requests
    }
    finally { stop_stub $stub }
}

# -------------------------------------------------------------------------------------------------
# A reset header that cannot be used still reaches the rate-limit guidance.
#
# This is the case that mattered here more than on the shell side. Get-BackoffDelay is called from
# inside the `catch` in Invoke-GitHubApiWithBackoff, so a throw raised in it is not caught by that
# catch: it leaves the function as a terminating error and the guidance at the bottom of the retry loop
# never runs. `X-RateLimit-Reset: not-a-number` ended the install with a complaint about converting a
# value to Int32 -- a message about a cast, for a condition whose remedy is to set a token -- and any
# value past Int32.MaxValue did the same.
#
# The assertion is that the guidance is PRINTED. Both the broken and the fixed version exit nonzero, so
# an assertion on the exit code alone passes on either and measures nothing.
#
# The two cases differ in attempt count and the difference is the behavior: a value that is not a number
# is rejected before the arithmetic and the exponential fallback runs to the ceiling, while a value that
# IS a number and names a reset three thousand years out implies a wait longer than MaxTotalWaitSeconds,
# which is checked before sleeping, so the guidance is reported at once.
# -------------------------------------------------------------------------------------------------
function test_an_unusable_reset_header_still_explains_itself {
    foreach ($case in @(
            @{ Scenario = 'reset-not-a-number'; Requests = 5 },
            @{ Scenario = 'reset-overflows-int32'; Requests = 1 }
        )) {
        $stub = start_stub $case.Scenario
        try {
            $run = run_installer $stub
            $requests = @(stub_requests $stub)
            $output = "$($run.Stdout)`n$($run.Stderr)"

            if ($run.ExitCode -eq 0) {
                fail "$($case.Scenario): expected a nonzero exit once the lookup gave up"
            }

            if ($output -notmatch 'rate limit rather than a problem with the release') {
                fail "$($case.Scenario): the rate-limit guidance was not printed. An unusable header must not turn a quota problem into a different failure -- a cast that throws inside Get-BackoffDelay escapes the catch and loses this message; output:`n$output"
            }
            else {
                pass "$($case.Scenario): reported the rate limit rather than failing on the header"
            }

            if ($output -match 'Cannot convert value') {
                fail "$($case.Scenario): the run failed on a type conversion, which is the defect this case exists for; output:`n$output"
            }

            if ($requests.Count -ne $case.Requests) {
                fail "$($case.Scenario): the stub saw $($requests.Count) requests, expected $($case.Requests); see the comment above this function for why the two cases differ"
            }
            else {
                pass "$($case.Scenario): made $($requests.Count) request(s), which is what this header implies"
            }

            assert_no_auth_reached_stub $case.Scenario $requests
        }
        finally { stop_stub $stub }
    }
}

# -------------------------------------------------------------------------------------------------
# A redirect to another host is not followed.
#
# Invoke-RestMethod follows redirects by default, and Windows PowerShell 5.1 does not strip the
# Authorization header across a cross-host redirect. So without -MaximumRedirection 0 a 30x out of the
# API would hand the bearer token to the target. The stub answers 302 to a reserved documentation name,
# so a run that followed it would fail to resolve rather than reach anything.
#
# The assertion is on the request count at the stub plus the absence of a success: the token check in
# assert_no_auth_reached_stub cannot see a request that went to a different host, which is exactly why
# not following is what has to be asserted.
# -------------------------------------------------------------------------------------------------
function test_a_redirect_is_not_followed {
    $stub = start_stub 'redirect-elsewhere'
    try {
        $run = run_installer $stub
        $requests = @(stub_requests $stub)

        if ($run.ExitCode -eq 0) {
            fail "redirect: a 302 out of the API must not produce a successful install; output:`n$($run.Stdout)"
        }
        else {
            pass "redirect: refused to treat a redirect as a release lookup"
        }

        if ($requests.Count -lt 1) {
            fail 'redirect: the stub saw no request at all, so the case did not run'
        }
        else {
            pass "redirect: the request reached the stub and stopped there"
        }

        assert_no_auth_reached_stub 'redirect' $requests
    }
    finally { stop_stub $stub }
}

try {
    disable_gh_cli
    stage_archive -Version $script:StubTag

    test_retry_after_is_honoured
    test_ratelimit_reset_is_honoured
    test_exponential_fallback
    test_exhaustion_is_bounded_and_explained
    test_single_429_is_survived
    test_an_unusable_reset_header_still_explains_itself
    test_a_redirect_is_not_followed
}
finally {
    Remove-Item -Recurse -Force $script:Work -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:Failures -ne 0) {
    throw "$($script:Failures) assertion(s) failed"
}
Write-Host 'all install-guard.ps1 backoff assertions passed'
