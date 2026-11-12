# Downloads and installs cfn-guard from GitHub releases on Windows.
#
# Parameters:
#   -Version   install this exact release tag instead of resolving the latest one. Skips the
#              GitHub API entirely, which is the only part of this script that can be rate
#              limited. Mirrors -v in install-guard.sh.
#
# Environment:
#   GITHUB_TOKEN, GH_TOKEN  when set, authenticates the release lookup; GITHUB_TOKEN wins if both
#                           are. The anonymous GitHub API allows 60 requests per hour per source IP,
#                           shared by everyone behind the same address, so a corporate NAT, a VPN or
#                           a CI runner can exhaust it through no fault of the caller. The `gh` CLI,
#                           if installed and logged in, is preferred over both and needs no setup --
#                           GH_TOKEN is read because that is the variable `gh` itself documents, so
#                           a caller who set it up for `gh` has already set it.
#   GUARD_DOWNLOAD_BASE_URL overrides where release archives are fetched from. Defaults to the
#                           GitHub releases URL. Set it to a file:// or https:// prefix to install
#                           an archive built locally, which is how this script is tested against
#                           the code under review rather than against the last release, and what
#                           makes an air-gapped install possible. An http:// origin also works but
#                           nothing here verifies a checksum or a signature, so whatever this
#                           points at is installed as-is: over plaintext that is anyone on the
#                           network path, not just the host you meant.
#   GUARD_API_BASE_URL      overrides where the release tag is looked up. Defaults to the GitHub
#                           REST API. Its reason to exist is the same as the variable above's: the
#                           retry and backoff below run only for responses the real API sends when
#                           its quota is already spent, which is not a state a test can ask for, so
#                           the responses have to come from somewhere a test controls. The token is
#                           deliberately NOT sent when this points anywhere other than
#                           api.github.com -- see Get-ApiTokenFor.
param(
  [string]$Version
)

# Total seconds we are willing to spend waiting across all retries. A primary rate limit can be up
# to an hour from reset, and an installer that appears to hang for an hour is worse than one that
# fails with an explanation, so past this we stop and say what to do about it.
$script:MaxTotalWaitSeconds = 300
# Attempts per request, and the first backoff delay when the server tells us nothing more specific.
$script:MaxAttempts = 5
$script:BaseDelaySeconds = 2

$script:DefaultGitHubApi = "https://api.github.com/repos/aws-cloudformation/cloudformation-guard"
$script:GitHubApi = if ($env:GUARD_API_BASE_URL) { $env:GUARD_API_BASE_URL } else { $script:DefaultGitHubApi }
$script:DefaultDownloadBaseUrl = "https://github.com/aws-cloudformation/cloudformation-guard/releases/download"

function main {
  param([string]$RequestedVersion)

  # Check for deps and if the user is in an admin shell
  check_requirements

  # Log to the user what version and archType we're trying to install
  $archType = Get-ArchType
  $majorVersion, $version = Get-GuardVersion -RequestedVersion $RequestedVersion
  Write-Host "Installing cfn-guard version $version for $archType architecture"

  # Create the guard directory & bin directory
  $guardDir = "$env:USERPROFILE\.guard\$majorVersion"
  $binDir = "$env:USERPROFILE\.guard\bin"
  Write-Host "Creating directories $guardDir & $binDir"
  # SilentlyContinue so the script doesn't break if the directories
  # Are already present
  mkdir $guardDir, $binDir -ErrorAction SilentlyContinue | Out-Null

  # Download the release into the temp directory
  $baseUrl = if ($env:GUARD_DOWNLOAD_BASE_URL) { $env:GUARD_DOWNLOAD_BASE_URL } else { $script:DefaultDownloadBaseUrl }
  $downloadUrl = "$baseUrl/$version/cfn-guard-v$majorVersion-$archType-windows-latest.tar.gz"
  $tmpFile = "$env:TEMP\guard.tar.gz"
  download_file_to_path $downloadUrl $tmpFile

  # Extract the temporary tar into the guard directories
  Write-Host "Extracting $tmpFile to $guardDir"
  extract_tar $tmpfile $guardDir

  # Symlink the binary file
  Write-Host "Creating symlink to bin"
  $cfnGuardExePath = "$guardDir\cfn-guard-v$majorVersion-$archType-windows-latest"
  New-Item -ItemType SymbolicLink -Path $binDir -Value $cfnGuardExePath -Force | Out-Null

  # Check that the symlink exists
  Write-Host "Checking installation was successful"
  if (-not (Get-Command "$binDir\cfn-guard")) {
      err "cfn-guard was not installed properly"
  }

  # Add guard to PATH automatically
  update_path $binDir

  Write-Host "Done."
}

# Architecture from .NET rather than WMI. Get-WmiObject was removed in PowerShell 6, and
# Get-CimInstance, its documented replacement, exists only on Windows -- neither can be exercised
# outside a Windows PowerShell host, so neither is testable before CI runs. RuntimeInformation is
# part of the framework, is present in every supported host, and reports the OS architecture
# directly, which is what the release archive name needs.
function Get-ArchType {
    $archtype = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($archtype) {
        "Arm64" { "aarch64" }
        "X64" { "x86_64" }
        "X86" { "i686" }
        default { err "Unsupported architecture type $archtype" }
    }
}

# Resolve the release tag to install, preferring whichever mechanism needs the least from the
# caller.
#
# 1. An explicit -Version, which skips the API and so cannot be rate limited.
# 2. `gh`, if installed and authenticated. It reuses credentials the caller already has, so it is
#    both authenticated and free of any setup on our part.
# 3. The REST API, authenticated when GITHUB_TOKEN is present and anonymous otherwise. The
#    anonymous path is the one subject to the 60/hour per-IP limit.
function Get-GuardVersion {
  param([string]$RequestedVersion)

  if ($RequestedVersion) {
    Write-Host "Using the requested version $RequestedVersion"
    return $RequestedVersion.Split('.')[0], $RequestedVersion
  }

  Write-Host "Getting the latest release version online"

  $tag = Get-TagFromGhCli
  if (-not $tag) {
    $latestRelease = Invoke-GitHubApiWithBackoff -Uri "$script:GitHubApi/releases/latest"
    $tag = $latestRelease.tag_name
  }
  if (-not $tag) {
    err "unable to determine which cfn-guard version to install"
  }

  Write-Host "Latest release is $tag"
  return $tag.Split('.')[0], $tag
}

# The tag according to the gh CLI, or $null when gh is absent, unauthenticated, or unhappy. Never
# fatal on its own: the REST paths are still worth trying.
function Get-TagFromGhCli {
  if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    return $null
  }
  gh auth status *> $null
  if ($LASTEXITCODE -ne 0) {
    return $null
  }
  $tag = gh release view --repo aws-cloudformation/cloudformation-guard --json tagName --jq ".tagName" 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $tag) {
    Write-Host "gh was available but did not return a release; falling back to the REST API"
    return $null
  }
  return $tag.Trim()
}

# GET a GitHub API URL, honouring the API's own backoff signals.
#
# The API tells us how long to wait and we listen, rather than guessing: retry-after on a
# secondary limit, and x-ratelimit-reset when the primary limit is exhausted. Blind exponential
# backoff would retry straight into an empty quota and report a network error for what is really a
# quota problem.
function Invoke-GitHubApiWithBackoff {
  param([string]$Uri)

  $headers = @{ "Accept" = "application/vnd.github+json"; "User-Agent" = "install-guard" }
  $token = Get-ApiTokenFor -Uri $Uri
  if ($token) {
    $headers["Authorization"] = "Bearer $token"
  }

  $attempt = 1
  $delay = $script:BaseDelaySeconds
  $waited = 0

  while ($true) {
    try {
      # -MaximumRedirection 0, so a redirect cannot carry the Authorization header to another host.
      #
      # Invoke-RestMethod follows redirects by default. PowerShell 6 and later strip Authorization
      # across a cross-host redirect; Windows PowerShell 5.1 does not, and Get-HeaderValue exists
      # precisely because this script has to run under both. So on 5.1 a 30x out of api.github.com
      # would hand the bearer token to whatever host the Location named. Get-ApiTokenFor already keeps
      # the token off every host but api.github.com on the way out; this keeps it there afterwards.
      #
      # Refusing to follow costs nothing on this call. The releases API answers 200 directly -- it is
      # the release *asset* that redirects to a storage host, and that download is a separate function
      # which sends no token. A redirect here would be a change at the API, and failing loudly on one
      # is better than following it with a credential attached.
      return Invoke-RestMethod -Uri $Uri -Headers $headers -MaximumRedirection 0 -ErrorAction Stop
    } catch {
      $response = $_.Exception.Response
      $status = 0
      if ($response) { $status = [int]$response.StatusCode }
      $sleep = Get-BackoffDelay -Response $response -Fallback $delay

      if ($attempt -ge $script:MaxAttempts -or ($waited + $sleep) -gt $script:MaxTotalWaitSeconds) {
        Write-Host "GitHub API request failed with HTTP $status after $attempt attempt(s)."
        if ($status -eq 403 -or $status -eq 429) {
          Write-Host "This is a rate limit rather than a problem with the release."
          Write-Host "Authenticate to raise it: set GITHUB_TOKEN, or run 'gh auth login',"
          Write-Host "or pass -Version <tag> to skip the lookup entirely."
        }
        err "unable to reach the GitHub API: $($_.Exception.Message)"
      }

      Write-Host "attempt $attempt of $($script:MaxAttempts) got HTTP $status; retrying in $sleep s"
      Start-Sleep -Seconds $sleep
      $waited = $waited + $sleep
      $attempt = $attempt + 1
      $delay = $delay * 2
    }
  }
}

# The bearer token to send to $Uri, which is $null for every host but the GitHub API.
#
# The host is checked rather than assumed. GUARD_API_BASE_URL can point this script's release lookup
# at any origin, and a token that followed it there would be handed to whoever controls that origin
# -- so the check is what keeps that variable a testing and mirroring convenience rather than a way
# to exfiltrate a credential. The same reasoning already kept the token away from the archive
# download, which redirects to a separate storage host.
#
# The prefix match is on "https://api.github.com/" with the trailing slash: without it,
# "https://api.github.com.example.invalid/" would match.
function Get-ApiTokenFor {
  param([string]$Uri)

  if (-not $Uri.StartsWith("https://api.github.com/", [System.StringComparison]::Ordinal)) {
    return $null
  }
  if ($env:GITHUB_TOKEN) { return $env:GITHUB_TOKEN }
  if ($env:GH_TOKEN) { return $env:GH_TOKEN }
  return $null
}

# Seconds to wait before the next attempt, from the response headers when they say, else $Fallback.
function Get-BackoffDelay {
  param($Response, [int]$Fallback)

  # Every value read here is a response header, which is to say text this script did not write and
  # cannot constrain. Each one is parsed with TryParse before it is used in arithmetic, and none is
  # cast directly.
  #
  # The reason is sharper than defensiveness. This function is called from inside the `catch` block in
  # Invoke-GitHubApiWithBackoff, so a throw raised here is NOT caught by that catch: it leaves the
  # function as a terminating error, and the caller never reaches the rate-limit guidance it exists to
  # print. `X-RateLimit-Reset: not-a-number` used to end the install with
  # "Cannot convert value ... to type System.Int32" -- a message about a cast, for a condition whose
  # remedy is to set a token -- and the explanation went with it. So did any value past Int32.MaxValue.
  #
  # [long] rather than [int] throughout, because an epoch second fits Int32 only until 2038 and
  # nothing stops a server or a proxy sending a larger number today.

  # retry-after is authoritative and is what a secondary limit returns.
  $retryAfter = Get-HeaderValue -Response $Response -Name "Retry-After"
  $retrySeconds = [long]0
  if ($retryAfter -and [long]::TryParse($retryAfter, [ref]$retrySeconds) -and $retrySeconds -gt 0) {
    return $retrySeconds
  }

  # A primary limit is exhausted when remaining is 0; reset is an epoch second.
  $remaining = Get-HeaderValue -Response $Response -Name "X-RateLimit-Remaining"
  $reset = Get-HeaderValue -Response $Response -Name "X-RateLimit-Reset"
  $resetEpoch = [long]0
  if ($remaining -eq "0" -and $reset -and [long]::TryParse($reset, [ref]$resetEpoch)) {
    # InvariantCulture, because `-UFormat %s` can carry a fractional part on some hosts and a culture
    # that reads `.` as a group separator would turn 1757451234.5 into 17574512345 -- a reset date
    # centuries out, which then reads as a wait this script would refuse rather than one it honours.
    $now = [long][double]::Parse(
      (Get-Date -UFormat %s),
      [System.Globalization.CultureInfo]::InvariantCulture)
    $until = $resetEpoch - $now + 1
    if ($until -gt 0) { return $until }
  }

  # Returned unclamped, and the caller is what bounds it: Invoke-GitHubApiWithBackoff compares
  # `$waited + $sleep` against MaxTotalWaitSeconds *before* sleeping, so an hour-long reset reports the
  # guidance immediately instead of hanging. Clamping here would turn that into a short sleep followed
  # by a retry into the same exhausted quota.
  return $Fallback
}

# One header value, read defensively. Windows PowerShell hands back a WebHeaderCollection with a
# string indexer while PowerShell 7 hands back HttpResponseHeaders with TryGetValues, and this
# script has to work under both. An unreadable header is not an error; it just means we fall back
# to exponential backoff.
function Get-HeaderValue {
  param($Response, [string]$Name)

  if (-not $Response) { return $null }
  try {
    $headers = $Response.Headers
    if ($null -eq $headers) { return $null }
    if ($headers -is [System.Net.WebHeaderCollection]) {
      return $headers[$Name]
    }
    $values = $null
    if ($headers.TryGetValues($Name, [ref]$values)) {
      return ($values | Select-Object -First 1)
    }
  } catch {
    return $null
  }
  return $null
}

function extract_tar {
  param($sourceFile, $destinationPath)
  if (-not (Test-Path $destinationPath)) {
      New-Item -ItemType Directory -Path $destinationPath | Out-Null
  }
  tar -xzf $sourceFile -C $destinationPath
}

function err {
    param($message)
    Write-Host $message -ForegroundColor Red
    throw $message
}

function check_cmd_present {
    param($cmd)
    if (-not (Get-Command $cmd)) {
        err "'$cmd' is required (command not found)"
    }
}

# Fetch the release archive, retried. Never authenticated: the archive redirects to a separate
# download host and a credential has no business travelling there.
function download_file_to_path {
    param($url, $outputFile)

    $attempt = 1
    $delay = $script:BaseDelaySeconds
    $waited = 0

    while ($true) {
      try {
        Write-Host "Downloading $url to $outputFile"
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($url, $outputFile)
        return
      } catch {
        if ($attempt -ge $script:MaxAttempts -or ($waited + $delay) -gt $script:MaxTotalWaitSeconds) {
          err "Failed to download cfn-guard release from $url after $attempt attempt(s)."
        }
        Write-Host "attempt $attempt of $($script:MaxAttempts) failed; retrying in $delay s"
        Start-Sleep -Seconds $delay
        $waited = $waited + $delay
        $attempt = $attempt + 1
        $delay = $delay * 2
      }
    }
}

function check_admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
  if ($isAdmin) {
      Write-Host "Script running as administrator."
  } else {
      err "Please run this script in PowerShell as an administrator."
  }
}

function check_requirements {
    Write-Host "Checking requirements"
    check_admin
    check_cmd_present "mkdir"
    check_cmd_present "rm"
    check_cmd_present "tar"
}

function update_path {
  param($binDir)
  $existingPathValue = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")

  if ($existingPathValue -like "*$binDir*") {
      Write-Host "PATH already includes cfn-guard. Skipping."
  } else {
      try {
          $updatedPathValue = "$existingPathValue;$binDir"
          [System.Environment]::SetEnvironmentVariable("PATH", $updatedPathValue, "Machine")
          Write-Host "Added cfn-guard to PATH."
      } catch {
          err "Could not automatically add cfn-guard to PATH. Please add it manually: $binDir"
      }
  }
}

main -RequestedVersion $Version
