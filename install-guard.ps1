# Downloads and installs cfn-guard from GitHub releases on Windows.
#
# Parameters:
#   -Version   install this exact release tag instead of resolving the latest one. Skips the
#              GitHub API entirely, which is the only part of this script that can be rate
#              limited. Mirrors -v in install-guard.sh.
#
# Environment:
#   GITHUB_TOKEN            when set, authenticates the release lookup. The anonymous GitHub API
#                           allows 60 requests per hour per source IP, shared by everyone behind
#                           the same address, so a corporate NAT, a VPN or a CI runner can exhaust
#                           it through no fault of the caller. The `gh` CLI, if installed and
#                           logged in, is preferred over this and needs no setup.
#   GUARD_DOWNLOAD_BASE_URL overrides where release archives are fetched from. Defaults to the
#                           GitHub releases URL. Set it to a file:// or http:// prefix to install
#                           an archive built locally, which is how this script is tested against
#                           the code under review rather than against the last release, and what
#                           makes an air-gapped install possible.
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

$script:GitHubApi = "https://api.github.com/repos/aws-cloudformation/cloudformation-guard"
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
  if ($env:GITHUB_TOKEN) {
    $headers["Authorization"] = "Bearer $env:GITHUB_TOKEN"
  }

  $attempt = 1
  $delay = $script:BaseDelaySeconds
  $waited = 0

  while ($true) {
    try {
      return Invoke-RestMethod -Uri $Uri -Headers $headers -ErrorAction Stop
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

# Seconds to wait before the next attempt, from the response headers when they say, else $Fallback.
function Get-BackoffDelay {
  param($Response, [int]$Fallback)

  # retry-after is authoritative and is what a secondary limit returns.
  $retryAfter = Get-HeaderValue -Response $Response -Name "Retry-After"
  if ($retryAfter -and [int]::TryParse($retryAfter, [ref]$null)) {
    $seconds = [int]$retryAfter
    if ($seconds -gt 0) { return $seconds }
  }

  # A primary limit is exhausted when remaining is 0; reset is an epoch second.
  $remaining = Get-HeaderValue -Response $Response -Name "X-RateLimit-Remaining"
  $reset = Get-HeaderValue -Response $Response -Name "X-RateLimit-Reset"
  if ($remaining -eq "0" -and $reset) {
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    $until = [int]$reset - $now + 1
    if ($until -gt 0) { return $until }
  }

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
