function main {
  # Check for deps and if the user is in an admin shell
  check_requirements

  # Log to the user what version and archType we're trying to install
  $archType = Get-ArchType
  $majorVersion, $version = Get-Versions
  Write-Host "Installing cfn-guard version $version for $archType architecture"

  # Create the guard directory & bin directory
  $guardDir = "$env:USERPROFILE\.guard\$majorVersion"
  $binDir = "$env:USERPROFILE\.guard\bin"
  Write-Host "Creating directories $guardDir & $binDir"
  # SilentlyContinue so the script doesn't break if the directories
  # Are already present
  mkdir $guardDir, $binDir -ErrorAction SilentlyContinue | Out-Null

  # Download the latest release into the temp directory
  $downloadUrl = "https://github.com/aws-cloudformation/cloudformation-guard/releases/download/$version/cfn-guard-v$majorVersion-$archType-windows-latest.tar.gz"
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

function Get-ArchType {
    $archtype = (Get-WmiObject -Class Win32_Processor).Architecture
    switch ($archtype) {
        12 { "aarch64" }
        9 { "x86_64" }
        0 { "i686" }
        default { err "Unsupported architecture type $archtype" }
    }
}

function Get-Versions {
  Write-Host "Getting the latest release version online"
  $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/aws-cloudformation/cloudformation-guard/releases/latest"
  $tag_name = $latestRelease.tag_name
  $majorVersion = $tag_name.Split('.')[0]
  $version = $tag_name
  Write-Host "Latest release is $version"
  return $majorVersion, $version
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
    throw
}

function check_cmd_present {
    param($cmd)
    if (-not (Get-Command $cmd)) {
        err "'$cmd' is required (command not found)"
    }
}

function download_file_to_path {
    param($url, $outputFile)
    try {
      Write-Host "Downloading $url to $outputFile"
      $webClient = New-Object System.Net.WebClient
      $webClient.DownloadFile($url, $outputFile)
    } catch {
      err "Failed to download cfn-guard release. Please try again."
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

main
