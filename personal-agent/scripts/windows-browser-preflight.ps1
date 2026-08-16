$ErrorActionPreference = "Stop"

if (-not $IsWindows) {
  throw "The production Browser Worker must run on Windows."
}

$required = @(
  "PERSONAL_AGENT_BROWSER_WORKER_TOKEN",
  "PERSONAL_AGENT_BROWSER_PROFILE_ROOT",
  "PERSONAL_AGENT_BROWSER_QUARANTINE_ROOT",
  "PERSONAL_AGENT_SECRET_DB_PATH"
)
foreach ($name in $required) {
  if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
    throw "Missing required environment variable: $name"
  }
}
if ($env:PERSONAL_AGENT_BROWSER_WORKER_TOKEN.Length -lt 32) {
  throw "PERSONAL_AGENT_BROWSER_WORKER_TOKEN must contain at least 32 characters."
}

$profileRoot = [IO.Path]::GetFullPath($env:PERSONAL_AGENT_BROWSER_PROFILE_ROOT)
$downloadRoot = [IO.Path]::GetFullPath($env:PERSONAL_AGENT_BROWSER_QUARANTINE_ROOT)
$secretDb = [IO.Path]::GetFullPath($env:PERSONAL_AGENT_SECRET_DB_PATH)
$paths = @($profileRoot, $downloadRoot, [IO.Path]::GetDirectoryName($secretDb))

foreach ($path in $paths) {
  if ($path.StartsWith("\\")) { throw "Sensitive data cannot use a network path: $path" }
  New-Item -ItemType Directory -Force -Path $path | Out-Null
  & icacls.exe $path /inheritance:r /grant:r "$env:USERNAME`:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Unable to restrict ACL: $path" }
}

$mountPoint = [IO.Path]::GetPathRoot($profileRoot)
try {
  $bitLocker = Get-BitLockerVolume -MountPoint $mountPoint
  if ($bitLocker.ProtectionStatus -ne "On") {
    throw "BitLocker/device encryption is not protecting $mountPoint"
  }
} catch [System.Management.Automation.CommandNotFoundException] {
  throw "Get-BitLockerVolume is unavailable; verify Windows device encryption manually."
}

$chrome = Get-Command chrome.exe, msedge.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $chrome) {
  Write-Warning "Chrome was not found on PATH. Playwright's bundled Chromium can be configured instead."
}

Write-Host "Browser Worker preflight passed. Profile, Session, Secret DB, and Downloads are on an encrypted local volume with restricted ACLs."
