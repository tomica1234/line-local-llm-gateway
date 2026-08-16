param(
  [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$Python = "$env:USERPROFILE\anaconda3\python.exe",
  [string]$TaskName = "PersonalAgentLineDesktopBridge"
)

$ErrorActionPreference = "Stop"

$installRoot = Join-Path $env:LOCALAPPDATA "PersonalAgentLineBridge"
$venvRoot = Join-Path $installRoot "venv"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
$venvPythonw = Join-Path $venvRoot "Scripts\pythonw.exe"
$configPath = Join-Path $installRoot "bridge.json"
$databasePath = Join-Path $installRoot "line-desktop-bridge.sqlite3"
$envPath = Join-Path $ProjectRoot ".env"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

if (-not (Test-Path $Python -PathType Leaf)) {
  throw "Windows Python was not found: $Python"
}
if (-not (Test-Path $envPath -PathType Leaf)) {
  throw "Personal Agent .env was not found: $envPath"
}

New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
if (-not (Test-Path $venvPython -PathType Leaf)) {
  & $Python -m venv $venvRoot
}

& $venvPython -m pip install --disable-pip-version-check "$ProjectRoot[line-desktop]"
if ($LASTEXITCODE -ne 0) {
  throw "Could not install the LINE Desktop Bridge environment."
}

$token = $null
$existingConfig = $null
if (Test-Path $configPath -PathType Leaf) {
  $existingConfig = Get-Content $configPath -Raw | ConvertFrom-Json
  if ([string]$existingConfig.token -and ([string]$existingConfig.token).Length -ge 32) {
    $token = [string]$existingConfig.token
  }
}
if (-not $token) {
  $bytes = New-Object byte[] 48
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($bytes)
  }
  finally {
    $rng.Dispose()
  }
  $token = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}
$sendAllowlist = @()
if ($existingConfig -and $existingConfig.send_allowlist) {
  $sendAllowlist = @($existingConfig.send_allowlist | ForEach-Object { [string]$_ })
}
$sendEnabled = [bool]($existingConfig -and $existingConfig.send_enabled `
  -and $sendAllowlist.Count -gt 0)

$config = [ordered]@{
  host = "127.0.0.1"
  port = 18791
  token = $token
  database_path = $databasePath
  send_enabled = $sendEnabled
  send_allowlist = $sendAllowlist
  restore_minimized_window = $true
  core_ingest_url = "http://127.0.0.1:8789/api/channels/line-desktop/ingest"
  sync_interval_seconds = 60
}
[IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 4), $utf8NoBom)

$updates = [ordered]@{
  PERSONAL_AGENT_LINE_DESKTOP_BRIDGE_URL = "http://127.0.0.1:18791/v1"
  PERSONAL_AGENT_LINE_DESKTOP_BRIDGE_TOKEN = $token
  PERSONAL_AGENT_LINE_DESKTOP_BRIDGE_TIMEOUT_SECONDS = "20"
  PERSONAL_AGENT_LINE_DESKTOP_SYNC_INTERVAL_SECONDS = "60"
  PERSONAL_AGENT_LINE_DESKTOP_SEND_ENABLED = $sendEnabled.ToString().ToLowerInvariant()
  PERSONAL_AGENT_ALLOW_REMOTE_LINE_DESKTOP_BRIDGE = "false"
}
$lines = [Collections.Generic.List[string]](Get-Content $envPath)
foreach ($key in $updates.Keys) {
  $replacement = "$key=$($updates[$key])"
  $found = $false
  for ($index = 0; $index -lt $lines.Count; $index++) {
    if ($lines[$index] -match "^$([Regex]::Escape($key))=") {
      $lines[$index] = $replacement
      $found = $true
      break
    }
  }
  if (-not $found) {
    $lines.Add($replacement)
  }
}
[IO.File]::WriteAllLines($envPath, $lines, $utf8NoBom)

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $installRoot /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Could not restrict the LINE Desktop Bridge directory ACL."
}

$argument = "-m personal_agent.line_desktop_bridge.main --config `"$configPath`""
$action = New-ScheduledTaskAction -Execute $venvPythonw -Argument $argument
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
  -MultipleInstances IgnoreNew
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask -and $existingTask.State -eq "Running") {
  Stop-ScheduledTask -TaskName $TaskName
  for ($attempt = 0; $attempt -lt 20; $attempt++) {
    if ((Get-ScheduledTask -TaskName $TaskName).State -ne "Running") {
      break
    }
    Start-Sleep -Milliseconds 250
  }
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$headers = @{ "X-Line-Desktop-Token" = $token }
$health = $null
for ($attempt = 0; $attempt -lt 30; $attempt++) {
  try {
    $health = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:18791/v1/health" `
      -Headers $headers -TimeoutSec 2
    break
  } catch {
    Start-Sleep -Milliseconds 500
  }
}
if ($null -eq $health -or $health.core_push.configured -ne $true) {
  throw "LINE Desktop Bridge did not become healthy."
}

& wsl.exe -d Ubuntu -- bash -lc "systemctl --user restart personal-agent.service"
if ($LASTEXITCODE -ne 0) {
  throw "The Windows bridge is active, but Personal Agent Core could not be restarted."
}

[PSCustomObject]@{
  Installed = $true
  TaskName = $TaskName
  BridgeStatus = $health.status
  LineRunning = $health.line_running
  CaptureMode = $health.capture_mode
  ScreenshotsPersisted = $health.screenshots_persisted
  SendEnabled = $health.send_enabled
  TokenPrinted = $false
} | Format-List
