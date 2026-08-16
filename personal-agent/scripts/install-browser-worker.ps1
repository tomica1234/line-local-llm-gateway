param(
  [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$Python = "$env:USERPROFILE\anaconda3\python.exe",
  [string]$TaskName = "PersonalAgentBrowserWorker"
)

$ErrorActionPreference = "Stop"

$installRoot = Join-Path $env:LOCALAPPDATA "PersonalAgentBrowserWorker"
$venvRoot = Join-Path $installRoot "venv"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
$venvPythonw = Join-Path $venvRoot "Scripts\pythonw.exe"
$configPath = Join-Path $installRoot "worker.json"
$profileRoot = Join-Path $installRoot "profiles"
$quarantineRoot = Join-Path $installRoot "quarantine"
$uploadRoot = Join-Path $installRoot "uploads"
$stateDb = Join-Path $installRoot "browser-worker.sqlite3"
$secretDb = Join-Path $installRoot "secrets.sqlite3"
$envPath = Join-Path $ProjectRoot ".env"
$firewallScript = Join-Path $PSScriptRoot "configure-browser-worker-firewall.ps1"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

if (-not (Test-Path $Python -PathType Leaf)) {
  throw "Windows Python was not found: $Python"
}
if (-not (Test-Path $envPath -PathType Leaf)) {
  throw "Personal Agent .env was not found: $envPath"
}
if (-not (Test-Path $firewallScript -PathType Leaf)) {
  throw "Scoped firewall helper was not found: $firewallScript"
}
$chrome = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $chrome -PathType Leaf)) {
  throw "Google Chrome is required at: $chrome"
}

New-Item -ItemType Directory -Force -Path $installRoot, $profileRoot, `
  $quarantineRoot, $uploadRoot | Out-Null
if (-not (Test-Path $venvPython -PathType Leaf)) {
  & $Python -m venv $venvRoot
}
& $venvPython -m pip install --disable-pip-version-check "$ProjectRoot[browser-worker]"
if ($LASTEXITCODE -ne 0) {
  throw "Could not install the Browser Worker environment."
}

$token = $null
if (Test-Path $configPath -PathType Leaf) {
  $existing = Get-Content $configPath -Raw | ConvertFrom-Json
  if ([string]$existing.token -and ([string]$existing.token).Length -ge 32) {
    $token = [string]$existing.token
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

$config = [ordered]@{
  host = "0.0.0.0"
  port = 18790
  token = $token
  profile_root = $profileRoot
  quarantine_root = $quarantineRoot
  state_db_path = $stateDb
  browser_channel = "chrome"
  headless = $false
  finance_allowlist = @()
  takeover_timeout_seconds = 300
  navigation_timeout_ms = 30000
  core_base_url = "http://127.0.0.1:8789"
  secret_db_path = $secretDb
  upload_roots = @($uploadRoot)
  allow_private_navigation = $false
  allow_non_windows = $false
  allowed_client_cidrs = @("127.0.0.0/8", "::1/128", "172.16.0.0/12")
}
[IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 4), $utf8NoBom)

$updates = [ordered]@{
  PERSONAL_AGENT_BROWSER_WORKER_URL = "http://wsl-host:18790/v1"
  PERSONAL_AGENT_BROWSER_WORKER_TOKEN = $token
  PERSONAL_AGENT_BROWSER_WORKER_TIMEOUT_SECONDS = "45"
  PERSONAL_AGENT_ALLOW_REMOTE_BROWSER_WORKER = "true"
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
& icacls.exe $installRoot /inheritance:r /grant:r "${identity}:(OI)(CI)F" `
  "SYSTEM:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Could not restrict the Browser Worker directory ACL."
}

$argument = "-m personal_agent.browser_worker.main --config `"$configPath`""
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
    if ((Get-ScheduledTask -TaskName $TaskName).State -ne "Running") { break }
    Start-Sleep -Milliseconds 250
  }
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$headers = @{ "X-Browser-Worker-Token" = $token }
$health = $null
for ($attempt = 0; $attempt -lt 40; $attempt++) {
  try {
    $health = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:18790/v1/health" `
      -Headers $headers -TimeoutSec 2
    break
  }
  catch {
    Start-Sleep -Milliseconds 500
  }
}
if ($null -eq $health -or $health.windows -ne $true -or $health.headed -ne $true) {
  throw "Windows Browser Worker did not become healthy."
}

$firewallRule = Get-NetFirewallRule -Name "PersonalAgentBrowserWorker-WSL" `
  -ErrorAction SilentlyContinue
if (-not $firewallRule -or $firewallRule.Enabled -ne "True") {
  $quotedScript = '"' + $firewallScript.Replace('"', '""') + '"'
  $quotedProgram = '"' + $venvPythonw.Replace('"', '""') + '"'
  $firewallArguments = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $quotedScript,
    "-ProgramPath", $quotedProgram,
    "-Port", "18790"
  )
  $elevated = Start-Process -FilePath "powershell.exe" -Verb RunAs `
    -ArgumentList $firewallArguments -Wait -PassThru
  if ($elevated.ExitCode -ne 0) {
    throw "The scoped WSL firewall rule was not installed."
  }
}

& wsl.exe -d Ubuntu -- bash -lc "systemctl --user restart personal-agent.service"
if ($LASTEXITCODE -ne 0) {
  throw "Browser Worker is active, but Personal Agent Core could not be restarted."
}

[PSCustomObject]@{
  Installed = $true
  TaskName = $TaskName
  BrowserStatus = $health.status
  Windows = $health.windows
  Headed = $health.headed
  Channel = $health.browser_channel
  DpapiCredentialStore = $true
  WslFirewallRule = "PersonalAgentBrowserWorker-WSL"
  AllowedClientCidrs = $config.allowed_client_cidrs -join ","
  TokenPrinted = $false
} | Format-List
