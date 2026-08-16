param(
  [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$TaskName = "PersonalAgentLineDesktopBridge",
  [switch]$Disable
)

$ErrorActionPreference = "Stop"

$installRoot = Join-Path $env:LOCALAPPDATA "PersonalAgentLineBridge"
$configPath = Join-Path $installRoot "bridge.json"
$envPath = Join-Path $ProjectRoot ".env"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

if (-not (Test-Path $configPath -PathType Leaf)) {
  throw "Install the LINE Desktop Bridge first."
}
if (-not (Test-Path $envPath -PathType Leaf)) {
  throw "Personal Agent .env was not found: $envPath"
}
$config = Get-Content $configPath -Raw | ConvertFrom-Json

if ($Disable) {
  $selectedIds = @()
  $config.send_enabled = $false
  $config.send_allowlist = @()
}
else {
  $headers = @{ "X-Line-Desktop-Token" = [string]$config.token }
  $snapshot = Invoke-RestMethod -Method Post `
    -Uri "http://127.0.0.1:$($config.port)/v1/snapshot" `
    -Headers $headers -ContentType "application/json" -Body "{}" -TimeoutSec 30
  if ($snapshot.session_state -ne "logged_in") {
    throw "Open Windows LINE and complete login before enabling personal LINE sending."
  }
  $conversations = @(
    $snapshot.messages |
      Group-Object conversation_id |
      ForEach-Object {
        [PSCustomObject]@{
          ConversationId = [string]$_.Name
          Title = [string]$_.Group[0].conversation_title
        }
      } |
      Sort-Object Title
  )
  if ($conversations.Count -eq 0) {
    throw "No visible LINE conversations were found. Open the intended chat and try again."
  }

  Write-Host "Select the exact LINE recipients to allow. Message bodies are not displayed."
  for ($index = 0; $index -lt $conversations.Count; $index++) {
    Write-Host "[$($index + 1)] $($conversations[$index].Title)"
  }
  $selection = (Read-Host "Numbers separated by commas").Split(",") |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ }
  $indexes = @($selection | ForEach-Object {
    $parsed = 0
    if (-not [int]::TryParse($_, [ref]$parsed) -or $parsed -lt 1 `
      -or $parsed -gt $conversations.Count) {
      throw "Invalid recipient number: $_"
    }
    $parsed - 1
  } | Select-Object -Unique)
  if ($indexes.Count -eq 0) {
    throw "At least one recipient must be selected."
  }
  $selected = @($indexes | ForEach-Object { $conversations[$_] })
  Write-Host "Allowlisted recipients:"
  $selected | ForEach-Object { Write-Host "- $($_.Title)" }
  if ((Read-Host "Type ENABLE LINE SEND to continue") -cne "ENABLE LINE SEND") {
    throw "Confirmation did not match; no settings were changed."
  }
  $selectedIds = @($selected | ForEach-Object { $_.ConversationId })
  $config.send_enabled = $true
  $config.send_allowlist = $selectedIds
}

[IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), $utf8NoBom)

$lines = [Collections.Generic.List[string]](Get-Content $envPath)
$replacement = "PERSONAL_AGENT_LINE_DESKTOP_SEND_ENABLED=" + `
  ($(if ($Disable) { "false" } else { "true" }))
$found = $false
for ($index = 0; $index -lt $lines.Count; $index++) {
  if ($lines[$index] -match "^PERSONAL_AGENT_LINE_DESKTOP_SEND_ENABLED=") {
    $lines[$index] = $replacement
    $found = $true
    break
  }
}
if (-not $found) { $lines.Add($replacement) }
[IO.File]::WriteAllLines($envPath, $lines, $utf8NoBom)

Restart-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2
& wsl.exe -d Ubuntu -- bash -lc "systemctl --user restart personal-agent.service"
if ($LASTEXITCODE -ne 0) {
  throw "LINE Bridge settings were saved, but Personal Agent Core could not be restarted."
}

[PSCustomObject]@{
  SendEnabled = -not $Disable
  AllowlistedRecipientCount = $selectedIds.Count
  PlaintextCredentialsExtracted = $false
  MessageBodiesDisplayed = $false
} | Format-List
