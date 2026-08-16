param(
  [Parameter(Mandatory = $true)]
  [string]$ProgramPath,
  [ValidateRange(1024, 65535)]
  [int]$Port = 18790,
  [string]$RuleName = "PersonalAgentBrowserWorker-WSL"
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal(
  [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Administrator privileges are required to configure the scoped WSL firewall rule."
}
if (-not (Test-Path $ProgramPath -PathType Leaf)) {
  throw "Browser Worker executable was not found: $ProgramPath"
}

$wslInterface = Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.InterfaceDescription -like "*Hyper-V Virtual Ethernet*" -and $_.Name -like "*WSL*" } |
  Select-Object -First 1
if (-not $wslInterface) {
  throw "The WSL Hyper-V network interface was not found. Start WSL and try again."
}

Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue |
  Remove-NetFirewallRule

New-NetFirewallRule `
  -Name $RuleName `
  -DisplayName "Personal Agent Browser Worker (WSL only)" `
  -Description "Allow the local WSL2 Core to reach the token-protected Browser Worker." `
  -Enabled True `
  -Profile Any `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort $Port `
  -RemoteAddress "172.16.0.0/12" `
  -InterfaceAlias $wslInterface.Name `
  -Program $ProgramPath | Out-Null

[PSCustomObject]@{
  Configured = $true
  RuleName = $RuleName
  InterfaceAlias = $wslInterface.Name
  Port = $Port
  RemoteAddress = "172.16.0.0/12"
} | Format-List
