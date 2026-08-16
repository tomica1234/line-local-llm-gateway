param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$')]
    [string]$Domain,

    [Parameter(Mandatory = $true)]
    [string]$CertFile,

    [Parameter(Mandatory = $true)]
    [string]$KeyFile,

    [string]$TailscaleExe = "$env:ProgramFiles\Tailscale\tailscale.exe",
    [string]$ProxyTaskName = 'PersonalAgentTLSProxy',
    [string]$MinimumValidity = '336h'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $TailscaleExe -PathType Leaf)) {
    throw "tailscale.exe was not found: $TailscaleExe"
}

$certDirectory = Split-Path -Parent $CertFile
$keyDirectory = Split-Path -Parent $KeyFile
if ($certDirectory -ne $keyDirectory) {
    throw 'Certificate and key must use the same protected directory.'
}
if (-not (Test-Path -LiteralPath $certDirectory -PathType Container)) {
    throw "Certificate directory was not found: $certDirectory"
}

$before = if (Test-Path -LiteralPath $CertFile -PathType Leaf) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $CertFile).Hash
} else {
    ''
}

& $TailscaleExe cert `
    "--min-validity=$MinimumValidity" `
    "--cert-file=$CertFile" `
    "--key-file=$KeyFile" `
    $Domain
if ($LASTEXITCODE -ne 0) {
    throw "tailscale cert failed with exit code $LASTEXITCODE"
}

$after = (Get-FileHash -Algorithm SHA256 -LiteralPath $CertFile).Hash
if ($before -ne $after) {
    Stop-ScheduledTask -TaskName $ProxyTaskName -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName $ProxyTaskName
}

$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertFile)
[pscustomobject]@{
    Domain = $Domain
    Renewed = ($before -ne $after)
    NotAfter = $certificate.NotAfter.ToString('o')
}
