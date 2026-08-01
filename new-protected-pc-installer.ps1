#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Label,

    [ValidateRange(1, 168)]
    [int]$ValidHours = 24,

    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DefaultsPath = Join-Path $InstallDir "remote-setup.json"
$PayloadDir = Join-Path $InstallDir "protected-pc-package"

if (-not (Test-Path $DefaultsPath)) {
    throw (
        "Remote-management server setup information is unavailable. " +
        "Rerun install-remote-server.ps1."
    )
}
if (-not (Test-Path $PayloadDir)) {
    throw (
        "The protected-PC installer payload is unavailable. " +
        "Rerun install-remote-server.ps1 from v1.10.2."
    )
}

$Defaults = Get-Content `
    -LiteralPath $DefaultsPath `
    -Raw |
    ConvertFrom-Json

$CertificateSource = [string]$Defaults.server_certificate
if (
    [string]::IsNullOrWhiteSpace($CertificateSource) -or
    -not (Test-Path $CertificateSource)
) {
    throw (
        "The management-server public certificate is unavailable. " +
        "Rerun install-remote-server.ps1 to repair the server."
    )
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::DesktopDirectory
    )
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $env:USERPROFILE "Desktop"
    }
}
New-Item `
    -ItemType Directory `
    -Path $OutputDirectory `
    -Force |
    Out-Null

$Result = & (Join-Path $InstallDir "new-device-enrollment-token.ps1") `
    -Label $Label `
    -ValidHours $ValidHours `
    -PassThru `
    -Quiet

if (-not $Result.RegistrationCode) {
    throw "The protected-PC registration code was not created."
}

$ExpiresUtc = ""
if (
    $Result.PSObject.Properties.Name -contains "ExpiresUtc" -and
    -not [string]::IsNullOrWhiteSpace([string]$Result.ExpiresUtc)
) {
    $ExpiresUtc = [string]$Result.ExpiresUtc
}
else {
    # Compatibility fallback for a v1.8.6 helper that returned only
    # ValidHours. The server still enforces its own authoritative expiry.
    $ExpiresUtc = (
        [DateTimeOffset]::UtcNow.AddHours($ValidHours)
    ).ToString("o")
}

$SafeLabel = $Label -replace '[^A-Za-z0-9._-]', '-'
$SafeLabel = $SafeLabel.Trim('-', '.', '_')
if ([string]::IsNullOrWhiteSpace($SafeLabel)) {
    $SafeLabel = "Protected-PC"
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ArchiveName = (
    "WindowsLoginGuard-$SafeLabel-$Timestamp.zip"
)
$ArchivePath = Join-Path $OutputDirectory $ArchiveName
$StageRoot = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    ("wlg-protected-pc-" + [Guid]::NewGuid().ToString("N"))

try {
    New-Item `
        -ItemType Directory `
        -Path $StageRoot `
        -Force |
        Out-Null

    Copy-Item `
        -Path (Join-Path $PayloadDir "*") `
        -Destination $StageRoot `
        -Recurse `
        -Force

    Copy-Item `
        -LiteralPath $CertificateSource `
        -Destination (Join-Path $StageRoot "server.crt") `
        -Force

    $Registration = [ordered]@{
        server_url = [string]$Defaults.server_url
        registration_code = [string]$Result.RegistrationCode
        server_certificate = "server.crt"
        display_name = $Label
        expires_utc = $ExpiresUtc
    }

    $Registration |
        ConvertTo-Json -Depth 4 |
        Set-Content `
            -LiteralPath (Join-Path $StageRoot "registration.json") `
            -Encoding UTF8 `
            -Force

    @"
WINDOWS LOGIN GUARD PROTECTED-PC INSTALLER

1. Copy this ZIP to the protected Windows PC.
2. Extract the ZIP.
3. Open PowerShell as Administrator in the extracted folder.
4. Run:

   .\install-protected-pc.ps1

No server URL, certificate path, or registration code needs to be entered.

The embedded registration code is single-use and expires after $ValidHours hour(s).
Transfer this ZIP through a secure channel and delete it after installation.
"@ |
        Set-Content `
            -LiteralPath (Join-Path $StageRoot "INSTALL-FIRST.txt") `
            -Encoding UTF8 `
            -Force

    if (Test-Path $ArchivePath) {
        Remove-Item `
            -LiteralPath $ArchivePath `
            -Force
    }

    Compress-Archive `
        -Path (Join-Path $StageRoot "*") `
        -DestinationPath $ArchivePath `
        -CompressionLevel Optimal
}
finally {
    Remove-Item `
        -LiteralPath $StageRoot `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Protected-PC installer created." -ForegroundColor Green
Write-Host ""
Write-Host "  $ArchivePath" -ForegroundColor Cyan
Write-Host ""
Write-Host "On the protected PC:"
Write-Host "  1. Copy and extract this ZIP."
Write-Host "  2. Run .\install-protected-pc.ps1 as Administrator."
Write-Host ""
Write-Host (
    "No manual certificate copy or registration-code entry is required."
)
Write-Host (
    "The ZIP contains a single-use registration code. Transfer it " +
    "securely and delete it after installation."
) -ForegroundColor Yellow
