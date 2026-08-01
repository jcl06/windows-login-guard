#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuard"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$SecureDir = Join-Path $env:ProgramData "WindowsLoginGuard\secure"
$PendingRegistrationPath = Join-Path `
    $SecureDir `
    "pending-remote-registration.json"

if (-not (Test-Path $PendingRegistrationPath)) {
    throw (
        "No pending remote registration was found. Create a new " +
        "protected-PC installer from the management server."
    )
}

$Pending = Get-Content `
    -LiteralPath $PendingRegistrationPath `
    -Raw |
    ConvertFrom-Json

$ServerUrl = [string]$Pending.server_url
$RegistrationCode = [string]$Pending.registration_code
$ServerCertificate = [string]$Pending.server_certificate
$DisplayName = [string]$Pending.display_name

foreach ($value in @(
    $ServerUrl,
    $RegistrationCode,
    $ServerCertificate,
    $DisplayName
)) {
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw (
            "The pending remote registration is incomplete. Create a " +
            "new protected-PC installer from the management server."
        )
    }
}

if (-not (Test-Path $ServerCertificate)) {
    throw (
        "The cached management-server certificate was not found: " +
        $ServerCertificate
    )
}

& (Join-Path $InstallDir "configure-remote-endpoint.ps1") `
    -ServerUrl $ServerUrl `
    -RegistrationCode $RegistrationCode `
    -ServerCertificate $ServerCertificate `
    -DisplayName $DisplayName `
    -InstallDir $InstallDir

Remove-Item `
    -LiteralPath $PendingRegistrationPath `
    -Force `
    -ErrorAction SilentlyContinue
Remove-Item `
    -LiteralPath $ServerCertificate `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Pending remote registration completed." `
    -ForegroundColor Green
