#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuard",
    [string]$PythonExe = "",
    [ValidateSet("installer_user", "administrators", "all_users")]
    [string]$ProtectionScope = "installer_user",
    [ValidateSet("allow", "require_admin_approval", "deny")]
    [string]$OutOfScopePolicy = "allow",
    [string]$ServerUrl = "",
    [Alias("EnrollmentToken")]
    [string]$RegistrationCode = "",
    [string]$ServerCertificate = "",
    [string]$DisplayName = $env:COMPUTERNAME
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VersionPath = Join-Path $SourceDir "VERSION"
if (-not (Test-Path -LiteralPath $VersionPath)) {
    throw "VERSION is missing from the extracted release."
}
$ReleaseVersion = (
    Get-Content -LiteralPath $VersionPath -Raw
).Trim()
if ([string]::IsNullOrWhiteSpace($ReleaseVersion)) {
    throw "VERSION is empty in the extracted release."
}

$RegistrationFile = Join-Path $SourceDir "registration.json"
$ExplicitRemoteValues = @(
    $ServerUrl,
    $RegistrationCode,
    $ServerCertificate
)
$ExplicitRemoteCount = @(
    $ExplicitRemoteValues | Where-Object { $_ }
).Count

if ($ExplicitRemoteCount -eq 0 -and (Test-Path $RegistrationFile)) {
    $Registration = Get-Content `
        -LiteralPath $RegistrationFile `
        -Raw |
        ConvertFrom-Json

    $ServerUrl = [string]$Registration.server_url
    $RegistrationCode = [string]$Registration.registration_code
    $CertificateValue = [string]$Registration.server_certificate
    $DisplayName = [string]$Registration.display_name

    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        $DisplayName = $env:COMPUTERNAME
    }

    if ([System.IO.Path]::IsPathRooted($CertificateValue)) {
        $ServerCertificate = $CertificateValue
    }
    else {
        $ServerCertificate = Join-Path $SourceDir $CertificateValue
    }

    Write-Host (
        "Protected-PC registration settings were loaded from the " +
        "installer bundle."
    ) -ForegroundColor Cyan
}

$remoteValues = @($ServerUrl, $RegistrationCode, $ServerCertificate)
$remoteCount = @($remoteValues | Where-Object { $_ }).Count
if ($remoteCount -ne 0 -and $remoteCount -ne 3) {
    throw (
        "Remote registration is incomplete. Server URL, registration " +
        "code, and server certificate must be supplied together."
    )
}

Write-Host "Installing Windows Login Guard protected PC $ReleaseVersion..."
& (Join-Path $SourceDir "install.ps1") `
    -InstallDir $InstallDir `
    -PythonExe $PythonExe `
    -ProtectionScope $ProtectionScope `
    -OutOfScopePolicy $OutOfScopePolicy

if ($remoteCount -eq 3) {
    foreach ($name in @(
        "remote_agent.py",
        "remote_common.py",
        "configure-remote-endpoint.ps1",
        "test-remote-endpoint.ps1",
        "disable-remote-endpoint.ps1",
        "resume-remote-registration.ps1"
    )) {
        Copy-Item `
            -LiteralPath (Join-Path $SourceDir $name) `
            -Destination $InstallDir `
            -Force
    }

    $SecureDir = Join-Path `
        $env:ProgramData `
        "WindowsLoginGuard\secure"
    New-Item `
        -ItemType Directory `
        -Path $SecureDir `
        -Force |
        Out-Null

    $PendingCertificatePath = Join-Path `
        $SecureDir `
        "pending-remote-server.crt"
    $PendingRegistrationPath = Join-Path `
        $SecureDir `
        "pending-remote-registration.json"

    Copy-Item `
        -LiteralPath $ServerCertificate `
        -Destination $PendingCertificatePath `
        -Force

    $ExpiresUtc = ""
    if (
        $null -ne $Registration -and
        $Registration.PSObject.Properties.Name -contains "expires_utc"
    ) {
        $ExpiresUtc = [string]$Registration.expires_utc
    }

    $PendingRegistration = [ordered]@{
        server_url = $ServerUrl
        registration_code = $RegistrationCode
        server_certificate = $PendingCertificatePath
        display_name = $DisplayName
        expires_utc = $ExpiresUtc
    }
    $PendingRegistration |
        ConvertTo-Json -Depth 4 |
        Set-Content `
            -LiteralPath $PendingRegistrationPath `
            -Encoding UTF8 `
            -Force

    foreach ($path in @(
        $PendingCertificatePath,
        $PendingRegistrationPath
    )) {
        icacls $path /inheritance:r | Out-Null
        icacls $path `
            /grant:r `
            "SYSTEM:F" `
            "Administrators:F" |
            Out-Null
    }

    try {
        & (Join-Path $SourceDir "configure-remote-endpoint.ps1") `
            -ServerUrl $ServerUrl `
            -RegistrationCode $RegistrationCode `
            -ServerCertificate $PendingCertificatePath `
            -DisplayName $DisplayName `
            -InstallDir $InstallDir
    }
    catch {
        Write-Host ""
        Write-Warning (
            "Local protection was installed, but remote registration " +
            "did not complete."
        )
        Write-Host "After connectivity is fixed, run:"
        Write-Host ""
        Write-Host (
            "  & '" +
            (Join-Path $InstallDir "resume-remote-registration.ps1") +
            "'"
        ) -ForegroundColor Cyan
        Write-Host ""
        Write-Host (
            "The pending registration code and public certificate were " +
            "preserved in the restricted Windows Login Guard data folder."
        )
        throw
    }

    Remove-Item `
        -LiteralPath $PendingRegistrationPath `
        -Force `
        -ErrorAction SilentlyContinue
    Remove-Item `
        -LiteralPath $PendingCertificatePath `
        -Force `
        -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Protected PC installation complete." -ForegroundColor Green
if ($remoteCount -eq 3) {
    Write-Host "Remote management: connected to $ServerUrl"

    if (Test-Path $RegistrationFile) {
        Remove-Item `
            -LiteralPath $RegistrationFile `
            -Force `
            -ErrorAction SilentlyContinue
    }
}
else {
    Write-Host (
        "Remote management was not configured. A registration code can " +
        "be added later without reinstalling protection."
    )
}
