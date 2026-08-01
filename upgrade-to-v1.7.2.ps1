#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$InstallDir = "C:\Program Files\WindowsLoginGuard")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SecureDir = Join-Path $env:ProgramData "WindowsLoginGuard\secure"
$ManagementTokenPath = Join-Path $SecureDir "management.token"
$MaintenanceHashPath = Join-Path $SecureDir "maintenance-key.sha256"
$ConfigPath = Join-Path $SecureDir "config.json"
. (Join-Path $SourceDir "scope_helpers.ps1")

if (-not (Get-Service WindowsLoginGuard -ErrorAction SilentlyContinue)) {
    throw "WindowsLoginGuard service is not installed."
}

Stop-Service WindowsLoginGuard -Force
(Get-Service WindowsLoginGuard).WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
    [TimeSpan]::FromSeconds(20)
)
Stop-WlgUiProcesses

$backupDir = Join-Path $InstallDir (
    "backup-before-v1.7.2-" + (Get-Date -Format "yyyyMMdd-HHmmss")
)
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

$files = @(
    "common.py",
    "service.py",
    "ui.pyw",
    "admin.pyw",
    "open-admin.ps1",
    "scope_helpers.ps1",
    "uninstall.ps1",
    "wlg-recovery.cmd",
    "config.example.json",
    "README.md",
    "VERSION"
)

foreach ($name in $files) {
    $existing = Join-Path $InstallDir $name
    if (Test-Path $existing) {
        Copy-Item $existing $backupDir -Force
    }
}

if (Test-Path $ConfigPath) {
    Copy-Item $ConfigPath (Join-Path $backupDir "config.json") -Force
}

foreach ($name in $files) {
    Copy-Item (Join-Path $SourceDir $name) $InstallDir -Force
}

# Existing installations may retain the shorter v1.5.x duration list.
# Append the newly supported values without removing any administrator choices.
if (Test-Path $ConfigPath) {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    $orderedDurations = @(
        "once",
        "until_lock",
        "session",
        "15_minutes",
        "30_minutes",
        "1_hour",
        "2_hours",
        "4_hours",
        "8_hours",
        "24_hours"
    )
    $currentDurations = @($config.allowed_approval_durations)
    foreach ($duration in $orderedDurations) {
        if ($currentDurations -notcontains $duration) {
            $currentDurations += $duration
        }
    }
    $migratedDurations = @(
        $orderedDurations | Where-Object { $currentDurations -contains $_ }
    )
    if ($null -eq $config.PSObject.Properties["allowed_approval_durations"]) {
        $config | Add-Member -NotePropertyName allowed_approval_durations -NotePropertyValue $migratedDurations
    }
    else {
        $config.allowed_approval_durations = $migratedDurations
    }

    $temporaryConfig = "$ConfigPath.v172.tmp"
    $json = $config | ConvertTo-Json -Depth 8
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($temporaryConfig, $json + [Environment]::NewLine, $utf8NoBom)
    Move-Item $temporaryConfig $ConfigPath -Force
}

if (-not (Test-Path $ManagementTokenPath)) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    $token = [Convert]::ToBase64String($bytes)
    [System.IO.File]::WriteAllText(
        $ManagementTokenPath,
        $token,
        [System.Text.Encoding]::ASCII
    )
}
icacls $ManagementTokenPath /inheritance:r | Out-Null
icacls $ManagementTokenPath /grant:r "SYSTEM:F" "Administrators:F" | Out-Null

if (-not (Test-Path $MaintenanceHashPath)) {
    throw (
        "The maintenance recovery key is not configured. " +
        "Re-run the v1.1.0 or later installation before upgrading."
    )
}

$servicePath = (
    Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuard'"
).PathName
$serviceExe = if ($servicePath.StartsWith('"')) {
    [regex]::Match($servicePath, '^"([^"]+)"').Groups[1].Value
}
else {
    $servicePath.Split(' ')[0]
}
$pythonExe = Join-Path (Split-Path -Parent $serviceExe) "python.exe"

Push-Location $InstallDir
try {
    & $pythonExe -c "import common, service; print('v1.7.2 service modules validated')"
    if ($LASTEXITCODE -ne 0) {
        throw "v1.7.2 service validation failed."
    }

    & $pythonExe (Join-Path $InstallDir "ui.pyw") --startup-check
    if ($LASTEXITCODE -ne 0) {
        throw "v1.7.2 UI startup validation failed."
    }
}
finally {
    Pop-Location
}

Set-Service WindowsLoginGuard -StartupType Automatic
Start-Service WindowsLoginGuard
(Get-Service WindowsLoginGuard).WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Running,
    [TimeSpan]::FromSeconds(20)
)

$AdminShortcutPath = New-WlgAdminDesktopShortcut `
    -InstallDir $InstallDir

Write-Host ""
Write-Host "Upgrade to v1.7.2 complete."
Write-Host "Desktop Admin shortcut and PC-local audit timestamp display installed."
Write-Host "Safe Mode and WinRE CLI recovery remain available as emergency paths."
Write-Host "Admin shortcut: $AdminShortcutPath"
Write-Host 'Open Admin manually with: powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\WindowsLoginGuard\open-admin.ps1"'
Write-Host "Existing enrollments, policies, recovery codes, and keys were preserved."
