#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$InstallDir = "C:\Program Files\WindowsLoginGuard")

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
$VersionLabel = $ReleaseVersion -replace '[^A-Za-z0-9._-]', '-'
$SecureDir = Join-Path $env:ProgramData "WindowsLoginGuard\secure"
$ConfigPath = Join-Path $SecureDir "config.json"
$RemoteAgentConfigPath = Join-Path $SecureDir "remote-agent.json"
. (Join-Path $SourceDir "scope_helpers.ps1")

if (-not (Get-Service WindowsLoginGuard -ErrorAction SilentlyContinue)) {
    throw "WindowsLoginGuard service is not installed."
}

$RemoteAgentService = Get-Service `
    WindowsLoginGuardRemoteAgent `
    -ErrorAction SilentlyContinue
$RemoteEndpointEnabled = [bool](
    $RemoteAgentService -or
    (Test-Path $RemoteAgentConfigPath)
)

if ($RemoteAgentService) {
    Stop-Service `
        WindowsLoginGuardRemoteAgent `
        -Force `
        -ErrorAction SilentlyContinue
}

Stop-Service WindowsLoginGuard -Force
(Get-Service WindowsLoginGuard).WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
    [TimeSpan]::FromSeconds(20)
)
Stop-WlgUiProcesses

$BackupDir = Join-Path $InstallDir (
    "backup-before-$VersionLabel-" + (Get-Date -Format "yyyyMMdd-HHmmss")
)
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

$CoreFiles = @(
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
    "VERSION",
    "requirements.txt"
)

$RemoteFiles = @(
    "remote_agent.py",
    "remote_common.py",
    "configure-remote-endpoint.ps1",
    "test-remote-endpoint.ps1",
    "disable-remote-endpoint.ps1",
    "resume-remote-registration.ps1"
)

$FilesToUpgrade = @($CoreFiles)
if ($RemoteEndpointEnabled) {
    $FilesToUpgrade += $RemoteFiles
}

foreach ($name in $FilesToUpgrade) {
    $Existing = Join-Path $InstallDir $name
    if (Test-Path $Existing) {
        Copy-Item `
            -LiteralPath $Existing `
            -Destination $BackupDir `
            -Force
    }
}

if (Test-Path $ConfigPath) {
    Copy-Item `
        -LiteralPath $ConfigPath `
        -Destination (Join-Path $BackupDir "config.json") `
        -Force
}

foreach ($name in $CoreFiles) {
    Copy-Item `
        -LiteralPath (Join-Path $SourceDir $name) `
        -Destination $InstallDir `
        -Force
}

if ($RemoteEndpointEnabled) {
    foreach ($name in $RemoteFiles) {
        Copy-Item `
            -LiteralPath (Join-Path $SourceDir $name) `
            -Destination $InstallDir `
            -Force
    }
}
else {
    foreach ($name in $RemoteFiles) {
        Remove-Item `
            -LiteralPath (Join-Path $InstallDir $name) `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

if (Test-Path (Join-Path $SourceDir "docs")) {
    Copy-Item `
        (Join-Path $SourceDir "docs") `
        $InstallDir `
        -Recurse `
        -Force
}

$ServicePath = (
    Get-CimInstance `
        Win32_Service `
        -Filter "Name='WindowsLoginGuard'"
).PathName
$ServiceExe = if ($ServicePath.StartsWith('"')) {
    [regex]::Match($ServicePath, '^"([^"]+)"').Groups[1].Value
}
else {
    $ServicePath.Split(' ')[0]
}
$PythonExe = Join-Path `
    (Split-Path -Parent $ServiceExe) `
    "python.exe"

& $PythonExe `
    -m pip install `
    --upgrade `
    -r (Join-Path $InstallDir "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Dependency update failed for release $ReleaseVersion."
}

Push-Location $InstallDir
try {
    & $PythonExe -c (
        "import common, service; " +
        "print('Local protection modules validated')"
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Local module validation failed for release $ReleaseVersion."
    }

    if ($RemoteEndpointEnabled) {
        & $PythonExe -c (
            "import remote_common, remote_agent; " +
            "print('Remote endpoint modules validated')"
        )
        if ($LASTEXITCODE -ne 0) {
            throw "Remote endpoint validation failed for release $ReleaseVersion."
        }
    }

    & $PythonExe `
        (Join-Path $InstallDir "ui.pyw") `
        --startup-check
    if ($LASTEXITCODE -ne 0) {
        throw "UI startup validation failed for release $ReleaseVersion."
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

if ($RemoteAgentService) {
    Set-Service WindowsLoginGuardRemoteAgent -StartupType Automatic
    Start-Service WindowsLoginGuardRemoteAgent
    (Get-Service WindowsLoginGuardRemoteAgent).WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(20)
    )
}

if ($RemoteEndpointEnabled) {
    foreach ($name in @(
        "remote-command-secret.dpapi",
        "remote-command-state.json"
    )) {
        $path = Join-Path $SecureDir $name
        if (Test-Path $path) {
            icacls $path /inheritance:r | Out-Null
            icacls $path /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
        }
    }
}

$AdminShortcutPath = New-WlgAdminDesktopShortcut `
    -InstallDir $InstallDir

Write-Host ""
Write-Host "Upgrade to $ReleaseVersion complete." -ForegroundColor Green
Write-Host (
    "Local enrollment, policy, recovery, maintenance, and audit data " +
    "were preserved."
)
Write-Host "Admin shortcut: $AdminShortcutPath"

if ($RemoteEndpointEnabled) {
    Write-Host (
        "Remote endpoint components were upgraded and the existing " +
        "registration was preserved."
    )
}
else {
    Write-Host (
        "This PC remains local-only. No remote-management endpoint " +
        "components were installed."
    )
}
