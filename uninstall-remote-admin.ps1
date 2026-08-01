#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$InstallDir = "C:\Program Files\WindowsLoginGuardRemoteAdmin")
$ErrorActionPreference = "Stop"

$NotifierConfig = Join-Path `
    $InstallDir `
    "configure-approval-notifier.ps1"
if (Test-Path $NotifierConfig) {
    & $NotifierConfig -Disable
}
else {
    Remove-ItemProperty `
        -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "WindowsLoginGuardApprovalNotifier" `
        -ErrorAction SilentlyContinue
}

$Desktop = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonDesktopDirectory
)
if ([string]::IsNullOrWhiteSpace($Desktop)) {
    $Desktop = Join-Path $env:PUBLIC "Desktop"
}
Remove-Item (Join-Path $Desktop "Windows Login Guard Remote Administration.lnk") `
    -Force -ErrorAction SilentlyContinue
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Remote Administration app removed. Per-user registration data was preserved."
