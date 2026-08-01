#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuardRemoteServer",
    [switch]$DeleteServerData
)
$ErrorActionPreference = "Stop"
if (Get-Service WindowsLoginGuardManagementServer -ErrorAction SilentlyContinue) {
    $service = Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuardManagementServer'"
    $pathName = [string]$service.PathName
    $serviceExe = if ($pathName.StartsWith('"')) {
        [regex]::Match($pathName, '^"([^"]+)"').Groups[1].Value
    }
    else { $pathName.Split(' ')[0] }
    $pythonExe = Join-Path (Split-Path -Parent $serviceExe) "python.exe"
    Stop-Service WindowsLoginGuardManagementServer -Force -ErrorAction SilentlyContinue
    if (Test-Path $pythonExe) {
        & $pythonExe (Join-Path $InstallDir "remote_server.py") remove | Out-Null
    }
}
$ServerConfigPath = Join-Path $env:ProgramData "WindowsLoginGuardRemoteServer\secure\server.json"
$ServerPort = 8443
if (Test-Path $ServerConfigPath) {
    try {
        $ServerPort = [int]((Get-Content $ServerConfigPath -Raw | ConvertFrom-Json).port)
    }
    catch { }
}
$FirewallRule = "Windows Login Guard Remote Management ($ServerPort)"
Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
if ($DeleteServerData) {
    Remove-Item (Join-Path $env:ProgramData "WindowsLoginGuardRemoteServer") `
        -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "Remote Management Server removed."
