#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuard",
    [switch]$RemoveRegistration
)
$ErrorActionPreference = "Stop"
$service = Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuard'"
if ($service) {
    $pathName = [string]$service.PathName
    $serviceExe = if ($pathName.StartsWith('"')) {
        [regex]::Match($pathName, '^"([^"]+)"').Groups[1].Value
    }
    else { $pathName.Split(' ')[0] }
    $pythonExe = Join-Path (Split-Path -Parent $serviceExe) "python.exe"
}
if (Get-Service WindowsLoginGuardRemoteAgent -ErrorAction SilentlyContinue) {
    Stop-Service WindowsLoginGuardRemoteAgent -Force -ErrorAction SilentlyContinue
    if ($pythonExe -and (Test-Path $pythonExe)) {
        & $pythonExe (Join-Path $InstallDir "remote_agent.py") remove | Out-Null
    }
}
if ($RemoveRegistration) {
    $secure = Join-Path $env:ProgramData "WindowsLoginGuard\secure"
    Remove-Item (Join-Path $secure "remote-agent.json") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $secure "remote-device-token.dpapi") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $secure "remote-command-secret.dpapi") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $secure "remote-command-state.json") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $secure "remote-server.crt") -Force -ErrorAction SilentlyContinue
}
Write-Host "Remote Agent disabled. Revoke the device centrally if it should not reconnect."
