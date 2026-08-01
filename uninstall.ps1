#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuard",
    [switch]$KeepEnrollment
)

$ErrorActionPreference = "Continue"
. (Join-Path $InstallDir "scope_helpers.ps1")

$remoteAgentInfo = Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuardRemoteAgent'" -ErrorAction SilentlyContinue
if (Get-Service WindowsLoginGuardRemoteAgent -ErrorAction SilentlyContinue) {
    Stop-Service WindowsLoginGuardRemoteAgent -Force -ErrorAction SilentlyContinue
    if ($remoteAgentInfo -and $remoteAgentInfo.PathName) {
        $remoteAgentExe = if ($remoteAgentInfo.PathName.StartsWith('"')) {
            [regex]::Match($remoteAgentInfo.PathName, '^"([^"]+)"').Groups[1].Value
        }
        else { $remoteAgentInfo.PathName.Split(' ')[0] }
        $remoteAgentPython = Join-Path (Split-Path -Parent $remoteAgentExe) "python.exe"
        if (Test-Path $remoteAgentPython) {
            & $remoteAgentPython (Join-Path $InstallDir "remote_agent.py") remove | Out-Null
        }
        else { sc.exe delete WindowsLoginGuardRemoteAgent | Out-Null }
    }
}

Remove-WlgLegacyUiTasks
Stop-WlgUiProcesses
Remove-WlgAdminDesktopShortcut

$serviceInfo = Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuard'" -ErrorAction SilentlyContinue
if (Get-Service WindowsLoginGuard -ErrorAction SilentlyContinue) {
    Stop-Service WindowsLoginGuard -Force -ErrorAction SilentlyContinue
}

$PythonExe = ""
if ($serviceInfo -and $serviceInfo.PathName) {
    $serviceExe = if ($serviceInfo.PathName.StartsWith('"')) {
        [regex]::Match($serviceInfo.PathName, '^"([^"]+)"').Groups[1].Value
    } else {
        $serviceInfo.PathName.Split(' ')[0]
    }
    $PythonExe = Join-Path (Split-Path -Parent $serviceExe) "python.exe"
}
$ServiceScript = Join-Path $InstallDir "service.py"
if ($PythonExe -and (Test-Path $PythonExe) -and (Test-Path $ServiceScript)) {
    & $PythonExe $ServiceScript remove
}
else {
    sc.exe delete WindowsLoginGuard | Out-Null
}

Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
if (-not $KeepEnrollment) {
    Remove-Item (Join-Path $env:ProgramData "WindowsLoginGuard") `
        -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Windows Login Guard removed."
if ($KeepEnrollment) {
    Write-Host "Per-user OTP enrollments and configuration were retained."
}
