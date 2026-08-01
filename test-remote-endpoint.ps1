#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$InstallDir = "C:\Program Files\WindowsLoginGuard")
$ErrorActionPreference = "Stop"
$service = Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuard'"
if (-not $service) { throw "WindowsLoginGuard is not installed." }
$pathName = [string]$service.PathName
$serviceExe = if ($pathName.StartsWith('"')) {
    [regex]::Match($pathName, '^"([^"]+)"').Groups[1].Value
}
else { $pathName.Split(' ')[0] }
$pythonExe = Join-Path (Split-Path -Parent $serviceExe) "python.exe"
& $pythonExe (Join-Path $InstallDir "remote_agent.py") test
if ($LASTEXITCODE -ne 0) { throw "Remote synchronization test failed." }
