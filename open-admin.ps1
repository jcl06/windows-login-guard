#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$InstallDir = "C:\Program Files\WindowsLoginGuard"
$AdminApp = Join-Path $InstallDir "admin.pyw"

if (-not (Test-Path $AdminApp)) {
    throw "Windows Login Guard Admin was not found at: $AdminApp"
}

$service = Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuard'"
if (-not $service) {
    throw "WindowsLoginGuard service is not installed."
}

$servicePath = [string]$service.PathName
if ([string]::IsNullOrWhiteSpace($servicePath)) {
    throw "WindowsLoginGuard service executable path is empty."
}

if ($servicePath.StartsWith('"')) {
    $match = [regex]::Match($servicePath, '^"([^"]+)"')
    if (-not $match.Success) {
        throw "Could not parse the WindowsLoginGuard service path."
    }
    $serviceExe = $match.Groups[1].Value
}
else {
    $serviceExe = $servicePath.Split(' ')[0]
}

$runtimeDir = Split-Path -Parent $serviceExe
$candidates = @(
    (Join-Path $runtimeDir "pythonw.exe"),
    (Join-Path $runtimeDir "python.exe"),
    (Join-Path $InstallDir "venv\Scripts\pythonw.exe"),
    (Join-Path $InstallDir "venv\Scripts\python.exe")
)

$pythonExe = $candidates |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1

if (-not $pythonExe) {
    throw (
        "Windows Login Guard Python runtime was not found. " +
        "Service executable: $serviceExe"
    )
}

Start-Process `
    -FilePath $pythonExe `
    -ArgumentList @("`"$AdminApp`"") `
    -WorkingDirectory $InstallDir
