Set-StrictMode -Version Latest

function Get-WlgRemoteServerPython {
    $service = Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuardManagementServer'"
    if (-not $service) {
        throw "WindowsLoginGuardManagementServer is not installed."
    }
    $pathName = [string]$service.PathName
    $serviceExe = if ($pathName.StartsWith('"')) {
        [regex]::Match($pathName, '^"([^"]+)"').Groups[1].Value
    }
    else {
        $pathName.Split(' ')[0]
    }
    $pythonExe = Join-Path (Split-Path -Parent $serviceExe) "python.exe"
    if (-not (Test-Path $pythonExe)) {
        throw "Could not locate the Python runtime used by the management service."
    }
    return $pythonExe
}
