#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [Parameter(Mandatory = $true)]
    [Alias("RegistrationCode")]
    [string]$EnrollmentToken,
    [Parameter(Mandatory = $true)][string]$ServerCertificate,
    [string]$DisplayName = $env:COMPUTERNAME,
    [ValidateRange(5, 300)][int]$SyncIntervalSeconds = 10,
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuard"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Get-Service WindowsLoginGuard -ErrorAction SilentlyContinue)) {
    throw "WindowsLoginGuard must be installed before enabling remote management."
}
if (-not (Test-Path $ServerCertificate)) {
    throw "Server certificate was not found: $ServerCertificate"
}
foreach ($name in @("remote_agent.py", "remote_common.py", "VERSION")) {
    if (-not (Test-Path (Join-Path $InstallDir $name))) {
        throw "$name is missing from $InstallDir. Install or upgrade Windows Login Guard first."
    }
}

$service = Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuard'"
$pathName = [string]$service.PathName
$serviceExe = if ($pathName.StartsWith('"')) {
    [regex]::Match($pathName, '^"([^"]+)"').Groups[1].Value
}
else { $pathName.Split(' ')[0] }
$PythonExe = Join-Path (Split-Path -Parent $serviceExe) "python.exe"
if (-not (Test-Path $PythonExe)) {
    throw "Could not locate the Python runtime used by WindowsLoginGuard."
}

$SecureDir = Join-Path $env:ProgramData "WindowsLoginGuard\secure"
$PinnedCertificate = Join-Path $SecureDir "remote-server.crt"
Copy-Item $ServerCertificate $PinnedCertificate -Force
icacls $PinnedCertificate /inheritance:r | Out-Null
icacls $PinnedCertificate /grant:r "SYSTEM:F" "Administrators:F" | Out-Null

$AgentScript = Join-Path $InstallDir "remote_agent.py"
& $PythonExe $AgentScript register `
    --server $ServerUrl `
    --enrollment-token $EnrollmentToken `
    --display-name $DisplayName `
    --ca-cert $PinnedCertificate `
    --sync-interval $SyncIntervalSeconds
if ($LASTEXITCODE -ne 0) {
    throw "Protected-device registration failed."
}

$AgentConfig = Join-Path $SecureDir "remote-agent.json"
$AgentToken = Join-Path $SecureDir "remote-device-token.dpapi"
$CommandSecret = Join-Path $SecureDir "remote-command-secret.dpapi"
$CommandState = Join-Path $SecureDir "remote-command-state.json"
foreach ($path in @(
    $AgentConfig,
    $AgentToken,
    $CommandSecret,
    $CommandState
)) {
    if (-not (Test-Path $path)) {
        continue
    }
    icacls $path /inheritance:r | Out-Null
    icacls $path /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
}

if (Get-Service WindowsLoginGuardRemoteAgent -ErrorAction SilentlyContinue) {
    Stop-Service WindowsLoginGuardRemoteAgent -Force -ErrorAction SilentlyContinue
    & $PythonExe $AgentScript remove | Out-Null
    Start-Sleep -Seconds 1
}
& $PythonExe $AgentScript --startup auto install
if ($LASTEXITCODE -ne 0) { throw "Remote Agent service installation failed." }
sc.exe config WindowsLoginGuardRemoteAgent depend= WindowsLoginGuard | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to configure the Remote Agent dependency." }
sc.exe failure WindowsLoginGuardRemoteAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to configure Remote Agent recovery actions." }
sc.exe failureflag WindowsLoginGuardRemoteAgent 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable Remote Agent failure actions." }

Start-Service WindowsLoginGuardRemoteAgent
(Get-Service WindowsLoginGuardRemoteAgent).WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Running,
    [TimeSpan]::FromSeconds(30)
)

& $PythonExe $AgentScript test
if ($LASTEXITCODE -ne 0) {
    throw "Remote Agent was installed, but the initial synchronization test failed."
}

Write-Host ""
Write-Host "Remote management enabled for this protected device." -ForegroundColor Green
Write-Host "Service: WindowsLoginGuardRemoteAgent"
Write-Host "Server: $ServerUrl"
Write-Host "Pinned certificate: $PinnedCertificate"
