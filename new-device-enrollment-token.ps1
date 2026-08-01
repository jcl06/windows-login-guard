#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Label,

    [ValidateRange(1, 168)]
    [int]$ValidHours = 24,

    [switch]$PassThru,

    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $InstallDir "remote-server-tools.ps1")
$PythonExe = Get-WlgRemoteServerPython

$output = & $PythonExe `
    (Join-Path $InstallDir "remote_server.py") `
    create-enrollment-token `
    --kind device `
    --label $Label `
    --hours $ValidHours `
    2>&1
$exitCode = $LASTEXITCODE

if (-not $Quiet) {
    foreach ($line in $output) {
        Write-Host ([string]$line)
    }
}

if ($exitCode -ne 0) {
    throw "Protected-device registration-code creation failed."
}

$tokenLine = $output |
    ForEach-Object { [string]$_ } |
    Where-Object { $_ -like "Registration code: *" } |
    Select-Object -Last 1

if (-not $tokenLine) {
    throw "The registration code was not returned by the management server."
}

$registrationCode = $tokenLine.Substring(
"Registration code: ".Length).Trim()

$expiryLine = $output |
    ForEach-Object { [string]$_ } |
    Where-Object { $_ -like "Expires UTC: *" } |
    Select-Object -Last 1

if (-not $expiryLine) {
    throw "The registration-code expiration was not returned by the server."
}

$expiresUtc = $expiryLine.Substring("Expires UTC: ".Length).Trim()

if ($PassThru) {
    [pscustomobject]@{
        Kind = "device"
        Label = $Label
        RegistrationCode = $registrationCode
        ExpiresUtc = $expiresUtc
        ValidHours = $ValidHours
    }
}
