#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Username,
    [string]$QrPath = ""
)
$ErrorActionPreference = "Stop"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $InstallDir "remote-server-tools.ps1")
$PythonExe = Get-WlgRemoteServerPython
if (-not $QrPath) {
    $safeName = ($Username -replace '[^A-Za-z0-9_.-]', '_')
    $QrPath = Join-Path $env:USERPROFILE "Desktop\WLG-Remote-$safeName-QR.png"
}
& $PythonExe (Join-Path $InstallDir "remote_server.py") create-admin `
    --username $Username --qr $QrPath
if ($LASTEXITCODE -ne 0) { throw "Administrator creation failed." }
