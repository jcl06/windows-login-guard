#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("device", "workstation")]
    [string]$Kind,
    [Parameter(Mandatory = $true)][string]$Id
)
$ErrorActionPreference = "Stop"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $InstallDir "remote-server-tools.ps1")
$PythonExe = Get-WlgRemoteServerPython
& $PythonExe (Join-Path $InstallDir "remote_server.py") revoke `
    --kind $Kind --id $Id
if ($LASTEXITCODE -ne 0) { throw "Remote object revocation failed." }
