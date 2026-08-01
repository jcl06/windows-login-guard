#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet("devices", "workstations")]
    [string]$Kind = "devices"
)
$ErrorActionPreference = "Stop"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $InstallDir "remote-server-tools.ps1")
$PythonExe = Get-WlgRemoteServerPython
$Command = if ($Kind -eq "devices") { "list-devices" } else { "list-workstations" }
& $PythonExe (Join-Path $InstallDir "remote_server.py") $Command
if ($LASTEXITCODE -ne 0) { throw "Remote registration listing failed." }
