#Requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = "List")]
param(
    [Parameter(ParameterSetName = "Set", Mandatory = $true)]
    [string]$Username,
    [Parameter(ParameterSetName = "Set", Mandatory = $true)]
    [ValidateSet("enabled", "disabled")]
    [string]$State
)
$ErrorActionPreference = "Stop"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $InstallDir "remote-server-tools.ps1")
$PythonExe = Get-WlgRemoteServerPython
if ($PSCmdlet.ParameterSetName -eq "List") {
    & $PythonExe (Join-Path $InstallDir "remote_server.py") list-admins
}
else {
    & $PythonExe (Join-Path $InstallDir "remote_server.py") set-admin-state `
        --username $Username --state $State
}
if ($LASTEXITCODE -ne 0) { throw "Central administrator management failed." }
