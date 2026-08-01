#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Label,

    [ValidateRange(1, 168)]
    [int]$ValidHours = 24,

    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path

& (Join-Path $InstallDir "new-protected-pc-installer.ps1") `
    -Label $Label `
    -ValidHours $ValidHours `
    -OutputDirectory $OutputDirectory
