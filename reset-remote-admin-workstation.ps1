[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$DataDir = Join-Path $env:APPDATA "WindowsLoginGuardRemoteAdmin"
Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "This Windows user must register the Remote Admin app again on next launch."
Write-Host "Revoke the old workstation ID on the management server if appropriate."
