#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)][string]$UserSid,
    [switch]$KeepProfile
)

$ErrorActionPreference = "Stop"
$UserDir = Join-Path $env:ProgramData "WindowsLoginGuard\secure\users\$UserSid"
if (-not (Test-Path $UserDir)) { throw "No enrollment exists for SID $UserSid" }

if ($PSCmdlet.ShouldProcess($UserSid, "Revoke Windows Login Guard enrollment")) {
    Stop-Service WindowsLoginGuard -Force
    if ($KeepProfile) {
        Remove-Item (Join-Path $UserDir "secret.dpapi") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $UserDir "recovery_codes.json") -Force -ErrorAction SilentlyContinue
    }
    else {
        Remove-Item $UserDir -Recurse -Force
    }
    Start-Service WindowsLoginGuard
    Write-Host "Enrollment revoked for $UserSid. The account will return to enrollment mode if it remains in scope."
}
