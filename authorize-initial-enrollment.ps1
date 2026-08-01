#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$UserSid,
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuard"
)

$ErrorActionPreference = "Stop"
. (Join-Path $InstallDir "scope_helpers.ps1")
$ConfigPath = Join-Path $env:ProgramData "WindowsLoginGuard\secure\config.json"
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$values = @($config.initial_enrollment_sids)
if ($values -notcontains $UserSid) { $values += $UserSid }
Set-WlgJsonProperty $config "initial_enrollment_sids" $values

Stop-Service WindowsLoginGuard -Force
Write-WlgJsonNoBom -Path $ConfigPath -Object $config
Start-Service WindowsLoginGuard
Write-Host "One-time trusted enrollment enabled for SID $UserSid."
Write-Host "The authorization is removed automatically after successful OTP testing."
