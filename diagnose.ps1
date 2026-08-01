#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"
$SecureDir = Join-Path $env:ProgramData "WindowsLoginGuard\secure"
$ConfigPath = Join-Path $SecureDir "config.json"
$UsersDir = Join-Path $SecureDir "users"

Write-Host "=== Service ==="
Get-Service WindowsLoginGuard -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize

Write-Host "`n=== Version ==="
Get-Content "C:\Program Files\WindowsLoginGuard\VERSION" -ErrorAction SilentlyContinue

Write-Host "`n=== Configuration ==="
$config = Get-Content $ConfigPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
$config | ConvertTo-Json -Depth 8

Write-Host "`n=== Enrolled accounts ==="
Get-ChildItem $UsersDir -Directory -ErrorAction SilentlyContinue |
    ForEach-Object {
        $profilePath = Join-Path $_.FullName "profile.json"
        if (Test-Path $profilePath) {
            Get-Content $profilePath -Raw | ConvertFrom-Json
        }
    } |
    Select-Object username, user_sid, is_administrator, enrolled_at_utc |
    Format-Table -AutoSize

Write-Host "`n=== Recent log ==="
Get-Content (Join-Path $SecureDir "guard.log") -Tail 60 -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Failure actions:"
if ($config.failure_actions) {
    $config.failure_actions.PSObject.Properties | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Value)"
    }
}
Write-Host "Lock command fallback: $($config.lock_failure_action)"
Write-Host "Interaction mode: $($config.interaction_mode)"
Write-Host "Isolated fallback: $($config.isolated_desktop_fallback)"
Write-Host ""
Write-Host "Search recent UI diagnostics with:"
Write-Host '  Select-String "$SecureDir\guard.log" -Pattern "UI event|isolated"'
