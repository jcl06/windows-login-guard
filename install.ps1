#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuard",
    [string]$PythonExe = "",
    [ValidateSet("installer_user", "administrators", "all_users")]
    [string]$ProtectionScope = "installer_user",
    [ValidateSet("allow", "require_admin_approval", "deny")]
    [string]$OutOfScopePolicy = "allow"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Resolve-Python {
    param([string]$RequestedPath)
    if ($RequestedPath) {
        $candidate = (Get-Command $RequestedPath -ErrorAction Stop).Source
    }
    else {
        $candidate = $null
        $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($launcher) {
            $output = & $launcher.Source -3 -c "import sys; print(sys.executable)" 2>&1
            if (($LASTEXITCODE -eq 0) -and $output) {
                $candidate = ($output | Select-Object -Last 1).ToString().Trim()
            }
        }
        if (-not $candidate) {
            $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
            if ($pythonCommand) { $candidate = $pythonCommand.Source }
        }
    }
    if (-not $candidate -or -not (Test-Path $candidate)) {
        throw "Install 64-bit Python 3.11+ for all users, then rerun."
    }
    & $candidate -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.11 or newer is required." }

    $blockedRoots = @(
        $env:USERPROFILE,
        $env:LOCALAPPDATA,
        (Join-Path $env:ProgramFiles "WindowsApps")
    ) | Where-Object { $_ }
    foreach ($root in $blockedRoots) {
        if ($candidate.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw @"
Python is installed under the current user's profile:
  $candidate

Install 64-bit Python for all users under C:\Program Files. The service runs as LocalSystem.
"@
        }
    }
    return $candidate
}

function Invoke-PyWin32PostInstall {
    param([Parameter(Mandatory = $true)][string]$PythonPath)
    $pythonRoot = Split-Path -Parent $PythonPath
    $candidates = @(
        (Join-Path $pythonRoot "Scripts\pywin32_postinstall.py"),
        (Join-Path $pythonRoot "Lib\site-packages\pywin32_postinstall.py")
    )
    $script = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $script) {
        Invoke-CheckedNative -FilePath $PythonPath `
            -Arguments @("-m", "pip", "install", "--force-reinstall", "--no-cache-dir", "pywin32==312") `
            -Description "pywin32 repair"
        $script = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $script) { throw "pywin32_postinstall.py could not be located." }
    Write-Host "Using pywin32 post-install script: $script"
    Invoke-CheckedNative -FilePath $PythonPath `
        -Arguments @($script, "-install") `
        -Description "pywin32 machine installation"
}

$PythonExe = Resolve-Python -RequestedPath $PythonExe
$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProgramDataDir = Join-Path $env:ProgramData "WindowsLoginGuard"
$SecureDir = Join-Path $ProgramDataDir "secure"
$RuntimeDir = Join-Path $ProgramDataDir "runtime"
$UsersDir = Join-Path $SecureDir "users"
$ConfigPath = Join-Path $SecureDir "config.json"
$ServiceScript = Join-Path $InstallDir "service.py"
. (Join-Path $SourceDir "scope_helpers.ps1")

Write-Host "Using Python: $PythonExe"
Write-Host "Installing Windows Login Guard v1.7.2..."

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $UsersDir -Force | Out-Null
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null

Copy-Item "$SourceDir\*.py" $InstallDir -Force
Copy-Item "$SourceDir\*.pyw" $InstallDir -Force
Copy-Item "$SourceDir\*.ps1" $InstallDir -Force
Copy-Item "$SourceDir\*.cmd" $InstallDir -Force
Copy-Item "$SourceDir\requirements.txt" $InstallDir -Force
Copy-Item "$SourceDir\config.example.json" $InstallDir -Force
Copy-Item "$SourceDir\VERSION" $InstallDir -Force

Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @("-m", "pip", "install", "--upgrade", "pip") `
    -Description "pip upgrade"
Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @("-m", "pip", "install", "--upgrade", "-r", (Join-Path $InstallDir "requirements.txt")) `
    -Description "dependency installation"
Invoke-PyWin32PostInstall -PythonPath $PythonExe
Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @("-c", "import pyotp, qrcode, PIL, win32serviceutil, win32ts; print('Dependency check passed')") `
    -Description "dependency validation"

icacls $ProgramDataDir /inheritance:r | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to secure $ProgramDataDir." }
icacls $ProgramDataDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(RX)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to set ProgramData permissions." }
icacls $SecureDir /inheritance:r | Out-Null
icacls $SecureDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to set secure-directory permissions." }
icacls $RuntimeDir /inheritance:r | Out-Null
icacls $RuntimeDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to set runtime-directory permissions." }

Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @((Join-Path $InstallDir "self_test.py")) `
    -Description "pre-install self-test"

if (-not (Test-Path $ConfigPath)) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $config = [ordered]@{
        credential_mode = "per_user"
        protection_scope = $ProtectionScope
        installer_user_sid = $identity.User.Value
        installer_user_name = $identity.Name
        excluded_user_sids = @()
        initial_enrollment_sids = @($identity.User.Value)
        verify_on_logon = $true
        verify_on_unlock = $true
        enforce_on_service_start = $true
        timeout_seconds = 45
        poll_interval_seconds = 1
        max_otp_attempts = 5
        ui_ready_timeout_seconds = 10
        ui_launch_retries = 1
        enrollment_session_timeout_seconds = 600
        allow_bootstrap_enrollment = $false
        out_of_scope_policy = $OutOfScopePolicy
        no_approver_policy = "allow"
        approval_timeout_seconds = 120
        failure_actions = [ordered]@{
            logon = "logoff"
            unlock = "lock"
            service_start = "lock"
            admin_approval_timeout = "lock"
            out_of_scope_deny = "logoff"
        }
        lock_action_timeout_seconds = 8
        lock_failure_action = "logoff"
        allowed_approval_durations = @(
            "once", "until_lock", "session", "15_minutes", "30_minutes", "1_hour", "2_hours", "4_hours", "8_hours", "24_hours"
        )
        default_approval_duration = "session"
        issuer = "Windows Login Guard"
    }
    Write-WlgJsonNoBom -Path $ConfigPath -Object $config
}

Push-Location $InstallDir
try {
    Invoke-CheckedNative -FilePath $PythonExe `
        -Arguments @("-c", "from common import load_config; print(load_config()['credential_mode'])") `
        -Description "configuration validation"
}
finally { Pop-Location }

Remove-WlgLegacyUiTasks
Stop-WlgUiProcesses

if (Get-Service WindowsLoginGuard -ErrorAction SilentlyContinue) {
    Stop-Service WindowsLoginGuard -Force -ErrorAction SilentlyContinue
    & $PythonExe $ServiceScript remove | Out-Null
    Start-Sleep -Seconds 1
}
Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @($ServiceScript, "--startup", "auto", "install") `
    -Description "service installation"
sc.exe failure WindowsLoginGuard reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to configure service recovery actions." }
sc.exe failureflag WindowsLoginGuard 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable service recovery actions." }

$SecureDir = Join-Path $env:ProgramData "WindowsLoginGuard\secure"

$ManagementTokenPath = Join-Path $SecureDir "management.token"
if (-not (Test-Path $ManagementTokenPath)) {
    $managementBytes = New-Object byte[] 32
    $managementRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $managementRng.GetBytes($managementBytes)
    }
    finally {
        $managementRng.Dispose()
    }
    $managementToken = [Convert]::ToBase64String($managementBytes)
    [System.IO.File]::WriteAllText(
        $ManagementTokenPath,
        $managementToken,
        [System.Text.Encoding]::ASCII
    )
}
icacls $ManagementTokenPath /inheritance:r | Out-Null
icacls $ManagementTokenPath /grant:r "SYSTEM:F" "Administrators:F" | Out-Null

$MaintenanceHashPath = Join-Path $SecureDir "maintenance-key.sha256"
$NewMaintenanceKey = $null
if (-not (Test-Path $MaintenanceHashPath)) {
    $keyBytes = New-Object byte[] 20
    $keyRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $keyRng.GetBytes($keyBytes)
    }
    finally {
        $keyRng.Dispose()
    }
    $hex = ($keyBytes | ForEach-Object { $_.ToString("X2") }) -join ""
    $NewMaintenanceKey = (
        $hex.Substring(0, 8) + "-" +
        $hex.Substring(8, 8) + "-" +
        $hex.Substring(16, 8) + "-" +
        $hex.Substring(24, 8) + "-" +
        $hex.Substring(32, 8)
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($NewMaintenanceKey)
        )
    }
    finally {
        $sha.Dispose()
    }
    $hashHex = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    Set-Content -Path $MaintenanceHashPath -Value $hashHex -Encoding ASCII
}
icacls $MaintenanceHashPath /inheritance:r | Out-Null
icacls $MaintenanceHashPath /grant:r "SYSTEM:F" "Administrators:F" | Out-Null

Start-Service WindowsLoginGuard
(Get-Service WindowsLoginGuard).WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Running,
    [TimeSpan]::FromSeconds(20)
)

$AdminShortcutPath = New-WlgAdminDesktopShortcut `
    -InstallDir $InstallDir

Write-Host ""
Write-Host "Installation complete."
Write-Host "Admin shortcut: $AdminShortcutPath"
if ($NewMaintenanceKey) {
    Write-Host ""
    Write-Host "SAVE THIS MAINTENANCE RECOVERY KEY OFFLINE." -ForegroundColor Yellow
    Write-Host "It will not be displayed again:"
    Write-Host ""
    Write-Host "  $NewMaintenanceKey" -ForegroundColor Cyan
    Write-Host ""
}
Write-Host "The installer account's enrollment window should open automatically."
Write-Host "Its QR code is displayed in the window and is not written to disk."
Write-Host "An unenrolled protected account is never logged off by Login Guard."
Write-Host "Logs: $SecureDir\guard.log"
