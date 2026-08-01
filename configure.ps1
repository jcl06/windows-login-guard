#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet("installer_user", "administrators", "all_users")]
    [string]$ProtectionScope,
    [ValidateSet("allow", "require_admin_approval", "deny")]
    [string]$OutOfScopePolicy,
    [ValidateSet("allow", "deny")]
    [string]$NoApproverPolicy,
    [ValidateSet("inline", "admin_session", "either")]
    [string]$AdminApprovalMode,
    [ValidateSet("topmost", "isolated_desktop")]
    [string]$InteractionMode,
    [Nullable[int]]$IsolatedDesktopStartTimeoutSeconds,
    [ValidateSet("topmost", "lock")]
    [string]$IsolatedDesktopFallback,
    [Nullable[bool]]$VerifyOnLogon,
    [Nullable[bool]]$VerifyOnUnlock,
    [Nullable[bool]]$EnforceOnServiceStart,
    [Nullable[bool]]$AllowBootstrapEnrollment,
    [Nullable[int]]$TimeoutSeconds,
    [Nullable[int]]$ApprovalTimeoutSeconds,
    [ValidateSet("allow", "lock", "logoff")]
    [string]$LogonFailureAction,
    [ValidateSet("allow", "lock", "logoff")]
    [string]$UnlockFailureAction,
    [ValidateSet("allow", "lock", "logoff")]
    [string]$ServiceStartFailureAction,
    [ValidateSet("allow", "lock", "logoff")]
    [string]$AdminApprovalTimeoutAction,
    [ValidateSet("allow", "lock", "logoff")]
    [string]$OutOfScopeDenyAction,
    [Nullable[int]]$LockActionTimeoutSeconds,
    [Nullable[bool]]$CompactVerifyWindow,
    [Nullable[bool]]$AutoSubmitOtp,
    [Nullable[int]]$AutoSubmitDelayMs,
    [Nullable[bool]]$AlwaysOnTop,
    [Nullable[bool]]$ForceForeground,
    [Nullable[int]]$FocusRetryMs,
    [Nullable[int]]$FocusRetryCount,
    [ValidateSet("allow", "logoff")]
    [string]$LockFailureAction,
    [ValidateSet("once", "until_lock", "session", "15_minutes", "1_hour", "8_hours", "24_hours")]
    [string]$DefaultApprovalDuration,
    [string[]]$AllowedApprovalDurations,
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuard"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $InstallDir "scope_helpers.ps1")

$ConfigPath = Join-Path $env:ProgramData "WindowsLoginGuard\secure\config.json"
if (-not (Test-Path $ConfigPath)) { throw "Active config not found: $ConfigPath" }
$configText = Get-Content $ConfigPath -Raw
$config = $configText | ConvertFrom-Json

if ($PSBoundParameters.ContainsKey("ProtectionScope")) {
    Set-WlgJsonProperty $config "protection_scope" $ProtectionScope
}
if ($PSBoundParameters.ContainsKey("OutOfScopePolicy")) {
    Set-WlgJsonProperty $config "out_of_scope_policy" $OutOfScopePolicy
}
if ($PSBoundParameters.ContainsKey("NoApproverPolicy")) {
    Set-WlgJsonProperty $config "no_approver_policy" $NoApproverPolicy
}
if ($PSBoundParameters.ContainsKey("AdminApprovalMode")) {
    Set-WlgJsonProperty $config "admin_approval_mode" $AdminApprovalMode
}
if ($PSBoundParameters.ContainsKey("InteractionMode")) {
    Set-WlgJsonProperty $config "interaction_mode" $InteractionMode
}
if ($PSBoundParameters.ContainsKey("IsolatedDesktopStartTimeoutSeconds")) {
    Set-WlgJsonProperty $config "isolated_desktop_start_timeout_seconds" ([int]$IsolatedDesktopStartTimeoutSeconds)
}
if ($PSBoundParameters.ContainsKey("IsolatedDesktopFallback")) {
    Set-WlgJsonProperty $config "isolated_desktop_fallback" $IsolatedDesktopFallback
}
if ($PSBoundParameters.ContainsKey("VerifyOnLogon")) {
    Set-WlgJsonProperty $config "verify_on_logon" ([bool]$VerifyOnLogon)
}
if ($PSBoundParameters.ContainsKey("VerifyOnUnlock")) {
    Set-WlgJsonProperty $config "verify_on_unlock" ([bool]$VerifyOnUnlock)
}
if ($PSBoundParameters.ContainsKey("EnforceOnServiceStart")) {
    Set-WlgJsonProperty $config "enforce_on_service_start" ([bool]$EnforceOnServiceStart)
}
if ($PSBoundParameters.ContainsKey("AllowBootstrapEnrollment")) {
    Set-WlgJsonProperty $config "allow_bootstrap_enrollment" ([bool]$AllowBootstrapEnrollment)
}
if ($PSBoundParameters.ContainsKey("TimeoutSeconds")) {
    Set-WlgJsonProperty $config "timeout_seconds" ([int]$TimeoutSeconds)
}
if ($PSBoundParameters.ContainsKey("ApprovalTimeoutSeconds")) {
    Set-WlgJsonProperty $config "approval_timeout_seconds" ([int]$ApprovalTimeoutSeconds)
}
if (-not ($config.PSObject.Properties.Name -contains "failure_actions")) {
    Set-WlgJsonProperty $config "failure_actions" ([pscustomobject]@{
        logon = "logoff"
        unlock = "lock"
        service_start = "lock"
        admin_approval_timeout = "lock"
        out_of_scope_deny = "logoff"
    })
}
if ($PSBoundParameters.ContainsKey("LogonFailureAction")) {
    Set-WlgJsonProperty $config.failure_actions "logon" $LogonFailureAction
}
if ($PSBoundParameters.ContainsKey("UnlockFailureAction")) {
    Set-WlgJsonProperty $config.failure_actions "unlock" $UnlockFailureAction
}
if ($PSBoundParameters.ContainsKey("ServiceStartFailureAction")) {
    Set-WlgJsonProperty $config.failure_actions "service_start" $ServiceStartFailureAction
}
if ($PSBoundParameters.ContainsKey("AdminApprovalTimeoutAction")) {
    Set-WlgJsonProperty $config.failure_actions "admin_approval_timeout" $AdminApprovalTimeoutAction
}
if ($PSBoundParameters.ContainsKey("OutOfScopeDenyAction")) {
    Set-WlgJsonProperty $config.failure_actions "out_of_scope_deny" $OutOfScopeDenyAction
}
if ($PSBoundParameters.ContainsKey("LockActionTimeoutSeconds")) {
    Set-WlgJsonProperty $config "lock_action_timeout_seconds" ([int]$LockActionTimeoutSeconds)
}
if ($PSBoundParameters.ContainsKey("LockFailureAction")) {
    Set-WlgJsonProperty $config "lock_failure_action" $LockFailureAction
}
if ($PSBoundParameters.ContainsKey("CompactVerifyWindow")) {
    Set-WlgJsonProperty $config "ui_compact_verify_window" ([bool]$CompactVerifyWindow)
}
if ($PSBoundParameters.ContainsKey("AutoSubmitOtp")) {
    Set-WlgJsonProperty $config "ui_auto_submit_otp" ([bool]$AutoSubmitOtp)
}
if ($PSBoundParameters.ContainsKey("AutoSubmitDelayMs")) {
    Set-WlgJsonProperty $config "ui_auto_submit_delay_ms" ([int]$AutoSubmitDelayMs)
}
if ($PSBoundParameters.ContainsKey("AlwaysOnTop")) {
    Set-WlgJsonProperty $config "ui_always_on_top" ([bool]$AlwaysOnTop)
}
if ($PSBoundParameters.ContainsKey("ForceForeground")) {
    Set-WlgJsonProperty $config "ui_force_foreground" ([bool]$ForceForeground)
}
if ($PSBoundParameters.ContainsKey("FocusRetryMs")) {
    Set-WlgJsonProperty $config "ui_focus_retry_ms" ([int]$FocusRetryMs)
}
if ($PSBoundParameters.ContainsKey("FocusRetryCount")) {
    Set-WlgJsonProperty $config "ui_focus_retry_count" ([int]$FocusRetryCount)
}
if ($PSBoundParameters.ContainsKey("AllowedApprovalDurations")) {
    Set-WlgJsonProperty $config "allowed_approval_durations" @($AllowedApprovalDurations)
}
if ($PSBoundParameters.ContainsKey("DefaultApprovalDuration")) {
    Set-WlgJsonProperty $config "default_approval_duration" $DefaultApprovalDuration
}

$service = Get-Service WindowsLoginGuard -ErrorAction SilentlyContinue
if (-not $service) { throw "WindowsLoginGuard service is not installed." }
$wasRunning = $service.Status -eq "Running"
if ($wasRunning) {
    Stop-Service WindowsLoginGuard -Force
    (Get-Service WindowsLoginGuard).WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(20)
    )
}
Stop-WlgUiProcesses

try {
    Write-WlgJsonNoBom -Path $ConfigPath -Object $config

    $servicePath = (Get-CimInstance Win32_Service -Filter "Name='WindowsLoginGuard'").PathName
    $serviceExe = if ($servicePath.StartsWith('"')) {
        [regex]::Match($servicePath, '^"([^"]+)"').Groups[1].Value
    } else {
        $servicePath.Split(' ')[0]
    }
    $pythonExe = Join-Path (Split-Path -Parent $serviceExe) "python.exe"
    Push-Location $InstallDir
    try {
        & $pythonExe -c "from common import load_config; c=load_config(); print('Validated:', c['protection_scope'], c['out_of_scope_policy'])"
        if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }
    }
    finally { Pop-Location }

    Set-Service WindowsLoginGuard -StartupType Automatic
    Start-Service WindowsLoginGuard
    (Get-Service WindowsLoginGuard).WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(20)
    )
}
catch {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ConfigPath, $configText, $utf8NoBom)
    Write-Warning "Configuration failed. The previous config was restored."
    if ($wasRunning) { Start-Service WindowsLoginGuard -ErrorAction SilentlyContinue }
    throw
}

Write-Host ""
Write-Host "Configuration applied."
Write-Host "Protection scope: $($config.protection_scope)"
Write-Host "Out-of-scope policy: $($config.out_of_scope_policy)"
Write-Host "Administrator approval mode: $($config.admin_approval_mode)"
Write-Host "Interaction mode: $($config.interaction_mode)"
Write-Host "Isolated desktop startup timeout: $($config.isolated_desktop_start_timeout_seconds) seconds"
Write-Host "Isolated desktop fallback: $($config.isolated_desktop_fallback)"
Write-Host "Default approval duration: $($config.default_approval_duration)"
Write-Host "Failure actions:"
Write-Host "  logon: $($config.failure_actions.logon)"
Write-Host "  unlock: $($config.failure_actions.unlock)"
Write-Host "  service_start: $($config.failure_actions.service_start)"
Write-Host "  admin_approval_timeout: $($config.failure_actions.admin_approval_timeout)"
Write-Host "  out_of_scope_deny: $($config.failure_actions.out_of_scope_deny)"
Write-Host "Compact OTP window: $($config.ui_compact_verify_window)"
Write-Host "Automatic six-digit submission: $($config.ui_auto_submit_otp)"
Write-Host "Automatic submission delay: $($config.ui_auto_submit_delay_ms) ms"
Write-Host "Always on top: $($config.ui_always_on_top)"
Write-Host "Force foreground: $($config.ui_force_foreground)"
Write-Host "Focus retry delay: $($config.ui_focus_retry_ms) ms"
Write-Host "Focus retry count: $($config.ui_focus_retry_count)"
Write-Host "Active sessions were evaluated immediately after service restart."
