# Diagnostics and Troubleshooting

Run:

```powershell
& "C:\Program Files\WindowsLoginGuard\diagnose.ps1"
```

Check version and service:

```powershell
Get-Content "C:\Program Files\WindowsLoginGuard\VERSION"
Get-Service WindowsLoginGuard
```

Restart:

```powershell
Restart-Service WindowsLoginGuard -Force
```

A restart clears session-only F8 bypasses.

Review logs:

```powershell
Get-Content "C:\ProgramData\WindowsLoginGuard\secure\guard.log" -Tail 100
Get-Content "C:\ProgramData\WindowsLoginGuard\secure\admin_audit.jsonl" -Tail 100
```

## OTP prompt missing

Confirm service state, protection scope, and maintenance state, then review
`guard.log`.

## OTP rejected

Confirm PC and authenticator clocks:

```powershell
Get-Date
Get-TimeZone
w32tm /query /status
```

## F8 does nothing

F8 remains unavailable until the configured failed-attempt threshold is
reached.

## Administration console does not open

Run `open-admin.ps1` from elevated PowerShell and review service status and
`guard.log`.

## Version mismatch

Complete the upgrade or reinstall the same release so `admin.pyw` and the
service match.

## Maintenance key lost

Rotate it from **Recovery & Maintenance** using an enrolled administrator OTP
or recovery code.

## Desktop appears before OTP

Use isolated desktop with topmost fallback. This minimizes normal-desktop
exposure but remains post-login enforcement.

## Initial-enrollment authorization targets the wrong account

`whoami /user` returns the SID of the account running the elevated PowerShell
process. When PowerShell was started with another administrator's credentials,
that SID may not belong to the interactive desktop user.

Use:

```powershell
$interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName

$targetSid = (
    New-Object System.Security.Principal.NTAccount($interactiveUser)
).Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value
```

Verify the resolved identity before running the authorization script. See
[Finding a Windows Account SID](ACCOUNT_SIDS.md).
