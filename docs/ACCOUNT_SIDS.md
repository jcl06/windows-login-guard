# Finding a Windows Account SID

`authorize-initial-enrollment.ps1` requires the target Windows account's
security identifier (SID), for example:

```text
S-1-5-21-123456789-123456789-123456789-1001
```

Use the SID of the user account that must complete enrollment. Do not use a
group SID, machine SID, or the SID of a different administrator account.

## Current PowerShell account

Show the identity and SID of the account running the current PowerShell
process:

```powershell
whoami /user
```

Return only the SID:

```powershell
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

`whoami /user` reports the identity of the elevated PowerShell process. When
PowerShell was started with different administrator credentials, this may not
be the Windows account that is currently signed in at the desktop.

## Currently signed-in interactive user

From an elevated PowerShell window, identify the interactive desktop user and
translate that account name to its SID:

```powershell
$interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
$interactiveUser

$targetSid = (
    New-Object System.Security.Principal.NTAccount($interactiveUser)
).Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value

$targetSid
```

This is the safer method when the elevated PowerShell window may be running as
a different administrator.

## List local accounts and their SIDs

Using the Local Accounts module:

```powershell
Get-LocalUser |
    Select-Object Name, Enabled, SID
```

A CIM alternative is:

```powershell
Get-CimInstance Win32_UserAccount `
    -Filter "LocalAccount=True" |
    Select-Object Name, Domain, Disabled, SID
```

## Resolve one local account

Replace `AccountName` with the exact local Windows account name:

```powershell
$targetSid = (
    Get-LocalUser -Name "AccountName"
).SID.Value

$targetSid
```

Then authorize its one-time enrollment:

```powershell
& "C:\Program Files\WindowsLoginGuard\authorize-initial-enrollment.ps1" `
    -UserSid $targetSid
```

## Resolve a domain account

Use the full `DOMAIN\UserName` account name:

```powershell
$accountName = "CONTOSO\UserName"

$targetSid = (
    New-Object System.Security.Principal.NTAccount($accountName)
).Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value

$targetSid
```

For a local account resolved through `NTAccount`, use:

```powershell
$accountName = "$env:COMPUTERNAME\AccountName"
```

## Verify that a SID resolves to the expected account

Before authorizing enrollment:

```powershell
$sid = New-Object `
    System.Security.Principal.SecurityIdentifier($targetSid)

$sid.Translate(
    [System.Security.Principal.NTAccount]
).Value
```

Confirm that the returned account is the intended user.

## Complete example

This example authorizes the currently signed-in interactive desktop account,
even when the elevated shell uses different administrator credentials:

```powershell
$interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName

if (-not $interactiveUser) {
    throw "No interactive Windows user was detected."
}

$targetSid = (
    New-Object System.Security.Principal.NTAccount($interactiveUser)
).Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value

Write-Host "Authorizing $interactiveUser with SID $targetSid"

& "C:\Program Files\WindowsLoginGuard\authorize-initial-enrollment.ps1" `
    -UserSid $targetSid
```

The authorization is one-time. Windows Login Guard removes it automatically
after the account successfully tests and activates its OTP enrollment.
