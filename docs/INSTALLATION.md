# Installation and First Enrollment

Run the prerequisite checker:

```powershell
.\test-prerequisites.ps1 -Role ProtectedPc
```

Install a standalone protected PC:

```powershell
.\install-protected-pc.ps1
```

Save the machine maintenance recovery key displayed by the installer.

![Lab-VM enrollment](images/lab-enrollment.png)

Scan the QR code or enter the manual key, confirm the six-digit TOTP, save the
recovery codes, and select Continue.

![Lab-VM recovery codes](images/lab-recovery-codes.png)

Test by locking Windows:

```powershell
rundll32.exe user32.dll,LockWorkStation
```

![Lab-VM verification](images/lab-verification.png)

Protection scopes are `installer_user`, `administrators`, and `all_users`.
Out-of-scope behavior is `allow`, `require_admin_approval`, or `deny`.

Additional account enrollment may require an enrolled administrator:

![Lab-VM administrator approval](images/lab-administrator-approval.png)

## Authorize one account for controlled initial enrollment

The authorization script requires the target account SID.

List local accounts:

```powershell
Get-LocalUser |
    Select-Object Name, Enabled, SID
```

Resolve one local account and authorize it:

```powershell
$targetSid = (
    Get-LocalUser -Name "AccountName"
).SID.Value

& "C:\Program Files\WindowsLoginGuard\authorize-initial-enrollment.ps1" `
    -UserSid $targetSid
```

When PowerShell is elevated using a different administrator, identify the
interactive desktop account instead of using `whoami /user`:

```powershell
$interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName

$targetSid = (
    New-Object System.Security.Principal.NTAccount($interactiveUser)
).Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value
```

The trusted enrollment entry is removed automatically after successful OTP
testing.

See [Finding a Windows Account SID](ACCOUNT_SIDS.md) for domain-account and SID
verification commands.
