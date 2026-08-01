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

## Install optional remote management

Install and test local protection before adding remote management.

### Management-server PC

The server PC must already have Windows Login Guard installed, and the current
Windows administrator must have completed OTP enrollment.

```powershell
.\test-prerequisites.ps1 `
    -Role ManagementServer `
    -DnsName "wlg-server.example.internal" `
    -Port 8443

.\install-remote-server.ps1 `
    -DnsName "wlg-server.example.internal" `
    -Port 8443
```

The installer automatically installs the management service, local Remote
Administration app, approval notifier, Remote Agent, firewall rule, linked
administrator identity, and local device registration.

### Additional protected PC

Create the bundle on the server:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\new-protected-pc-installer.ps1" `
    -Label "Protected-PC"
```

Transfer and extract the generated ZIP on the endpoint, then run as
Administrator:

```powershell
.\install-protected-pc.ps1
```

### Separate Admin PC

On the management server, create a workstation registration code:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\new-workstation-enrollment-token.ps1" `
    -Label "ADMIN-PC - Administrator" `
    -ValidHours 24
```

Copy only the public server certificate to the Admin PC. Do not copy the server
private key or database.

On the Admin PC:

```powershell
.\test-prerequisites.ps1 -Role RemoteAdmin
.\install-remote-admin.ps1
```

Open **Windows Login Guard Remote Administration**. On first launch, provide:

- the management-server URL;
- the copied public certificate;
- the single-use Admin-workstation registration code;
- a workstation label.

After registration, sign in with the linked administrator username and the
same Windows Login Guard OTP used on the management-server PC.

See [Optional Remote Management](../REMOTE_MANAGEMENT.md) for the complete
certificate-export command, service checks, registration verification,
troubleshooting, and upgrade procedures.

