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

For a normal installation, both `-DnsName` and `-Port` are optional:

```powershell
.\test-prerequisites.ps1 -Role ManagementServer
.\install-remote-server.ps1
```

The defaults are the current Windows computer name and TCP 8443.

Use explicit values only for a deliberately configured DNS alias or FQDN, or a
different HTTPS port:

```powershell
.\test-prerequisites.ps1 `
    -Role ManagementServer `
    -DnsName "wlg-server.example.internal" `
    -Port 9443

.\install-remote-server.ps1 `
    -DnsName "wlg-server.example.internal" `
    -Port 9443
```

The custom DNS name must resolve to the management-server PC from the server,
every protected PC, and every separate Admin PC.

The installer installs the management service, local Remote Administration app,
approval notifier, Remote Agent, firewall rule, linked administrator identity,
and local protected-device registration.

Verify:

```powershell
Get-Service `
    WindowsLoginGuard, `
    WindowsLoginGuardManagementServer, `
    WindowsLoginGuardRemoteAgent

Get-NetTCPConnection `
    -LocalPort 8443 `
    -State Listen
```

### Register an additional protected PC

On the management-server PC, create a complete protected-PC installer bundle:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\new-protected-pc-installer.ps1" `
    -Label "Protected-PC" `
    -ValidHours 24
```

The ZIP is created on the current user's Desktop unless `-OutputDirectory` is
specified. It contains the server URL, public certificate, display name, and a
single-use protected-device registration code.

Transfer the ZIP securely to the target PC. Extract it, open elevated
PowerShell in the extracted directory, and run:

```powershell
Get-ChildItem -LiteralPath . -Recurse -File |
    Unblock-File

Set-ExecutionPolicy `
    -Scope Process `
    -ExecutionPolicy Bypass `
    -Force

.\test-prerequisites.ps1 -Role ProtectedPc
.\install-protected-pc.ps1
```

Verify the endpoint:

```powershell
Get-Service WindowsLoginGuard, WindowsLoginGuardRemoteAgent

& "C:\Program Files\WindowsLoginGuard\test-remote-endpoint.ps1"
```

The device appears in Remote Administration after registration completes and
the Remote Agent performs its first synchronization.

When local protection succeeds but registration is interrupted, retry after
connectivity is restored:

```powershell
& "C:\Program Files\WindowsLoginGuard\resume-remote-registration.ps1"
```

Local OTP protection remains active while registration is pending or the
management server is unavailable.

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
