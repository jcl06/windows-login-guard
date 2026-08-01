# Optional Remote Management for Windows Login Guard v1.10.3


> Remote management is an optional extension. Install and test local Windows
> Login Guard first. A standalone PC does not require this role.

Remote management is optional. A single PC can use Windows Login Guard local
TOTP protection, recovery, configuration, audit, diagnostics, and the local
Administration console without installing this role.

For local-only deployment, see:

- [Installation Guide](docs/INSTALLATION.md#one-standalone-pc-local-only)
- [Local Administration Guide](docs/LOCAL_ADMINISTRATION.md)

## Prerequisites

Remote management is installed only after the common and role-specific
requirements in
[Windows Installation Prerequisites](docs/PREREQUISITES.md) are satisfied.

The management-server PC must already:

- be protected by Windows Login Guard;
- have the current Windows administrator fully enrolled;
- have a stable resolvable hostname or FQDN;
- have an unused TCP port, normally 8443;
- permit Windows Firewall administration;
- have outbound package-repository access during installation.

For a normal management-server installation, both `-DnsName` and
`-Port` are optional:

```powershell
.\test-prerequisites.ps1 -Role ManagementServer
```

When omitted, the installation uses:

```text
DnsName = $env:COMPUTERNAME
Port    = 8443
```

Specify them only when using a deliberately configured DNS alias or FQDN, or
when changing the HTTPS port:

```powershell
.\test-prerequisites.ps1 `
    -Role ManagementServer `
    -DnsName "wlg-server.example.internal" `
    -Port 9443
```

A custom DNS name must resolve to the management-server PC from the server
itself, every protected PC, and every separate Admin PC.

A separate Admin PC should run:

```powershell
.\test-prerequisites.ps1 -Role RemoteAdmin
```

## Installation overview

Remote management has three deployment roles:

1. **Management-server PC** — hosts the HTTPS API, central database, local
   Remote Administration app, notifier, and normally its own protected-PC
   Remote Agent.
2. **Protected PC** — runs local Windows Login Guard plus the outbound Remote
   Agent.
3. **Separate Admin PC** — runs only Remote Administration and the per-user
   approval notifier.

The management-server PC may also be the only Admin PC. In that case,
`install-remote-server.ps1` installs and links Remote Administration
automatically; do not run `install-remote-admin.ps1` on the server PC.

## Step 1: protect and enroll the management-server PC

The future server must first be a working protected PC.

From elevated PowerShell in the extracted release:

```powershell
.\test-prerequisites.ps1 -Role ProtectedPc
.\install-protected-pc.ps1
```

Complete OTP enrollment for the Windows administrator that will install the
server. Confirm that local verification and the local Administration console
work before continuing.

The account running `install-remote-server.ps1` must:

- be enrolled in Windows Login Guard;
- still have its DPAPI-protected TOTP secret;
- be a Windows administrator.

## Step 2: install the management server and its local Admin app

For a normal installation, let the installer use the current Windows
computer name and the default HTTPS port:

```powershell
.\test-prerequisites.ps1 -Role ManagementServer
.\install-remote-server.ps1
```

These defaults are equivalent to:

```text
DnsName = $env:COMPUTERNAME
Port    = 8443
```

Use explicit parameters only when a different, already configured DNS identity
or HTTPS port is required:

```powershell
.\test-prerequisites.ps1 `
    -Role ManagementServer `
    -DnsName "wlg-server.example.internal" `
    -Port 9443

.\install-remote-server.ps1 `
    -DnsName "wlg-server.example.internal" `
    -Port 9443
```

The selected name is written into the server URL and certificate. Every
protected PC and separate Admin PC must be able to resolve that name.

The installer performs all of the following:

- upgrades the local protected-PC role to the current release;
- installs `WindowsLoginGuardManagementServer`;
- generates or preserves the HTTPS certificate and private key;
- creates the TCP firewall rule for `LocalSubnet`;
- installs Remote Administration locally;
- links the currently enrolled local administrator;
- reuses that administrator's existing Windows Login Guard OTP;
- registers the server PC as a managed protected device;
- installs and starts `WindowsLoginGuardRemoteAgent`;
- enables the approval notifier for the current Windows user;
- opens Remote Administration.

No separate remote-administrator OTP is created for the automatically linked
administrator.

Verify the services:

```powershell
Get-Service `
    WindowsLoginGuard, `
    WindowsLoginGuardManagementServer, `
    WindowsLoginGuardRemoteAgent
```

Verify the listener:

```powershell
Get-NetTCPConnection `
    -LocalPort 8443 `
    -State Listen
```

The local Remote Administration app uses the loopback endpoint created by the
installer. Remote clients must use the configured hostname or FQDN, not
`localhost`.

## Step 3: register another protected PC

Protected-PC registration is initiated on the management-server PC. Remote
Administration displays and manages a device only after the generated bundle
has been installed on that PC, registration has completed, and the Remote
Agent has sent its first synchronization.

Remote Administration does not require the administrator to manually enter a
device ID, token, server URL, or certificate.

On the management-server PC, create a complete installer bundle:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\new-protected-pc-installer.ps1" `
    -Label "Accounting-PC" `
    -ValidHours 24
```

The ZIP is created on the current user's Desktop unless `-OutputDirectory` is
specified. It contains a single-use protected-device registration code with
the requested validity period.

Transfer the ZIP securely to the target PC. On that PC:

1. Extract the ZIP.
2. Open PowerShell as Administrator in the extracted directory.
3. Run:

```powershell
Get-ChildItem -LiteralPath . -Recurse -File |
    Unblock-File

Set-ExecutionPolicy `
    -Scope Process `
    -ExecutionPolicy Bypass `
    -Force

.\install-protected-pc.ps1
```

The bundle already contains the server URL, public certificate, display name,
and single-use registration code. Do not enter them manually.

Verify the endpoint:

```powershell
Get-Service WindowsLoginGuard, WindowsLoginGuardRemoteAgent

& "C:\Program Files\WindowsLoginGuard\test-remote-endpoint.ps1"
```

If local installation succeeds but registration is interrupted, retry after
connectivity is restored:

```powershell
& "C:\Program Files\WindowsLoginGuard\resume-remote-registration.ps1"
```

Local OTP protection remains active while remote registration is pending.

After successful installation, wait for the Remote Agent's first
synchronization, then open Remote Administration and confirm that the new
device appears in the protected-device inventory.

On the management server, registrations can also be reviewed with:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\list-remote-registrations.ps1"
```

## Step 4: install a separate Admin PC

A separate Admin PC does not need the local Windows Login Guard service unless
you also want that PC protected. It needs:

- the extracted current release;
- the public management-server certificate;
- a single-use Admin-workstation registration code;
- network access to the server hostname and port.

### On the management-server PC: export the public certificate

Use a command to copy the public certificate to a transfer location. Do not
copy or expose `server.key` or the management database.

```powershell
$serverInstall = "C:\Program Files\WindowsLoginGuardRemoteServer"
$setup = Get-Content `
    (Join-Path $serverInstall "remote-setup.json") `
    -Raw |
    ConvertFrom-Json

$publicCert = Join-Path `
    ([Environment]::GetFolderPath("Desktop")) `
    "wlg-management-server.crt"

Copy-Item `
    -LiteralPath $setup.server_certificate `
    -Destination $publicCert `
    -Force

$publicCert
```

### On the management-server PC: create the Admin-PC code

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\new-workstation-enrollment-token.ps1" `
    -Label "ADMIN-PC - Administrator" `
    -ValidHours 24
```

The code is single-use and expires. Transfer the code and public certificate
through a secure channel.

### On the separate Admin PC: install Remote Administration

From elevated PowerShell in the extracted release:

```powershell
Get-ChildItem -LiteralPath . -Recurse -File |
    Unblock-File

Set-ExecutionPolicy `
    -Scope Process `
    -ExecutionPolicy Bypass `
    -Force

.\test-prerequisites.ps1 -Role RemoteAdmin
.\install-remote-admin.ps1
```

Open the desktop shortcut:

```text
Windows Login Guard Remote Administration
```

Or run:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteAdmin\open-remote-admin.ps1"
```

On first launch, enter:

| Field | Value |
|---|---|
| Server URL | `https://wlg-server.example.internal:8443` |
| Server certificate | the copied `wlg-management-server.crt` |
| Registration code | the single-use code created on the server |
| Workstation label | a descriptive Admin-PC name |

Select **Register**. Then sign in with an enabled remote administrator.

For the administrator automatically linked by `install-remote-server.ps1`, use
the linked Windows Login Guard username and the same authenticator OTP used on
the management-server PC.

The workstation token is protected with current-user DPAPI. The notifier is
registered under the current user's `HKCU` Run key. When another Windows user
will use Remote Administration on the same PC, create another workstation code
and complete registration while signed in as that user.

### Optional: create an independent remote administrator

Most deployments should use the automatically linked local administrator. To
create a separate management-only OTP identity on the server:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\new-remote-admin.ps1" `
    -Username "remote-admin"
```

Scan the generated QR code and use that username and OTP when signing in from a
registered Admin PC.

## Step 5: verify registrations and connectivity

On the management server:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\list-remote-registrations.ps1"
```

On a separate Admin PC:

```powershell
Test-NetConnection `
    wlg-server.example.internal `
    -Port 8443
```

Open Remote Administration and confirm:

- the management-server PC appears online;
- newly installed protected PCs appear online;
- the Sessions, Audit, Logs, and Diagnostics views load;
- a test approval notification reaches the intended Admin user;
- Lock Session and Log Off Session are enabled only for valid online sessions.

## Upgrade remote-management roles

Upgrade protected PCs with:

```powershell
.\upgrade-to-v1.10.3.ps1
```

Upgrade or repair a server that uses the default computer name and TCP 8443
by rerunning:

```powershell
.\install-remote-server.ps1
```

When the original installation used an explicit DNS alias, FQDN, or nondefault
port, use the same values during repair or upgrade:

```powershell
.\install-remote-server.ps1 `
    -DnsName "wlg-server.example.internal" `
    -Port 9443
```

Changing the server name or port changes the management URL and may require
updated client registration or certificate deployment.

Upgrade a **separate** Admin PC by rerunning:

```powershell
.\install-remote-admin.ps1
```

Existing per-user workstation registration is retained unless it is revoked or
reset.

## Architecture

Remote management uses three separate roles:

```text
Protected PC Remote Agent
        │ outbound HTTPS
        ▼
Management Server API
        ▲
        │ HTTPS
Remote Administration / Approval Notifier
```

Protected PCs initiate outbound connections. The management server does not
open an interactive connection to a protected PC.

The management-server PC may also be a protected PC and the primary Admin PC.
Its local Remote Administration and Remote Agent use
`https://localhost:<port>`. Remote protected PCs use the configured hostname or
FQDN.

## Components

### Protected PC

- Windows Login Guard service
- verification and enrollment UI
- local encrypted user state
- Remote Agent, when remote management is enabled
- pinned public management-server certificate
- device-specific token and signed-command secret protected by DPAPI

### Management server

- HTTPS API service
- server certificate and private key
- SQLite management database
- registered device and Admin-workstation identities
- device telemetry, approval requests, commands, and central audit history

### Admin workstation

- Remote Administration desktop application
- current-user DPAPI-protected workstation token
- pinned public server certificate
- notification-only background notifier
- in-memory administrator session after OTP authentication

## Authentication model

### Administrator sign-in

The management database stores the linked Windows SID and authentication
source. It does not copy the local TOTP secret into the management database.

For a local linked administrator, the server validates the supplied OTP against
the original Windows Login Guard credential protected by machine DPAPI on the
management-server PC.

A successful sign-in creates a short-lived in-memory/API administrator session.
Approve, Deny, Lock Session, and Log Off Session use that authenticated session
without a second OTP prompt.

Closing Remote Administration discards the desktop application's in-memory
session.

### Admin workstation identity

A workstation token identifies a registered, non-revoked Admin workstation.
The token is protected with current-user DPAPI.

The background notifier uses this identity only against the
notification-specific endpoint. It cannot call privileged decision, device
removal, dashboard, log, or remote session-control endpoints.

### Protected-device identity

Each protected PC has:

- a device ID;
- a device bearer token;
- a device-specific signed-command secret;
- a stable hash derived from the Windows MachineGuid for idempotent
  registration.

The server stores token hashes rather than plaintext device tokens.

## TLS and certificate handling

The management server uses HTTPS. Installers generate or reuse the configured
server certificate.

Protected PCs and Admin workstations pin the public server certificate. A
protected-PC installer bundle may contain the public certificate, but never the
private key.

The configured `DnsName` must be a hostname or FQDN that protected PCs can
resolve and that appears in the certificate.

## Device registration

Registration codes are:

- short-lived;
- single-use;
- stored by hash on the server;
- bound to a registration type;
- removed from the generated bundle after successful registration when
  possible.

If the server accepts a registration but the response is lost, the same
machine may safely retry within the code's validity window. The stable machine
identity prevents creation of another active record for the same Windows
installation.

## Device telemetry

A protected PC sends current snapshots containing operational data such as:

- endpoint and agent version;
- online/health state;
- Windows session metadata;
- verification state;
- redacted local logs;
- diagnostics;
- approval-request metadata.

It does not send:

- TOTP secrets;
- recovery codes;
- maintenance keys;
- plaintext DPAPI-protected values;
- Windows account passwords.

The management server stores the latest device snapshot. The Remote
Administration console refreshes inventory and selected-device details only
while it is open.

## Approval notification flow

The notification-only background process runs in the signed-in Admin user's
Windows session.

It polls every five seconds for minimal pending-request metadata:

- request ID;
- device ID and display name;
- Windows session ID;
- username;
- request and expiration timestamps.

Selecting a notification opens Remote Administration. The administrator must
authenticate with OTP before taking action.

## Remote approval protocol

A protected session creates an approval request bound to:

- device ID;
- Windows session ID;
- username and user SID;
- challenge ID;
- request ID;
- expiration.

The administrator reviews the request and confirms Approve or Deny. Approval
also includes a permitted duration.

The server creates a short-lived HMAC-signed command. The protected PC checks:

- command type;
- device ID;
- request ID and command ID;
- Windows session ID;
- username and user SID;
- challenge ID;
- issue and expiration times;
- nonce;
- HMAC signature;
- replay state.

Only then does the Remote Agent ask the local Windows Login Guard service to
apply the decision.

## Remote lock and logoff

Remote Administration acts on a selected Windows session, not an unqualified
whole-machine action.

### Lock Session

The protected PC validates the live session identity and disconnects the
selected session through Windows Terminal Services. Running applications remain
open.

### Log Off Session

The protected PC validates the live session identity and logs off the selected
session through Windows Terminal Services. Applications close and unsaved work
may be lost.

Both actions require:

- an authenticated administrator session;
- a registered Admin workstation;
- an online protected PC;
- a ready signed-command channel;
- a current matching session ID and user SID;
- an explicit confirmation;
- command delivery before the 90-second expiration.

Both actions are audited centrally and locally.

## Server outage behavior

Windows Login Guard local protection does not depend on management-server
availability.

During an outage:

- local OTP verification continues;
- local failure actions continue;
- remote approval cannot be requested or completed;
- new remote lock/logoff commands cannot be delivered;
- the device eventually appears offline in Remote Administration;
- the Remote Agent retries with exponential backoff capped at 900 seconds.

The retry schedule resets immediately after a successful synchronization.

## Network exposure

The default management-server firewall rule allows TCP 8443 from
`LocalSubnet` on all Windows network profiles.

This is suitable for a single trusted local subnet. Deployments spanning routed
subnets, site-to-site VPNs, or untrusted networks must define explicit firewall
scope and certificate/DNS requirements.

Protected PCs require outbound HTTPS access to the management server. They do
not require an inbound Windows Firewall rule.

## Sensitive storage locations

The following locations contain private runtime state and must not be copied
into source control or a public release:

```text
C:\ProgramData\WindowsLoginGuard\secure
C:\ProgramData\WindowsLoginGuardRemoteServer\secure
%LOCALAPPDATA%\WindowsLoginGuardRemoteAdmin
```

Generated protected-PC bundles must be treated as temporary deployment
artifacts until their registration codes expire or are consumed.

## Revocation and removal

Removing a stale device registration deletes server-side registration and
cached telemetry. It does not uninstall Windows Login Guard from the protected
PC.

Removing an online device invalidates its Remote Agent registration. The
device must be registered again before remote synchronization resumes.

Workstation and administrator identities may also be revoked through the
provided management tools.

## Security boundaries

Remote management intentionally does not provide:

- arbitrary command execution;
- remote PowerShell;
- file transfer;
- remote password reset;
- direct retrieval of OTP or recovery secrets;
- general software installation.

These exclusions limit the attack surface and keep the signed command channel
restricted to defined Windows Login Guard operations.
