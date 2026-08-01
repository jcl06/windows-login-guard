# Optional Remote Management for Windows Login Guard v1.10.2


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

Run:

```powershell
.\test-prerequisites.ps1 `
    -Role ManagementServer `
    -DnsName "wlg-server.example.internal" `
    -Port 8443
```

A separate Admin PC should run:

```powershell
.\test-prerequisites.ps1 -Role RemoteAdmin
```

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
