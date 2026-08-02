# Windows Login Guard v1.10.4

Windows Login Guard v1.10.4 is a cumulative release from v1.7.2.

It preserves standalone local TOTP enforcement, recovery, maintenance, local
Administration, audit, and diagnostics while adding optional centralized
remote management, remote approvals, remote session controls, resilient
endpoint synchronization, and reliable service-owned enforcement when the
verification UI fails.

Remote management remains optional. A protected PC continues to enforce local
TOTP when the management server is unavailable.

## Highlights

- Optional centralized management for protected Windows PCs
- Protected-PC outbound HTTPS communication
- Remote approval and denial for pending verification requests
- Background approval notifications on administrator workstations
- Remote Lock Session and Log Off Session actions
- Signed, device-specific, replay-resistant remote commands
- Central device, session, audit, log, and diagnostic visibility
- Stable protected-device identity and duplicate-registration prevention
- Generated protected-PC installer bundles
- Separate Remote Administration installation for dedicated Admin PCs
- Exponential endpoint retry backoff during management-server outages
- Service-owned verification-failure locking and fallback enforcement
- Expanded prerequisite, installation, recovery, security, and administration documentation

## Local protection retained from v1.7.2

Local-only deployments continue to support:

- per-account TOTP enrollment;
- QR-code and manual-key provisioning;
- DPAPI-protected TOTP secrets;
- one-time account recovery codes stored as hashes;
- configurable account-protection scope;
- administrator-authorized enrollment;
- verification after sign-in and workstation unlock;
- optional verification when the service starts;
- topmost and isolated-desktop verification modes;
- configurable timeout and attempt limits;
- separate sign-in, unlock, service-start, approval-timeout, and out-of-scope failure actions;
- hidden F8 session recovery after repeated OTP failures;
- machine-wide maintenance mode;
- maintenance recovery-key rotation;
- Safe Mode and Windows Recovery Environment recovery;
- local Administration, configuration, audit, and diagnostics.

Existing local enrollment, configuration, recovery-code hashes, maintenance
state, and audit data are preserved during supported upgrades.

## v1.8 remote-management foundation

The v1.8 series added the optional remote-management platform.

### Management server

The management server provides:

- an HTTPS API service;
- SQLite-backed management state;
- centralized protected-device inventory;
- registered administrator-workstation identities;
- central administrator sessions protected by OTP;
- device telemetry, approval requests, commands, and central audit history;
- last-known information for offline protected PCs.

The management-server installer also:

- installs the local Remote Administration application;
- links the currently enrolled local Windows Login Guard administrator;
- reuses that administrator's existing OTP;
- registers the management-server PC as a managed protected device;
- configures the current user's approval notifier;
- creates the required LocalSubnet firewall rule.

### Protected-PC Remote Agent

Protected PCs initiate outbound HTTPS connections to the server. No inbound
management port is opened on protected endpoints.

The Remote Agent synchronizes current operational state such as:

- endpoint and service health;
- enrolled-account totals;
- active Windows sessions;
- verification status;
- recent local audit activity;
- a redacted local log tail;
- diagnostic results.

It does not transmit TOTP seeds, recovery codes, maintenance keys, Windows
passwords, or plaintext DPAPI-protected values.

### Remote Administration

The desktop Remote Administration application provides:

- protected-device inventory;
- selected-device details;
- live Windows session visibility;
- central and endpoint audit history;
- endpoint log and diagnostic views;
- approval-request review;
- remote session Lock and Log Off actions.

Administrator API sessions are created through OTP authentication and remain in
application memory. Closing the application discards the in-memory session.

## Registration and deployment improvements

The release series adds:

- generated protected-PC installer ZIPs;
- embedded server URL, public certificate, display name, and single-use registration code;
- resumable protected-PC registration after temporary network failure;
- stable identity derived from the Windows installation;
- idempotent registration when a successful server response is lost;
- duplicate-device prevention;
- protected-device token rotation on re-registration;
- revocable protected-device and Admin-workstation registrations;
- server-side device removal without uninstalling the endpoint.

Generated endpoint bundles contain the public server certificate and
registration material only. They do not contain the server private key or
management database.

## v1.9 remote approval

The v1.9 series added end-to-end remote login approval.

A protected user can select **Request Approval** from the verification window.
The request is bound to the exact:

- protected device;
- Windows session;
- username and user SID;
- verification challenge;
- request ID;
- expiration;
- server-issued nonce.

Remote administrators can approve for:

- one verification;
- until workstation lock;
- until sign-out;
- 15 or 30 minutes;
- 1, 2, 4, 8, or 24 hours.

The user can return to local OTP verification while approval is pending.

### Approval notifier

A per-user notifier starts when the administrator signs in to Windows. It:

- polls for minimal pending-request metadata;
- displays Windows notifications;
- plays the Windows alert sound;
- opens Remote Administration when selected;
- cannot approve, deny, remove devices, read dashboards, or run session actions.

Approve and Deny use the active OTP-authenticated Remote Administration
session. A second OTP is not requested for each decision.

## Signed remote commands

Each protected device receives a unique command-signing secret through its
pinned TLS connection.

Commands are:

- signed with HMAC-SHA256;
- bound to the exact device, session, user SID, request, challenge, nonce, and expiration;
- rejected when invalid, expired, replayed, or mismatched;
- processed idempotently;
- audited centrally and locally.

## v1.10 remote session control

The v1.10 series added:

- **Lock Session**
- **Log Off Session**

The administrator selects an exact Windows session before issuing the action.

Locking disconnects the selected session while leaving applications running.
The user must authenticate again.

Logging off terminates the selected session and closes its applications.
Unsaved work may be lost, so Remote Administration displays an explicit
confirmation warning.

Session actions:

- require an authenticated Remote Administration session;
- require a registered Admin workstation;
- require an online protected PC and ready command channel;
- are bound to session ID, username, and user SID;
- expire after 90 seconds;
- are signed and processed idempotently;
- are audited centrally and locally.

## Remote Administration reliability fixes

The release series corrects:

- invisible OTP sign-in and workstation-registration dialogs;
- silent startup failures under `pythonw.exe`;
- network requests blocking the Tkinter UI thread;
- dashboard hangs during refresh;
- overlapping automatic and manual refresh operations;
- unnecessary rebuilding of inactive tabs;
- large audit and log rendering delays;
- Lock and Log Off controls being disabled during background refresh;
- unclear browser behavior when opening the server root URL.

API work now runs in background workers, only the active tab is rendered, and
inventory refresh no longer blocks otherwise valid session actions.

## Installer and server fixes

The cumulative release also corrects:

- pywin32 installation and runtime-repair detection;
- PowerShell handling of failed native Python import probes;
- machine-wide Python installation-scope detection;
- pip package-resolution checking through the same pip path used by installation;
- SQLite connection and temporary-database handle leakage;
- protected-PC bundle expiry handling;
- preservation of pending registration material;
- management-server firewall handling across Domain, Private, and Public profiles while remaining restricted to `LocalSubnet`;
- role preservation when upgrading a local-only PC;
- duplicate records caused by lost registration responses.

## v1.10.2 endpoint retry backoff

The protected-PC Remote Agent now uses exponential retry backoff during a
management-server outage.

With the default ten-second synchronization interval, consecutive failures use:

```text
10 seconds
20 seconds
40 seconds
80 seconds
160 seconds
320 seconds
640 seconds
900 seconds
900 seconds thereafter
```

The maximum retry interval is 15 minutes. The next successful synchronization
immediately restores the configured normal interval.

Local OTP enforcement is unaffected by the outage.

## v1.10.4 verification-failure lock correction

v1.10.4 corrects the verification-failure lock implementation introduced in
v1.10.3. `WTSDisconnectSession` disconnects an RDS session; it does not
guarantee that the visible local workstation desktop is locked. v1.10.3 also
accepted the disconnected session state as successful lock confirmation.

### Fix

- The service launches `lock_session.pyw` in the exact target user session.
- The helper runs on `winsta0\default` and calls `LockWorkStation()`.
- Lock completion requires `WTS_SESSION_LOCK`, session logoff, or session
  termination.
- A disconnected session state is no longer accepted as proof of a workstation
  lock.
- The configured `lock_failure_action` is applied when the lock is not
  confirmed before timeout.
- Audit details identify `LockWorkStation`, the target desktop, helper process,
  and actual confirmation event.

## v1.10.3 service-owned enforcement foundation

v1.10.3 moved verification-failure enforcement from the failed UI process to
the Windows service. v1.10.4 corrects the Windows locking method used by that
service-owned path.

### Root cause

Earlier builds recorded the configured failure action and queued the physical
lock for `ui.pyw`. During an isolated-desktop startup failure, that UI process
could be stuck or no longer polling, so `LockWorkStation()` was never called.
The lock timeout and configured fallback could also fail to complete.

### Fix

- The Windows service owns verification-failure session enforcement.
- Lock enforcement no longer depends on the failed verification UI.
- v1.10.3 attempted enforcement with `WTSDisconnectSession`; v1.10.4
  replaces that method with an interactive `LockWorkStation()` helper.
- The configured lock-action timeout is enforced by the service.
- The configured lock-failure action is applied when locking raises an error or is not confirmed before timeout.
- Maintenance, break-glass recovery, remote logoff, and session removal cancel outstanding service-owned lock waits cleanly.
- A failed Windows logoff request is no longer recorded as successful initiation.

### Audit events

The existing `verification_failure_action` event records the selected policy.
Execution is now recorded separately through:

- `verification_lock_requested`
- `verification_lock_completed`
- `verification_lock_failed`
- `verification_lock_fallback_applied`
- `windows_session_logoff_failed`

## Installation prerequisites

- Windows 10 or Windows 11, 64-bit
- Windows PowerShell 5.1 or newer
- Elevated local-administrator access
- 64-bit CPython 3.11 or newer installed for all users
- Python `pip` and Tcl/Tk GUI support
- Package-repository access during dependency installation
- Accurate Windows and authenticator-device clocks
- A TOTP-compatible authenticator

Run the appropriate preflight check before installation:

```powershell
.\test-prerequisites.ps1 -Role ProtectedPc
```

For a normal management-server installation, both `-DnsName` and `-Port`
are optional:

```powershell
.\test-prerequisites.ps1 -Role ManagementServer
```

The defaults are the current Windows computer name and TCP 8443.

Use explicit parameters only for a configured DNS alias/FQDN or a nondefault
port:

```powershell
.\test-prerequisites.ps1 `
    -Role ManagementServer `
    -DnsName "wlg-server.example.internal" `
    -Port 9443
```

```powershell
.\test-prerequisites.ps1 -Role RemoteAdmin
```

## Upgrade from v1.7.2 through v1.10.3

From elevated PowerShell in the extracted v1.10.4 package:

```powershell
Set-ExecutionPolicy `
    -Scope Process `
    -ExecutionPolicy Bypass `
    -Force

.\test-prerequisites.ps1 -Role ProtectedPc

.\upgrade.ps1
```

Verify:

```powershell
Get-Content "C:\Program Files\WindowsLoginGuard\VERSION"
Get-Service WindowsLoginGuard
```

Expected version:

```text
1.10.4
```

A local-only installation remains local-only. Remote management is not enabled
automatically.

The upgrade entry point is now version-neutral. Future releases continue to
use `upgrade.ps1`, while the target release is read from the `VERSION` file.

## New standalone installation

```powershell
.\install-protected-pc.ps1
```

No management-server parameters are required.

## Remote-management installation

The complete ordered procedure is documented in:

- `REMOTE_MANAGEMENT.md`
- `docs/INSTALLATION.md`

The supported roles are:

1. management-server PC with local Remote Administration;
2. additional protected PCs;
3. optional separate Admin PCs.

For the normal management-server installation:

```powershell
.\test-prerequisites.ps1 -Role ManagementServer
.\install-remote-server.ps1
```

`-DnsName` and `-Port` are optional. When omitted, the installer uses the
current Windows computer name and TCP 8443.

### Register another protected PC

Create a complete installer bundle on the management server:

```powershell
& "C:\Program Files\WindowsLoginGuardRemoteServer\new-protected-pc-installer.ps1" `
    -Label "Accounting-PC" `
    -ValidHours 24
```

Transfer the generated ZIP to the target PC, extract it, and run:

```powershell
.\install-protected-pc.ps1
```

The bundle contains the server URL, public certificate, display name, and
single-use protected-device registration code.

The device becomes visible in Remote Administration after installation,
successful registration, and the Remote Agent's first synchronization. Remote
Administration does not require manual entry of a device ID or device token.

A separate Admin PC uses `install-remote-admin.ps1`, a public server
certificate copy, and a single-use Admin-workstation registration code created
on the management server.

## Compatibility

- Existing v1.7.2 local enrollment is preserved during supported upgrade.
- Remote management remains optional.
- Protected PCs continue local enforcement when the server is offline.
- v1.10.4 uses the same remote-management API generation as v1.10.2 and
  v1.10.3.
- Upgrade all remote roles together when moving from older v1.8 or v1.9 builds.

## Security notes

- Windows Login Guard remains a post-login control.
- It is not a Credential Provider or pre-boot authentication system.
- The desktop may briefly become visible before verification.
- `isolated_desktop` provides the strongest available post-login presentation.
- Local administrators and unrestricted offline access remain inside the machine trust boundary.
- BitLocker is recommended where offline modification is a concern.
- Never distribute the management-server private key or management database.
- Only the public server certificate should be transferred to protected PCs or Admin workstations.

## Known limitations

- Remote approval and remote session actions require a reachable management server and protected-PC command channel.
- Local OTP verification continues during remote-management outages.
- Browsers may warn about the private server certificate; desktop clients use certificate pinning.
- Remote Administration and notifier per-user logs do not yet have complete automatic retention management.
- The central database does not yet automatically purge historical completed approvals, session actions, or audit records.

