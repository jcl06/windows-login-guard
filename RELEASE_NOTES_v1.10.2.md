# Windows Login Guard v1.10.2

v1.10.2 adds exponential management-server retry backoff to the protected-PC
Remote Agent.

## Retry behavior

With the default 10-second synchronization interval, consecutive failures use:

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

The maximum retry delay is 15 minutes.

After the first successful synchronization, the failure counter is cleared and
the Remote Agent immediately returns to its configured normal interval,
normally 10 seconds.

## Operational behavior

- Local Windows Login Guard protection is independent of this retry schedule.
- OTP verification and local enforcement continue while the server is down.
- Service stop remains responsive because backoff waits are interruptible.
- Each retry sends a fresh current snapshot; failed status snapshots are not
  accumulated into an offline queue.
- The longer retry interval reduces repeated network traffic and failure-log
  entries during an extended management-server outage.

## Public-package documentation revision

The public v1.10.2 package was reviewed and reissued with:

- deployment-neutral hostname examples;
- corrected Remote Administration authentication and notification behavior;
- a rewritten v1.10.2 remote-management architecture document;
- `SECURITY.md`;
- `.gitignore` rules for runtime secrets and generated artifacts;
- `check-release-safety.py` for pre-publication scanning.

No runtime protocol or installed-service behavior changed in this documentation
revision.

## Complete documentation revision

The public v1.10.2 package was revised again to provide a complete user guide.

Added:

- a product overview explaining what Windows Login Guard is and is not;
- a deployment matrix covering local-only and remote-managed installations;
- complete one-PC local-only installation and initial-enrollment instructions;
- a local Administration-console reference covering every tab;
- configuration, recovery, maintenance, offline recovery, troubleshooting,
  upgrade, and uninstall guides;
- clear separation between local Administration and Remote Administration;
- documentation for advanced PowerShell administration commands.

No runtime service, protocol, or security behavior changed in this
documentation revision.

## Windows prerequisite documentation revision

The public v1.10.2 documentation was revised to add:

- exact Windows, elevation, PowerShell, Python, pip, tkinter, time-sync,
  authenticator, disk-space, and package-network requirements;
- machine-wide Python installation instructions;
- execution-policy and downloaded-file preparation;
- protected-PC, management-server, remote-protected-PC, and separate Admin-PC
  prerequisite sections;
- a description of every system change made by each installer;
- `test-prerequisites.ps1`, a read-only PASS/WARN/FAIL preflight checker.

No installed-service or remote-management protocol behavior changed.

## Local-first product documentation revision

The public v1.10.2 documentation was revised to:

- present the product and local-only use case before remote management;
- explain what Windows Login Guard is for and how post-login enforcement works;
- provide exact first-enrollment button labels and OTP activation steps;
- show how to test normal verification;
- document how to open Windows Login Guard Administration;
- document all six local Administration areas;
- explain how to enroll another account and reset/re-enroll an account;
- place maintenance and recovery procedures in the main user journey;
- embed architecture, enrollment, verification, Administration, and recovery
  diagrams directly in the README and detailed guides.

No runtime service or protocol behavior changed.


## Tkinter and Administration-image clarification

The public documentation was corrected to explain that `tkinter` is Python's
built-in Tcl/Tk GUI interface rather than a normally separate package. It now
includes verification and repair instructions.

The stylized Administration illustration was removed. Its replacement is a
source-derived layout reference based on the current `admin.pyw` geometry,
tabs, System Overview page, Notifications frame, summary cards, Live Sessions
table, Recent Activity table, and status bar. It is explicitly labeled as not
being an actual Windows runtime screenshot.

No runtime component changed.

## Python Launcher command correction

The public documentation was corrected after testing a valid machine-wide
Python installation without `py.exe`.

Changes:

- `py.exe` is now documented as optional.
- Tkinter checks use `python -m tkinter`.
- The guide explains that `python -3` is invalid because `-3` belongs to the
  optional Python Launcher, not `python.exe`.
- Explicit `C:\Program Files\Python313\python.exe` examples are provided.
- The prerequisite checker continues to use `py.exe` when present and otherwise
  falls back to `python.exe`.

No Windows Login Guard runtime protocol or service behavior changed.

## Prerequisite checker NativeCommandError fix

The public prerequisite checker was corrected for Windows PowerShell 5.1.

Previously, `$ErrorActionPreference = "Stop"` caused a Python traceback written
to native stderr to terminate the script as `NativeCommandError`. This prevented
the checker from reporting missing modules as normal PASS/WARN/FAIL results.

`Invoke-PythonProbe` and the optional Python Launcher lookup now temporarily
capture native stderr under nonterminating error handling, preserve the native
exit code, normalize PowerShell `ErrorRecord` values to readable text, and then
restore the caller's error-action preference.

No installed Windows Login Guard runtime component changed.

## Prerequisite checker scope and pip-resolution fix

The R8 prerequisite checker corrects two defects found during Windows testing.

- `C:\Program Files\Python314\python.exe` was incorrectly reported as
  user-specific because the result of `.StartsWith()` was cast to the strings
  `"True"` or `"False"`, and both are truthy in a PowerShell condition.
- The checker used Python `urllib.request` to test the package index even though
  installation uses pip. This could produce a certificate result different from
  the actual installer.

R8 normalizes paths and evaluates real booleans. It also runs a no-install pip
dry-run against the role's actual requirements file. A failed pip resolution is
now an explicit installation-blocking `FAIL`.

The Windows Time warning now states that a stopped service alone does not prove
the clock is inaccurate and directs the user to verify automatic time and time
zone.

No installed Windows Login Guard runtime component changed.

## Prerequisite workflow clarification

The public documentation now states explicitly that users should run only:

```powershell
.\test-prerequisites.ps1 -Role ProtectedPc
```

The checker performs the pip dry-run internally. The underlying
`python -m pip install --dry-run ...` command is documented only for
troubleshooting a failed package-resolution check and is not a separate normal
installation step.

No runtime component changed.

## Actual Windows screenshot documentation revision

The public documentation now uses real Windows Login Guard v1.10.2 screens
extracted from a supplied Windows screen recording.

Added actual, sanitized views of:

- account-specific TOTP enrollment;
- one-time recovery-code display;
- isolated-desktop OTP verification;
- local Administration Dashboard;
- Enrolled Accounts;
- Configuration;
- Recovery & Maintenance;
- Audit.

QR payloads, TOTP secrets, recovery codes, account names, computer names,
timestamps, and audit row contents were redacted. The previous illustrative
enrollment, verification, Administration, and recovery diagrams were removed.

No installed runtime behavior changed.

## v1.7.2 documentation audit and local-guide restoration

The v1.10.2 public documentation was compared section by section with the
v1.7.2 README and checked against the current v1.10.2 source.

Restored or expanded the local security model, installer behavior, recovery
code semantics, hidden F8 details, maintenance-key rotation, Safe Mode/WinRE
procedures, Dashboard behavior, schema-driven configuration lifecycle, UTC
audit storage/local display, diagnostics, upgrade preservation, file
locations, limitations, and isolated-desktop guidance.

The active guide now uses unredacted screenshots from the disposable lab VM
recording, as requested.

No runtime behavior changed.
