# Windows Installation Prerequisites

This guide applies to Windows Login Guard v1.10.2.

Read this before running an installer. The required preparation depends on the
role being installed:

- standalone or remotely managed protected PC;
- management server and primary Admin PC;
- separate Remote Administration PC.

## Supported target

This release is intended for:

- Windows 10 or Windows 11;
- 64-bit Windows;
- an NTFS system volume with normal Windows ACL and DPAPI support;
- Windows PowerShell 5.1 or newer;
- an interactive Windows desktop session for enrollment and administration.

Windows Server and Windows on ARM64 are not validated by this release.

## Required Windows access

Installation must be performed from an account that:

- is a member of the local Administrators group;
- can approve a User Account Control prompt;
- can install and control Windows services;
- can write to `C:\Program Files` and `C:\ProgramData`;
- can install Python packages into the selected machine-wide Python
  installation.

Open PowerShell by selecting **Run as administrator**.

The protected-PC, remote-server, and Remote Admin installers all require
elevation.

## Required Python installation

Install **64-bit CPython 3.11 or newer for all users**.

The Python executable used by Windows Login Guard must not be installed under:

```text
%USERPROFILE%
%LOCALAPPDATA%
C:\Program Files\WindowsApps
```

The protected-PC service runs as `LocalSystem`. A Python installation available
only to the current user may work interactively but fail when Windows starts
the service.

A normal machine-wide location is:

```text
C:\Program Files\Python311
C:\Program Files\Python312
C:\Program Files\Python313
```

The exact folder depends on the installed Python version.

### Python installer options

During CPython installation, retain these components:

- `pip`;
- Tcl/Tk and IDLE;
- the Python launcher (`py.exe`), optional;
- the standard library.

Select:

```text
Install for all users
```

Adding the machine-wide Python installation to `PATH` is helpful but not mandatory. The optional Python Launcher (`py.exe`) may also locate Python, but Windows Login Guard does not require it. A specific executable can be supplied to a WLG installer:

```powershell
.\install-protected-pc.ps1 `
    -PythonExe "C:\Program Files\Python313\python.exe"
```

Do not use the Microsoft Store execution alias as the service runtime.

### Verify Python

Run:

```powershell
python -c "import sys, struct, tkinter, ssl, sqlite3; print(sys.executable); print(sys.version); print(struct.calcsize('P') * 8)"
```

The last output line must be:

```text
64
```

The displayed executable should be a machine-wide Python installation, normally
under `C:\Program Files`.


### `python` versus `py`

`python.exe` is the Python interpreter. `py.exe` is an optional Windows
launcher installed by some Python setups.

Windows Login Guard supports either:

```powershell
python -m tkinter
```

or an explicit executable:

```powershell
& "C:\Program Files\Python313\python.exe" -m tkinter
```

When `py` is not recognized, no repair is required as long as `python` points
to the intended 64-bit machine-wide installation.

Check it with:

```powershell
(Get-Command python).Source
```

Do not run:

```powershell
python -3 -m tkinter
```

The `-3` selector belongs to `py.exe`; `python.exe` reports it as an unknown
option.


## Python packages installed by WLG

The installers use `pip` to upgrade `pip` and install required packages into
the selected Python installation.

### Protected PC

```text
pywin32 >= 311
pyotp >= 2.9.0
qrcode[pil] >= 8.0
Pillow, installed through qrcode[pil]
```

### Management server

```text
pywin32 >= 311
pyotp >= 2.9.0
qrcode[pil] >= 8.0
Pillow
cryptography >= 44.0.0
```

### Separate Remote Administration PC

```text
pywin32 >= 311
```

The user interfaces use Python's built-in `tkinter` interface to Tcl/Tk.
This is normally included with the full Windows Python installation; it is not
normally installed as a separate pip package.

Verify it with:

```powershell
python -m tkinter
```

A small Tk test window should open. Alternatively:

```powershell
python -c "import tkinter; print(tkinter.TkVersion)"
```

When the import fails, modify or reinstall the machine-wide Python installation
and enable **Tcl/Tk and IDLE**. Do not install a package named `tkinter` from
pip.

## Internet or Python package repository access

The current installers run commands equivalent to:

```powershell
python -m pip install --upgrade pip
python -m pip install --upgrade -r requirements.txt
```

Therefore, during installation the PC must have outbound HTTPS access to its
configured Python package index. With normal pip configuration, that is the
public Python Package Index and its package-download service.

A corporate proxy or private package mirror may be used when pip is configured
for it.

An offline installation is not yet packaged with a wheel bundle. Preinstalling
all dependencies may not be sufficient because the current installer also
attempts to upgrade pip.


### Package resolution test

The preflight checker internally runs:

```text
python -m pip install --dry-run -r <role-requirements>
```

This is not a separate installation step. Running
`test-prerequisites.ps1` performs it automatically.

The internal dry run tests the actual pip configuration, proxy, certificate
handling, private mirror, and package compatibility without installing the
requirements.

Run the pip command manually only when troubleshooting a failed
**Python package resolution** result.

A failed pip resolution is reported as `FAIL` because the normal installer
also uses pip. Do not bypass TLS verification. Configure the approved
certificate authority or package mirror instead.


## TOTP authenticator

At least one protected administrator needs a TOTP-compatible authenticator.

The authenticator may be on:

- a phone;
- a tablet;
- another secured device;
- an approved password manager with TOTP support.

The protected PC displays a QR code during enrollment. The authenticator must
be able to scan or manually enter a standard TOTP enrollment secret.

Do not store the only authenticator and all recovery material solely on the
protected PC.

## Accurate date and time

TOTP verification depends on the clock.

Before enrollment:

1. Open Windows **Date & time** settings.
2. Enable automatic time.
3. Enable the correct time zone.
4. Select **Sync now** when available.
5. Confirm the authenticator device also has correct automatic time.

A materially incorrect PC or authenticator clock causes valid-looking
six-digit codes to be rejected.

## Disk space and system condition

Recommended free space on the Windows system drive:

- protected PC: at least 300 MB;
- management server with Admin app: at least 500 MB;
- separate Remote Admin PC: at least 200 MB.

These are operational allowances for Python dependencies, installed files,
logs, and upgrades rather than exact package-size limits.

Before installation:

- finish pending Windows restarts;
- close Python applications using the selected Python installation;
- stop other Python-based Windows services when they hold pywin32 DLLs open;
- confirm the Windows Event Log, Task Scheduler, and Windows Management
  Instrumentation services are operational;
- do not disable antivirus or endpoint protection.

Security software may inspect newly installed Python services. Review alerts
against the release checksum rather than disabling protection.

## Prepare the downloaded package

1. Verify the ZIP SHA-256 against the published release value.
2. Extract the ZIP completely to a local folder.
3. Do not run scripts from inside the ZIP preview.
4. Avoid running the installer directly from a network share.
5. Remove the internet download mark from the extracted files:

```powershell
Get-ChildItem -LiteralPath . -Recurse -File |
    Unblock-File
```

Only unblock a package after verifying its checksum and source.

## PowerShell execution policy

The scripts are not currently Authenticode-signed. A restrictive execution
policy may block them.

For the current elevated PowerShell process only:

```powershell
Set-ExecutionPolicy `
    -Scope Process `
    -ExecutionPolicy Bypass `
    -Force
```

This does not change the machine-wide execution policy.

Then run the prerequisite checker:

```powershell
.\test-prerequisites.ps1 -Role ProtectedPc
```

## Automated prerequisite checker

The release includes:

```text
test-prerequisites.ps1
```

Protected PC:

```powershell
.\test-prerequisites.ps1 `
    -Role ProtectedPc
```

Management server:

```powershell
.\test-prerequisites.ps1 `
    -Role ManagementServer `
    -DnsName "wlg-server.example.internal" `
    -Port 8443
```

Separate Remote Admin PC:

```powershell
.\test-prerequisites.ps1 `
    -Role RemoteAdmin
```

Use a specific Python executable:

```powershell
.\test-prerequisites.ps1 `
    -Role ProtectedPc `
    -PythonExe "C:\Program Files\Python313\python.exe"
```

Skip the default package-index connectivity test when pip uses a private mirror
or when testing an intentionally offline preparation:

```powershell
.\test-prerequisites.ps1 `
    -Role ProtectedPc `
    -SkipPackageIndexCheck
```

The checker does not install or modify Windows Login Guard. It reports PASS,
WARN, and FAIL results and exits with a nonzero status when a mandatory check
fails.


### Interpreting Python probe failures

The checker tests both built-in modules and packages that the installer may
need to download.

A missing optional dependency should appear as a `WARN`, and a missing
mandatory built-in component such as Tcl/Tk should appear as a `FAIL`.
Python tracebacks are captured as result details. They should not terminate the
PowerShell script with `NativeCommandError`.


## Protected-PC prerequisites

In addition to the common requirements:

- a TOTP authenticator is required for initial enrollment;
- the installer account should be the first account intended for enrollment;
- the account must be able to remain signed in while the enrollment window
  opens;
- recovery codes and the maintenance recovery key need an external storage
  location.

A local-only protected PC does not require:

- a management server;
- DNS preparation;
- an inbound firewall rule;
- another PC;
- a database server;
- a web server;
- a Microsoft cloud account.

## Management-server prerequisites

The management-server PC must first satisfy all protected-PC prerequisites.

Before running `install-remote-server.ps1`:

1. Windows Login Guard must already be installed on that PC.
2. The current Windows account must already be enrolled.
3. The current enrolled account must be recorded as a Windows administrator.
4. The local Windows Login Guard service must be running.
5. The server must have a stable hostname or resolvable FQDN.
6. Protected PCs must be able to resolve that name.
7. TCP port 8443, or the selected alternative, must not be used by another
   application.
8. Windows Firewall administration must be available.
9. The PC should use a stable IP address or DHCP reservation.
10. The network should be trusted and should not expose the service directly
    to the public internet.

The installer generates a private self-signed TLS certificate containing:

- the configured DNS name;
- the computer name;
- `localhost`;
- `127.0.0.1`;
- any explicitly supplied additional certificate names.

The private key remains on the management server. Protected PCs receive only
the public certificate for certificate pinning.

The default firewall rule allows the selected TCP port from `LocalSubnet` on
all Windows network profiles.

## Remote protected-PC prerequisites

A protected PC being connected to a management server additionally needs:

- the generated protected-PC installer bundle;
- the bundle's public server certificate;
- a valid short-lived registration code;
- outbound TCP connectivity to the server port;
- DNS resolution for the hostname in the server URL;
- correct system time.

No inbound firewall rule is required on the protected PC.

## Separate Remote Admin PC prerequisites

A separate Admin PC requires:

- Windows 10 or Windows 11 x64;
- local administrator rights for installation;
- machine-wide Python 3.11+ with its built-in Tcl/Tk GUI support;
- network and DNS connectivity to the management server;
- the public server certificate;
- a single-use Admin-workstation registration code;
- a Windows user profile in which the notifier and DPAPI-protected workstation
  token can be stored.

The separate Admin PC does not have to be a protected PC unless local WLG
protection is also desired on it.

## What the installers change

### Protected-PC installer

- installs dependencies into the selected Python installation;
- creates `C:\Program Files\WindowsLoginGuard`;
- creates restricted state under
  `C:\ProgramData\WindowsLoginGuard`;
- installs the `WindowsLoginGuard` service as an automatic Windows service;
- configures service recovery;
- creates the local Administration shortcut;
- generates a machine maintenance recovery key;
- opens initial enrollment.

### Management-server installer

- installs additional Python dependencies;
- creates the management-server and Remote Admin program directories;
- creates restricted server state and a SQLite database;
- generates or reuses the TLS certificate;
- installs the management-server service;
- creates the inbound firewall rule unless disabled;
- installs Remote Administration and the notifier;
- links the current enrolled administrator;
- registers the server PC's local Remote Agent.

### Remote Admin installer

- installs its Python dependency;
- copies the Remote Administration and notifier components;
- creates the common desktop shortcut;
- configures the current user's notifier startup entry.

## No reboot is normally required

A reboot is not normally required.

A reboot may be necessary when:

- Windows has a pending restart;
- pywin32 DLLs are locked by another Python service;
- Python was installed or repaired and the launcher/PATH is not yet visible;
- service installation succeeds but Windows cannot load the selected Python
  runtime.

The installer reports pywin32 runtime failure rather than silently completing
with a broken service.
