# Upgrade and Uninstall

Upgrade:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\upgrade-to-v1.10.2.ps1
```

The upgrade stops the service and UI processes, creates a timestamped backup,
replaces modules, preserves enrollment, policy, recovery state, tokens,
maintenance state, and remote registration, validates imports and hidden UI
startup, then restarts and verifies the service.

Verify:

```powershell
Get-Content "C:\Program Files\WindowsLoginGuard\VERSION"
Get-Service WindowsLoginGuard
```

Uninstall all state:

```powershell
& "C:\Program Files\WindowsLoginGuard\uninstall.ps1"
```

Retain enrollment and configuration:

```powershell
& "C:\Program Files\WindowsLoginGuard\uninstall.ps1" -KeepEnrollment
```
