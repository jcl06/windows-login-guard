# File Locations

Local program files:

```text
C:\Program Files\WindowsLoginGuard
```

Protected state:

```text
C:\ProgramData\WindowsLoginGuard\secure
```

Runtime IPC state:

```text
C:\ProgramData\WindowsLoginGuard\runtime
```

Important files:

```text
config.json
management.token
maintenance-key.sha256
maintenance.json
admin_audit.jsonl
guard.log
users\
```

The plaintext maintenance recovery key is not stored.

Remote-management server state is under
`C:\ProgramData\WindowsLoginGuardRemoteServer\secure`. Do not copy it into a
public release.
