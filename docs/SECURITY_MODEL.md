# Local Security Model

## Trust boundary

Windows Login Guard is a machine-local post-login control.

The local trust boundary includes Windows, LocalSystem, local administrators,
Windows DPAPI, NTFS ACL enforcement, the installed Python runtime, and the
Windows Login Guard service and UI modules.

A local administrator or a person with unrestricted offline write access to an
unencrypted system volume can modify local software and policy. BitLocker is
recommended where offline tampering matters.

## Protected storage

Protected data is stored under:

```text
C:\ProgramData\WindowsLoginGuard\secure
```

Important data includes `config.json`, `management.token`,
`maintenance-key.sha256`, `maintenance.json`, `admin_audit.jsonl`, `guard.log`,
and per-user profiles and DPAPI-protected secrets under `users\`.

## TOTP and recovery material

Each enrolled account receives its own DPAPI-protected TOTP secret.

User recovery codes are shown once, stored only as hashes, account-specific,
and consumed after successful use.

The machine maintenance recovery key is separate. Only its SHA-256 hash is
stored. It may be rotated by an enrolled administrator without the old key.

## Administration transport

The local Administration console uses a loopback IPC endpoint authenticated by
a machine-local random management token.

Sensitive operations additionally require an enrolled administrator OTP or
one-time administrator recovery code.

## Audit

Audit timestamps are stored in UTC. The Administration console converts them
to the PC's current time zone and labels them **Timestamp (Local)**.

OTP values, TOTP seeds, recovery codes, maintenance keys, remote tokens, and
command-signing secrets are not intentionally logged.

## Verification presentation

`topmost` uses the normal desktop. `isolated_desktop` creates a separate
desktop and uses the configured fallback if creation fails.

Windows Login Guard remains post-login enforcement and cannot provide the same
pre-desktop guarantee as a Credential Provider.
