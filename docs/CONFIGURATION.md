# Configuration Reference

The active configuration is:

```text
C:\ProgramData\WindowsLoginGuard\secure\config.json
```

The release includes `config.example.json`.

The graphical editor is schema-driven, validates values, previews changes,
requires an enrolled administrator credential, writes atomically, audits old
and new values, restarts the service, and reconnects.

## Verification

![Verification settings](images/lab-configuration-verification.png)

Sign-in, unlock, service-start enforcement, OTP timeout, maximum attempts,
interaction mode, and isolated-desktop fallback.

## Recovery

Failed attempts before F8 and recovery-entry timeout. The threshold cannot
exceed the maximum OTP attempts.

## Enrollment

![Enrollment settings](images/lab-configuration-enrollment.png)

Bootstrap enrollment and enrollment-session timeout.

## Policy

![Policy settings](images/lab-configuration-policy.png)

Out-of-scope behavior, no-approver behavior, approval mode, timeout, and default
duration.

## Failure handling

![Failure handling](images/lab-configuration-failure.png)

Separate sign-in, unlock, service-start, approval-timeout, out-of-scope, and
lock-failure actions.

## User interface

![User-interface settings](images/lab-configuration-user-interface.png)

Compact layout, automatic submission, delay, topmost behavior, foreground
behavior, and focus retry settings.

## Important defaults

```json
{
  "max_otp_attempts": 5,
  "recovery_otp_failure_threshold": 3,
  "recovery_entry_timeout_seconds": 600,
  "isolated_desktop_start_timeout_seconds": 12,
  "isolated_desktop_fallback": "topmost"
}
```
