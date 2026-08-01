from __future__ import annotations

import json
import os
import socket
import struct
from pathlib import Path
from typing import Any

import win32crypt

APP_NAME = "WindowsLoginGuard"
PROGRAM_DATA = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / APP_NAME
SECURE_DIR = PROGRAM_DATA / "secure"
RUNTIME_DIR = PROGRAM_DATA / "runtime"
USERS_DIR = SECURE_DIR / "users"
CONFIG_PATH = SECURE_DIR / "config.json"
LOG_PATH = SECURE_DIR / "guard.log"
PORT_FILE = RUNTIME_DIR / "service_port"
APPROVALS_PATH = SECURE_DIR / "approval_grants.json"
BOOTSTRAP_SECRET_PATH = SECURE_DIR / "bootstrap_secret.dpapi"
MANAGEMENT_TOKEN_PATH = SECURE_DIR / "management.token"
AUDIT_PATH = SECURE_DIR / "admin_audit.jsonl"
MAINTENANCE_STATE_PATH = SECURE_DIR / "maintenance.json"
MAINTENANCE_KEY_HASH_PATH = SECURE_DIR / "maintenance-key.sha256"
LEGACY_SECRET_PATH = SECURE_DIR / "secret.dpapi"
LEGACY_RECOVERY_PATH = SECURE_DIR / "recovery_codes.json"
HOST = "127.0.0.1"

VALID_PROTECTION_SCOPES = {"installer_user", "administrators", "all_users"}
VALID_OUT_OF_SCOPE_POLICIES = {"allow", "require_admin_approval", "deny"}
VALID_NO_APPROVER_POLICIES = {"allow", "deny"}
VALID_ADMIN_APPROVAL_MODES = {"inline", "admin_session", "either"}
VALID_INTERACTION_MODES = {"topmost", "isolated_desktop"}
VALID_ISOLATED_DESKTOP_FALLBACKS = {"topmost", "lock"}
VALID_FAILURE_ACTIONS = {"allow", "lock", "logoff"}
VALID_LOCK_FAILURE_ACTIONS = {"allow", "logoff"}
APPROVAL_DURATION_ORDER = [
    "once",
    "until_lock",
    "session",
    "15_minutes",
    "30_minutes",
    "1_hour",
    "2_hours",
    "4_hours",
    "8_hours",
    "24_hours",
]
VALID_APPROVAL_DURATIONS = set(APPROVAL_DURATION_ORDER)



ADMIN_CONFIG_SCHEMA: dict[str, dict[str, Any]] = {
    "verify_on_logon": {
        "type": "boolean",
        "section": "Verification",
        "label": "Verify on sign-in",
        "description": "Require Windows Login Guard verification after a protected account signs in.",
    },
    "verify_on_unlock": {
        "type": "boolean",
        "section": "Verification",
        "label": "Verify on workstation unlock",
        "description": "Require verification whenever a protected workstation session is unlocked.",
    },
    "enforce_on_service_start": {
        "type": "boolean",
        "section": "Verification",
        "label": "Enforce when the service starts",
        "description": "Create verification gates for protected active sessions when the Windows Login Guard service starts or restarts.",
    },
    "timeout_seconds": {
        "type": "integer",
        "section": "Verification",
        "label": "OTP timeout (seconds)",
        "description": "Maximum time allowed to complete normal OTP verification before the configured failure action is applied.",
        "minimum": 15,
        "maximum": 600,
    },
    "max_otp_attempts": {
        "type": "integer",
        "section": "Verification",
        "label": "Maximum OTP attempts",
        "description": "Maximum number of invalid OTP or user recovery-code submissions allowed for one verification gate.",
        "minimum": 1,
        "maximum": 20,
    },
    "interaction_mode": {
        "type": "enum",
        "section": "Verification",
        "label": "Interaction mode",
        "description": "Controls whether verification is shown on a separate isolated desktop or as a topmost window on the normal desktop.",
        "choices": ["topmost", "isolated_desktop"],
    },
    "isolated_desktop_fallback": {
        "type": "enum",
        "section": "Verification",
        "label": "Isolated desktop fallback",
        "description": "Action used when the isolated verification desktop cannot be created or displayed.",
        "choices": ["topmost", "lock"],
    },
    "recovery_otp_failure_threshold": {
        "type": "integer",
        "section": "Recovery",
        "label": "Failed OTP attempts before F8 recovery",
        "description": "Number of failed OTP submissions required before the hidden F8 session-recovery path becomes available.",
        "minimum": 1,
        "maximum": 20,
    },
    "recovery_entry_timeout_seconds": {
        "type": "integer",
        "section": "Recovery",
        "label": "Recovery entry timeout (seconds)",
        "description": "Maximum inactive time allowed while entering the machine recovery key and recovery reason.",
        "minimum": 60,
        "maximum": 3600,
    },
    "allow_bootstrap_enrollment": {
        "type": "boolean",
        "section": "Enrollment",
        "label": "Allow bootstrap enrollment",
        "description": "Allow the first eligible administrator to complete initial enrollment when no enrolled approver exists.",
    },
    "enrollment_session_timeout_seconds": {
        "type": "integer",
        "section": "Enrollment",
        "label": "Enrollment session timeout (seconds)",
        "description": "Maximum time an enrollment workflow may remain active before it is cancelled.",
        "minimum": 60,
        "maximum": 3600,
    },
    "out_of_scope_policy": {
        "type": "enum",
        "section": "Policy",
        "label": "Out-of-scope account policy",
        "description": "Action applied to an account that is not included in the configured protection scope.",
        "choices": ["allow", "require_admin_approval", "deny"],
    },
    "no_approver_policy": {
        "type": "enum",
        "section": "Policy",
        "label": "No enrolled approver policy",
        "description": "Action used when administrator approval is required but no enrolled approver is available.",
        "choices": ["allow", "deny"],
    },
    "admin_approval_mode": {
        "type": "enum",
        "section": "Policy",
        "label": "Administrator approval mode",
        "description": "Where administrator approval may be completed: inline, from another administrator session, or either.",
        "choices": ["inline", "admin_session", "either"],
    },
    "approval_timeout_seconds": {
        "type": "integer",
        "section": "Policy",
        "label": "Approval timeout (seconds)",
        "description": "Maximum time allowed for an administrator approval request before the configured timeout action is applied.",
        "minimum": 15,
        "maximum": 3600,
    },
    "default_approval_duration": {
        "type": "enum",
        "section": "Policy",
        "label": "Default approval duration",
        "description": "Default lifetime of an administrator approval grant after it is accepted.",
        "choices": [
            "once",
            "until_lock",
            "session",
            "15_minutes",
            "30_minutes",
            "1_hour",
            "2_hours",
            "4_hours",
            "8_hours",
            "24_hours",
        ],
    },
    "lock_action_timeout_seconds": {
        "type": "integer",
        "section": "Failure handling",
        "label": "Lock action timeout (seconds)",
        "description": "Time allowed for the workstation lock action to complete before the lock-failure action is used.",
        "minimum": 3,
        "maximum": 60,
    },
    "lock_failure_action": {
        "type": "enum",
        "section": "Failure handling",
        "label": "Action when workstation lock fails",
        "description": "Action taken if Windows Login Guard cannot lock the workstation when required.",
        "choices": ["allow", "logoff"],
    },
    "failure_actions.logon": {
        "type": "enum",
        "section": "Failure handling",
        "label": "Sign-in verification failure action",
        "description": "Action taken when verification after sign-in expires or reaches the attempt limit.",
        "choices": ["allow", "lock", "logoff"],
    },
    "failure_actions.unlock": {
        "type": "enum",
        "section": "Failure handling",
        "label": "Unlock verification failure action",
        "description": "Action taken when verification after workstation unlock fails.",
        "choices": ["allow", "lock", "logoff"],
    },
    "failure_actions.service_start": {
        "type": "enum",
        "section": "Failure handling",
        "label": "Service-start verification failure action",
        "description": "Action taken when a service-start verification gate fails.",
        "choices": ["allow", "lock", "logoff"],
    },
    "failure_actions.admin_approval_timeout": {
        "type": "enum",
        "section": "Failure handling",
        "label": "Administrator approval timeout action",
        "description": "Action taken when an administrator approval request reaches its timeout.",
        "choices": ["allow", "lock", "logoff"],
    },
    "failure_actions.out_of_scope_deny": {
        "type": "enum",
        "section": "Failure handling",
        "label": "Out-of-scope deny action",
        "description": "Action applied when the out-of-scope policy is set to deny.",
        "choices": ["allow", "lock", "logoff"],
    },
    "ui_compact_verify_window": {
        "type": "boolean",
        "section": "User interface",
        "label": "Use compact OTP window",
        "description": "Use the smaller OTP-only verification layout for enrolled users.",
    },
    "ui_auto_submit_otp": {
        "type": "boolean",
        "section": "User interface",
        "label": "Automatically submit complete OTP",
        "description": "Automatically submit a complete six-digit OTP without requiring the Verify button.",
    },
    "ui_auto_submit_delay_ms": {
        "type": "integer",
        "section": "User interface",
        "label": "Automatic submit delay (milliseconds)",
        "description": "Delay between entering the final OTP digit and automatic submission.",
        "minimum": 100,
        "maximum": 2000,
    },
    "ui_always_on_top": {
        "type": "boolean",
        "section": "User interface",
        "label": "Keep verification window on top",
        "description": "Keep the verification window above other application windows.",
    },
    "ui_force_foreground": {
        "type": "boolean",
        "section": "User interface",
        "label": "Force verification window to foreground",
        "description": "Repeatedly request foreground focus while the verification window is opening.",
    },
    "ui_focus_retry_ms": {
        "type": "integer",
        "section": "User interface",
        "label": "Focus retry interval (milliseconds)",
        "description": "Delay between attempts to focus the OTP input field.",
        "minimum": 50,
        "maximum": 5000,
    },
    "ui_focus_retry_count": {
        "type": "integer",
        "section": "User interface",
        "label": "Focus retry count",
        "description": "Number of focus retries performed after the verification window appears.",
        "minimum": 0,
        "maximum": 10,
    },
}


def admin_config_value(config: dict[str, Any], key: str) -> Any:
    if "." not in key:
        return config[key]
    parent, child = key.split(".", 1)
    return config[parent][child]


def set_admin_config_value(
    config: dict[str, Any],
    key: str,
    value: Any,
) -> None:
    if "." not in key:
        config[key] = value
        return
    parent, child = key.split(".", 1)
    nested = dict(config[parent])
    nested[child] = value
    config[parent] = nested


def validate_admin_config_updates(
    updates: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(updates, dict):
        raise ValueError("Configuration updates must be an object")

    unknown = sorted(set(updates) - set(ADMIN_CONFIG_SCHEMA))
    if unknown:
        raise ValueError(
            "Unsupported configuration setting(s): " + ", ".join(unknown)
        )

    normalized: dict[str, Any] = {}
    for key, value in updates.items():
        rule = ADMIN_CONFIG_SCHEMA[key]
        value_type = rule["type"]
        if value_type == "boolean":
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be true or false")
            normalized[key] = value
        elif value_type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{key} must be an integer")
            minimum = int(rule["minimum"])
            maximum = int(rule["maximum"])
            if not minimum <= value <= maximum:
                raise ValueError(
                    f"{key} must be between {minimum} and {maximum}"
                )
            normalized[key] = value
        elif value_type == "enum":
            if not isinstance(value, str):
                raise ValueError(f"{key} must be a selection")
            choices = list(rule["choices"])
            if value not in choices:
                raise ValueError(
                    f"{key} must be one of: {', '.join(choices)}"
                )
            normalized[key] = value
        else:
            raise ValueError(f"Unsupported schema type for {key}")

    candidate = json.loads(json.dumps(current))
    for key, value in normalized.items():
        set_admin_config_value(candidate, key, value)

    max_attempts = int(candidate["max_otp_attempts"])
    threshold = int(candidate["recovery_otp_failure_threshold"])
    if threshold > max_attempts:
        raise ValueError(
            "Failed OTP attempts before F8 recovery cannot exceed "
            "maximum OTP attempts"
        )

    default_duration = str(candidate["default_approval_duration"])
    if default_duration not in candidate["allowed_approval_durations"]:
        raise ValueError(
            "Default approval duration is not enabled by the active policy"
        )

    return normalized


def ensure_program_data() -> None:
    PROGRAM_DATA.mkdir(parents=True, exist_ok=True)
    SECURE_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    USERS_DIR.mkdir(parents=True, exist_ok=True)


def sid_directory(user_sid: str) -> Path:
    value = str(user_sid).strip()
    if not value.startswith("S-") or any(ch not in "S-0123456789" for ch in value):
        raise ValueError("Invalid Windows SID")
    return USERS_DIR / value


def user_secret_path(user_sid: str) -> Path:
    return sid_directory(user_sid) / "secret.dpapi"


def user_recovery_path(user_sid: str) -> Path:
    return sid_directory(user_sid) / "recovery_codes.json"


def user_profile_path(user_sid: str) -> Path:
    return sid_directory(user_sid) / "profile.json"


def user_enrollment_path(user_sid: str) -> Path:
    return sid_directory(user_sid) / "enrollment.json"


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _require_bool(config: dict[str, Any], key: str) -> bool:
    value = config[key]
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false")
    return value


def _require_int(
    config: dict[str, Any], key: str, minimum: int, maximum: int
) -> int:
    value = config[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}")
    return value


def _require_string_list(config: dict[str, Any], key: str) -> list[str]:
    value = config.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a JSON array of strings")
    normalized = [item.strip() for item in value if item.strip()]
    config[key] = normalized
    return normalized


def load_config() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "credential_mode": "per_user",
        "protection_scope": "installer_user",
        "installer_user_sid": "",
        "installer_user_name": "",
        "excluded_user_sids": [],
        "initial_enrollment_sids": [],
        "verify_on_logon": True,
        "verify_on_unlock": True,
        "enforce_on_service_start": True,
        "timeout_seconds": 45,
        "poll_interval_seconds": 1,
        "max_otp_attempts": 5,
        "recovery_otp_failure_threshold": 3,
        "recovery_entry_timeout_seconds": 600,
        "ui_ready_timeout_seconds": 10,
        "ui_launch_retries": 1,
        "enrollment_session_timeout_seconds": 600,
        "allow_bootstrap_enrollment": True,
        "out_of_scope_policy": "allow",
        "no_approver_policy": "allow",
        "admin_approval_mode": "inline",
        "interaction_mode": "topmost",
        "isolated_desktop_start_timeout_seconds": 12,
        "isolated_desktop_fallback": "topmost",
        "approval_timeout_seconds": 120,
        "failure_actions": {
            "logon": "logoff",
            "unlock": "lock",
            "service_start": "lock",
            "admin_approval_timeout": "lock",
            "out_of_scope_deny": "logoff",
        },
        "lock_action_timeout_seconds": 8,
        "lock_failure_action": "logoff",
        "allowed_approval_durations": list(APPROVAL_DURATION_ORDER),
        "default_approval_duration": "session",
        "ui_compact_verify_window": True,
        "ui_auto_submit_otp": True,
        "ui_auto_submit_delay_ms": 200,
        "ui_always_on_top": True,
        "ui_force_foreground": True,
        "ui_focus_retry_ms": 250,
        "ui_focus_retry_count": 3,
        "issuer": "Windows Login Guard",
    }

    if CONFIG_PATH.exists():
        loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
        if not isinstance(loaded, dict):
            raise ValueError("config.json must contain a JSON object")
        defaults.update(loaded)

    if str(defaults.get("credential_mode", "")).strip().lower() != "per_user":
        raise ValueError("credential_mode must be per_user")
    defaults["credential_mode"] = "per_user"

    scope = str(defaults["protection_scope"]).strip().lower()
    if scope not in VALID_PROTECTION_SCOPES:
        allowed = ", ".join(sorted(VALID_PROTECTION_SCOPES))
        raise ValueError(f"protection_scope must be one of: {allowed}")
    defaults["protection_scope"] = scope

    installer_sid = str(defaults.get("installer_user_sid", "")).strip()
    defaults["installer_user_sid"] = installer_sid
    defaults["installer_user_name"] = str(
        defaults.get("installer_user_name", "")
    ).strip()
    if scope == "installer_user" and not installer_sid:
        raise ValueError(
            "installer_user_sid is required when protection_scope is installer_user"
        )

    _require_string_list(defaults, "excluded_user_sids")
    _require_string_list(defaults, "initial_enrollment_sids")

    out_policy = str(defaults["out_of_scope_policy"]).strip().lower()
    if out_policy not in VALID_OUT_OF_SCOPE_POLICIES:
        allowed = ", ".join(sorted(VALID_OUT_OF_SCOPE_POLICIES))
        raise ValueError(f"out_of_scope_policy must be one of: {allowed}")
    defaults["out_of_scope_policy"] = out_policy

    no_approver = str(defaults["no_approver_policy"]).strip().lower()
    if no_approver not in VALID_NO_APPROVER_POLICIES:
        allowed = ", ".join(sorted(VALID_NO_APPROVER_POLICIES))
        raise ValueError(f"no_approver_policy must be one of: {allowed}")
    defaults["no_approver_policy"] = no_approver

    approval_mode = str(
        defaults.get("admin_approval_mode", "inline")
    ).strip().lower()
    if approval_mode not in VALID_ADMIN_APPROVAL_MODES:
        allowed = ", ".join(sorted(VALID_ADMIN_APPROVAL_MODES))
        raise ValueError(
            f"admin_approval_mode must be one of: {allowed}"
        )
    defaults["admin_approval_mode"] = approval_mode

    interaction_mode = str(
        defaults.get("interaction_mode", "topmost")
    ).strip().lower()
    if interaction_mode not in VALID_INTERACTION_MODES:
        allowed = ", ".join(sorted(VALID_INTERACTION_MODES))
        raise ValueError(f"interaction_mode must be one of: {allowed}")
    defaults["interaction_mode"] = interaction_mode

    isolated_fallback = str(
        defaults.get("isolated_desktop_fallback", "topmost")
    ).strip().lower()
    if isolated_fallback not in VALID_ISOLATED_DESKTOP_FALLBACKS:
        allowed = ", ".join(sorted(VALID_ISOLATED_DESKTOP_FALLBACKS))
        raise ValueError(
            f"isolated_desktop_fallback must be one of: {allowed}"
        )
    defaults["isolated_desktop_fallback"] = isolated_fallback

    # Migrate the v0.8 preview's single approval timeout setting into the
    # event-specific policy map. Unknown keys are rejected to catch typos.
    failure_defaults = {
        "logon": "logoff",
        "unlock": "lock",
        "service_start": "lock",
        "admin_approval_timeout": "lock",
        "out_of_scope_deny": "logoff",
    }
    loaded_failure_actions = defaults.get("failure_actions", {})
    if not isinstance(loaded_failure_actions, dict):
        raise ValueError("failure_actions must be a JSON object")
    if (
        "admin_approval_timeout" not in loaded_failure_actions
        and str(defaults.get("approval_timeout_action", "")).strip().lower()
        in VALID_FAILURE_ACTIONS
    ):
        failure_defaults["admin_approval_timeout"] = str(
            defaults.get("approval_timeout_action")
        ).strip().lower()
    unknown_failure_keys = sorted(
        set(loaded_failure_actions) - set(failure_defaults)
    )
    if unknown_failure_keys:
        raise ValueError(
            "Unsupported failure_actions key(s): "
            + ", ".join(unknown_failure_keys)
        )
    failure_defaults.update(loaded_failure_actions)
    for event_name, action in failure_defaults.items():
        normalized = str(action).strip().lower()
        if normalized not in VALID_FAILURE_ACTIONS:
            allowed = ", ".join(sorted(VALID_FAILURE_ACTIONS))
            raise ValueError(
                f"failure_actions.{event_name} must be one of: {allowed}"
            )
        failure_defaults[event_name] = normalized
    defaults["failure_actions"] = failure_defaults
    defaults.pop("approval_timeout_action", None)

    lock_failure_action = str(
        defaults.get("lock_failure_action", "logoff")
    ).strip().lower()
    if lock_failure_action not in VALID_LOCK_FAILURE_ACTIONS:
        allowed = ", ".join(sorted(VALID_LOCK_FAILURE_ACTIONS))
        raise ValueError(f"lock_failure_action must be one of: {allowed}")
    defaults["lock_failure_action"] = lock_failure_action

    durations = _require_string_list(defaults, "allowed_approval_durations")
    invalid_durations = sorted(set(durations) - VALID_APPROVAL_DURATIONS)
    if invalid_durations:
        raise ValueError(
            "Unsupported approval duration(s): " + ", ".join(invalid_durations)
        )
    if not durations:
        raise ValueError("allowed_approval_durations cannot be empty")

    default_duration = str(defaults["default_approval_duration"]).strip()
    if default_duration not in durations:
        raise ValueError(
            "default_approval_duration must be present in allowed_approval_durations"
        )
    defaults["default_approval_duration"] = default_duration

    _require_bool(defaults, "verify_on_logon")
    _require_bool(defaults, "verify_on_unlock")
    _require_bool(defaults, "enforce_on_service_start")
    _require_bool(defaults, "allow_bootstrap_enrollment")
    _require_int(defaults, "timeout_seconds", 15, 600)
    _require_int(defaults, "poll_interval_seconds", 1, 10)
    max_attempts = _require_int(defaults, "max_otp_attempts", 1, 20)
    recovery_threshold = _require_int(
        defaults,
        "recovery_otp_failure_threshold",
        1,
        20,
    )
    if recovery_threshold > max_attempts:
        raise ValueError(
            "recovery_otp_failure_threshold cannot exceed "
            "max_otp_attempts"
        )
    _require_int(
        defaults,
        "recovery_entry_timeout_seconds",
        60,
        3600,
    )
    _require_int(defaults, "ui_ready_timeout_seconds", 3, 60)
    _require_int(defaults, "ui_launch_retries", 0, 5)
    _require_int(
        defaults,
        "isolated_desktop_start_timeout_seconds",
        5,
        60,
    )
    _require_int(defaults, "enrollment_session_timeout_seconds", 60, 3600)
    _require_int(defaults, "approval_timeout_seconds", 15, 3600)
    _require_int(defaults, "lock_action_timeout_seconds", 3, 60)
    _require_bool(defaults, "ui_compact_verify_window")
    _require_bool(defaults, "ui_auto_submit_otp")
    _require_int(defaults, "ui_auto_submit_delay_ms", 100, 2000)
    _require_bool(defaults, "ui_always_on_top")
    _require_bool(defaults, "ui_force_foreground")
    _require_int(defaults, "ui_focus_retry_ms", 50, 5000)
    _require_int(defaults, "ui_focus_retry_count", 0, 10)

    issuer = str(defaults.get("issuer", "")).strip()
    if not issuer:
        raise ValueError("issuer cannot be empty")
    defaults["issuer"] = issuer
    return defaults


def protect_machine_secret(secret: str) -> bytes:
    # CRYPTPROTECT_LOCAL_MACHINE = 0x4. File ACLs restrict encrypted blobs to
    # Administrators and SYSTEM. Local administrators remain in the trust boundary.
    return win32crypt.CryptProtectData(
        secret.encode("utf-8"),
        APP_NAME,
        None,
        None,
        None,
        0x4,
    )


def unprotect_machine_secret(blob: bytes) -> str:
    _description, plaintext = win32crypt.CryptUnprotectData(
        blob, None, None, None, 0
    )
    return plaintext.decode("utf-8")


def recv_json(sock: socket.socket) -> dict[str, Any]:
    header = _recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    if length > 128 * 1024:
        raise ValueError("Message too large")
    payload = _recv_exact(sock, length)
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Message must be a JSON object")
    return value


def send_json(sock: socket.socket, data: dict[str, Any]) -> None:
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
