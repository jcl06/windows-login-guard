from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import string
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import pyotp
import servicemanager
import win32con
import win32event
import win32process
import win32profile
import win32service
import win32serviceutil
import win32security
import win32ts

from common import (
    APPROVALS_PATH,
    APPROVAL_DURATION_ORDER,
    BOOTSTRAP_SECRET_PATH,
    CONFIG_PATH,
    HOST,
    LOG_PATH,
    MANAGEMENT_TOKEN_PATH,
    ADMIN_CONFIG_SCHEMA,
    admin_config_value,
    set_admin_config_value,
    validate_admin_config_updates,
    MAINTENANCE_STATE_PATH,
    MAINTENANCE_KEY_HASH_PATH,
    AUDIT_PATH,
    PORT_FILE,
    SECURE_DIR,
    USERS_DIR,
    atomic_write_json,
    ensure_program_data,
    load_config,
    protect_machine_secret,
    recv_json,
    send_json,
    sid_directory,
    unprotect_machine_secret,
    user_profile_path,
    user_enrollment_path,
    user_recovery_path,
    user_secret_path,
)

WTS_SESSION_LOGON = getattr(win32ts, "WTS_SESSION_LOGON", 0x5)
WTS_SESSION_LOGOFF = getattr(win32ts, "WTS_SESSION_LOGOFF", 0x6)
WTS_SESSION_LOCK = getattr(win32ts, "WTS_SESSION_LOCK", 0x7)
WTS_SESSION_UNLOCK = getattr(win32ts, "WTS_SESSION_UNLOCK", 0x8)
WTS_SESSION_DESKTOP_READY = getattr(win32ts, "WTS_SESSION_DESKTOP_READY", 0xF)

DURATION_SECONDS = {
    "15_minutes": 15 * 60,
    "30_minutes": 30 * 60,
    "1_hour": 60 * 60,
    "2_hours": 2 * 60 * 60,
    "4_hours": 4 * 60 * 60,
    "8_hours": 8 * 60 * 60,
    "24_hours": 24 * 60 * 60,
}


@dataclass(frozen=True)
class SessionIdentity:
    session_id: int
    username: str
    user_sid: str
    is_administrator: bool


@dataclass
class SessionGate:
    session_id: int
    username: str
    user_sid: str
    kind: str  # verify, enroll, approval_wait, deny
    reason: str
    deadline: float | None = None
    timeout_seconds: int | None = None
    activation_deadline: float | None = None
    failed_attempts: int = 0
    recovery_failed_attempts: int = 0
    recovery_locked_until: float = 0.0
    recovery_active: bool = False
    recovery_deadline: float | None = None
    paused_deadline_remaining_seconds: int | None = None
    challenge_id: str = field(
        default_factory=lambda: secrets.token_urlsafe(18)
    )
    created_at: float = field(default_factory=time.time)
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class PendingClientAction:
    request_id: str
    action: str
    policy_key: str
    gate_kind: str
    reason: str
    deadline: float


@dataclass
class PendingEnrollment:
    user_sid: str
    username: str
    is_administrator: bool
    secret: str
    authorized_by: str
    created_monotonic: float
    failed_attempts: int = 0


@dataclass
class ApprovalGrant:
    target_user_sid: str
    target_username: str
    approved_by_sid: str
    approved_by_name: str
    grant_type: str
    session_id: int | None
    created_at_utc: str
    expires_at_utc: str | None


class LoginGuardService(win32serviceutil.ServiceFramework):
    _svc_name_ = "WindowsLoginGuard"
    _svc_display_name_ = "Windows Login Guard"
    _svc_description_ = (
        "Requires per-user TOTP verification or administrator approval after "
        "Windows sign-in and session unlock."
    )

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.started_at = time.time()
        self.stop_requested = threading.Event()
        self.server_ready = threading.Event()
        self.lock = threading.RLock()
        self.audit_lock = threading.Lock()

        self.gates: dict[int, SessionGate] = {}
        self.pending_enrollments: dict[str, PendingEnrollment] = {}
        self.session_grants: dict[int, ApprovalGrant] = {}
        self.timed_grants: dict[str, ApprovalGrant] = {}
        self.challenge_jobs: set[int] = set()
        self.ui_ready_events: dict[int, threading.Event] = {}
        self.ui_last_seen: dict[int, tuple[float, bool]] = {}
        self.ui_tokens: dict[int, str] = {}
        self.ui_launch_locks: dict[int, threading.Lock] = {}
        self.client_actions: dict[int, PendingClientAction] = {}
        self.recovery_session_bypasses: set[int] = set()
        self.session_failed_attempts: dict[int, int] = {}
        self.session_last_failure_utc: dict[int, str] = {}
        self.last_states: dict[int, int] = {}

        self.server_socket: socket.socket | None = None
        self.server_thread: threading.Thread | None = None
        self.worker_thread: threading.Thread | None = None
        self.startup_thread: threading.Thread | None = None
        self.config = load_config()

        ensure_program_data()
        self._load_timed_grants()

        self.logger = logging.getLogger("WindowsLoginGuard")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(message)s")
            )
            self.logger.addHandler(handler)

    def GetAcceptedControls(self) -> int:
        return super().GetAcceptedControls() | win32service.SERVICE_ACCEPT_SESSIONCHANGE

    def SvcOtherEx(self, control: int, event_type: int, data: Any) -> None:
        if control != win32service.SERVICE_CONTROL_SESSIONCHANGE:
            return

        try:
            session_id = int(data[0] if isinstance(data, (tuple, list)) else data)
        except (TypeError, ValueError, IndexError):
            self.logger.warning(
                "Malformed session event: type=%s data=%r", event_type, data
            )
            return

        event_names = {
            WTS_SESSION_LOGON: "logon",
            WTS_SESSION_LOGOFF: "logoff",
            WTS_SESSION_LOCK: "lock",
            WTS_SESSION_UNLOCK: "unlock",
            WTS_SESSION_DESKTOP_READY: "desktop_ready",
        }
        event_name = event_names.get(event_type, f"event_{event_type}")
        self.logger.info("Session event received: %s session=%s", event_name, session_id)

        if event_type == WTS_SESSION_LOCK:
            self._mark_ui_presence(session_id, False, "default")
            self._invalidate_until_lock_grant(session_id)
            with self.lock:
                self.gates.pop(session_id, None)
                self.client_actions.pop(session_id, None)
                self.recovery_session_bypasses.discard(session_id)
            self.logger.info(
                "Session %s locked; pending gate/action/recovery bypass cleared",
                session_id,
            )
            return

        if event_type == WTS_SESSION_UNLOCK:
            if self.config["verify_on_unlock"]:
                self._queue_evaluation(session_id, reason="unlock", replace=True)
            return

        if event_type in (WTS_SESSION_LOGON, WTS_SESSION_DESKTOP_READY):
            if self.config["verify_on_logon"]:
                self._queue_evaluation(session_id, reason=event_name, replace=False)
            return

        if event_type == WTS_SESSION_LOGOFF:
            with self.lock:
                self.gates.pop(session_id, None)
                self.session_grants.pop(session_id, None)
                self.ui_last_seen.pop(session_id, None)
                self.ui_ready_events.pop(session_id, None)
                self.ui_tokens.pop(session_id, None)
                self.ui_launch_locks.pop(session_id, None)
                self.client_actions.pop(session_id, None)
                self.recovery_session_bypasses.discard(session_id)
                self.session_failed_attempts.pop(session_id, None)
                self.session_last_failure_utc.pop(session_id, None)
            return

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_requested.set()
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self) -> None:
        servicemanager.LogInfoMsg("Windows Login Guard started")
        self.logger.info("Service started")
        self.logger.info("Session-change notifications enabled")
        try:
            self.server_thread = threading.Thread(target=self._serve, daemon=True)
            self.server_thread.start()
            if not self.server_ready.wait(timeout=10):
                raise RuntimeError("Local verification server did not become ready")

            self.worker_thread = threading.Thread(target=self._monitor, daemon=True)
            self.worker_thread.start()

            if self.config["enforce_on_service_start"]:
                self.startup_thread = threading.Thread(
                    target=self._evaluate_active_sessions_on_start,
                    daemon=True,
                )
                self.startup_thread.start()
            else:
                self.logger.info("Service-start enforcement is disabled")

            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        except Exception:
            self.logger.exception("Fatal service error")
            raise
        finally:
            self.logger.info("Service stopped")
            try:
                PORT_FILE.unlink(missing_ok=True)
            except OSError:
                pass

    def _serve(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = server
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, 0))
        server.listen(20)
        server.settimeout(1)
        port = server.getsockname()[1]
        PORT_FILE.write_text(str(port), encoding="ascii")
        self.logger.info("Local verification server listening on port %s", port)
        self.server_ready.set()

        while not self.stop_requested.is_set():
            try:
                client, _address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client, args=(client,), daemon=True
            ).start()

    def _handle_client(self, client: socket.socket) -> None:
        with client:
            client.settimeout(7)
            try:
                request = recv_json(client)
                session_id = int(request.get("session_id", -1))
                token = str(request.get("token", ""))
                action = str(request.get("action", ""))

                management_actions = {
                    "admin_dashboard",
                    "admin_diagnostics",
                    "admin_list_accounts",
                    "admin_get_config",
                    "admin_update_config",
                    "admin_regenerate_recovery",
                    "admin_reset_otp",
                    "admin_audit",
                    "admin_enable_maintenance",
                    "admin_disable_maintenance",
                    "admin_rotate_maintenance_key",
                    "remote_approve_session",
                    "remote_deny_session",
                    "remote_lock_session",
                    "remote_logoff_session",
                }
                if action in management_actions:
                    if not self._valid_management_token(token):
                        send_json(
                            client,
                            {"ok": False, "error": "invalid_management_token"},
                        )
                        return
                elif not self._valid_ui_token(session_id, token):
                    send_json(
                        client,
                        {"ok": False, "error": "invalid_session_token"},
                    )
                    return

                desktop_available = bool(request.get("desktop_available", False))
                interaction_context = str(
                    request.get("interaction_context", "default")
                ).strip().lower()
                if action in {"status", "ui_ready"}:
                    self._mark_ui_presence(
                        session_id,
                        desktop_available,
                        interaction_context,
                    )
                    response = self._status(session_id)
                elif action == "verify_user":
                    response = self._verify_user(
                        session_id, str(request.get("code", "")).strip()
                    )
                elif action == "request_remote_approval":
                    response = self._request_remote_approval(session_id)
                elif action == "cancel_remote_approval":
                    response = self._cancel_remote_approval(session_id)
                elif action == "recovery_begin":
                    response = self._recovery_begin(session_id)
                elif action == "recovery_activity":
                    response = self._recovery_activity(session_id)
                elif action == "recovery_cancel":
                    response = self._recovery_cancel(session_id)
                elif action == "recovery_unlock_session":
                    response = self._recovery_unlock_session(
                        session_id=session_id,
                        recovery_key=str(
                            request.get("recovery_key", "")
                        ).strip(),
                        reason=str(request.get("reason", "")).strip(),
                    )
                elif action == "authorize_enrollment":
                    response = self._authorize_enrollment(
                        session_id=session_id,
                        approver_id=str(request.get("approver_id", "")),
                        code=str(request.get("code", "")).strip(),
                    )
                elif action == "complete_enrollment":
                    response = self._complete_enrollment(
                        session_id, str(request.get("code", "")).strip()
                    )
                elif action == "approve_current_session":
                    response = self._approve_current_session(
                        target_session_id=session_id,
                        approver_id=str(request.get("approver_id", "")),
                        code=str(request.get("code", "")).strip(),
                        duration=str(request.get("duration", "")),
                    )
                elif action == "approve_session":
                    response = self._approve_session(
                        admin_session_id=session_id,
                        target_session_id=int(request.get("target_session_id", -1)),
                        code=str(request.get("code", "")).strip(),
                        duration=str(request.get("duration", "")),
                    )
                elif action == "client_action_result":
                    response = self._client_action_result(
                        session_id=session_id,
                        request_id=str(request.get("request_id", "")),
                        success=bool(request.get("success", False)),
                        error=str(request.get("error", "")),
                    )
                elif action == "ui_event":
                    response = self._record_ui_event(
                        session_id=session_id,
                        event_name=str(request.get("event_name", "")),
                        message=str(request.get("message", "")),
                    )
                elif action == "admin_dashboard":
                    response = self._admin_dashboard()
                elif action == "admin_diagnostics":
                    response = self._admin_diagnostics()
                elif action == "admin_list_accounts":
                    response = self._admin_list_accounts()
                elif action == "admin_get_config":
                    response = self._admin_get_config()
                elif action == "admin_update_config":
                    response = self._admin_update_config(
                        approver_sid=str(
                            request.get("approver_sid", "")
                        ),
                        code=str(request.get("code", "")).strip(),
                        updates=request.get("updates", {}),
                    )
                elif action == "admin_regenerate_recovery":
                    response = self._admin_regenerate_recovery(
                        target_sid=str(request.get("target_sid", "")),
                        approver_sid=str(request.get("approver_sid", "")),
                        code=str(request.get("code", "")).strip(),
                    )
                elif action == "admin_reset_otp":
                    response = self._admin_reset_otp(
                        target_sid=str(request.get("target_sid", "")),
                        approver_sid=str(request.get("approver_sid", "")),
                        code=str(request.get("code", "")).strip(),
                    )
                elif action == "admin_audit":
                    response = self._admin_audit(
                        limit=int(request.get("limit", 100))
                    )
                elif action == "admin_enable_maintenance":
                    response = self._admin_enable_maintenance(
                        approver_sid=str(
                            request.get("approver_sid", "")
                        ),
                        code=str(request.get("code", "")).strip(),
                        recovery_key=str(
                            request.get("recovery_key", "")
                        ).strip(),
                        reason=str(request.get("reason", "")).strip(),
                    )
                elif action == "admin_disable_maintenance":
                    response = self._admin_disable_maintenance(
                        approver_sid=str(
                            request.get("approver_sid", "")
                        ),
                        code=str(request.get("code", "")).strip(),
                        recovery_key=str(
                            request.get("recovery_key", "")
                        ).strip(),
                    )
                elif action == "admin_rotate_maintenance_key":
                    response = self._admin_rotate_maintenance_key(
                        approver_sid=str(
                            request.get("approver_sid", "")
                        ),
                        code=str(request.get("code", "")).strip(),
                    )
                elif action == "remote_approve_session":
                    response = self._remote_approve_session(
                        target_session_id=int(
                            request.get("target_session_id", -1)
                        ),
                        challenge_id=str(
                            request.get("challenge_id", "")
                        ),
                        target_user_sid=str(
                            request.get("target_user_sid", "")
                        ),
                        duration=str(request.get("duration", "")),
                        request_id=str(request.get("request_id", "")),
                        approver_name=str(
                            request.get("approver_name", "")
                        ),
                    )
                elif action == "remote_deny_session":
                    response = self._remote_deny_session(
                        target_session_id=int(
                            request.get("target_session_id", -1)
                        ),
                        challenge_id=str(
                            request.get("challenge_id", "")
                        ),
                        target_user_sid=str(
                            request.get("target_user_sid", "")
                        ),
                        request_id=str(request.get("request_id", "")),
                        approver_name=str(
                            request.get("approver_name", "")
                        ),
                    )
                elif action == "remote_lock_session":
                    response = self._remote_lock_session(
                        target_session_id=int(
                            request.get("target_session_id", -1)
                        ),
                        target_user_sid=str(
                            request.get("target_user_sid", "")
                        ),
                        request_id=str(request.get("request_id", "")),
                        approver_name=str(
                            request.get("approver_name", "")
                        ),
                    )
                elif action == "remote_logoff_session":
                    response = self._remote_logoff_session(
                        target_session_id=int(
                            request.get("target_session_id", -1)
                        ),
                        target_user_sid=str(
                            request.get("target_user_sid", "")
                        ),
                        request_id=str(request.get("request_id", "")),
                        approver_name=str(
                            request.get("approver_name", "")
                        ),
                    )
                else:
                    response = {"ok": False, "error": "unknown_action"}
                send_json(client, response)
            except Exception as exc:
                self.logger.warning("Client request failed: %s", exc)
                try:
                    send_json(
                        client,
                        {
                            "ok": False,
                            "error": "request_failed",
                            "message": str(exc),
                        },
                    )
                except Exception:
                    pass

    def _valid_management_token(self, token: str) -> bool:
        try:
            expected = MANAGEMENT_TOKEN_PATH.read_text(
                encoding="ascii"
            ).strip()
        except OSError:
            return False
        return bool(
            expected and token and hmac.compare_digest(expected, token)
        )

    def _append_admin_audit(
        self,
        *,
        action: str,
        target_sid: str,
        target_username: str,
        actor_sid: str,
        actor_username: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "timestamp_utc": self._utc_now_iso(),
            "action": action,
            "target_sid": target_sid,
            "target_username": target_username,
            "actor_sid": actor_sid,
            "actor_username": actor_username,
            "details": details or {},
        }
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_lock:
            with AUDIT_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    def _management_approver(
        self, approver_sid: str, code: str
    ) -> dict[str, Any] | None:
        profile = self._read_profile(approver_sid)
        if not profile:
            return None
        if not bool(profile.get("is_administrator", False)):
            return None
        if not self._user_is_enrolled(approver_sid):
            return None
        if not self._verify_account_code(
            approver_sid, code, consume_recovery=True
        ):
            return None
        return profile

    def _account_management_record(
        self, profile_path: Path
    ) -> dict[str, Any] | None:
        try:
            profile = json.loads(
                profile_path.read_text(encoding="utf-8-sig")
            )
            sid = str(profile.get("user_sid", profile_path.parent.name))
            recovery: dict[str, Any] = {}
            enrollment: dict[str, Any] = {}
            try:
                recovery = json.loads(
                    user_recovery_path(sid).read_text(
                        encoding="utf-8-sig"
                    )
                )
            except (OSError, json.JSONDecodeError):
                pass
            try:
                enrollment = json.loads(
                    user_enrollment_path(sid).read_text(
                        encoding="utf-8-sig"
                    )
                )
            except (OSError, json.JSONDecodeError):
                pass
            return {
                "sid": sid,
                "username": str(profile.get("username", sid)),
                "is_administrator": bool(
                    profile.get("is_administrator", False)
                ),
                "enrolled": self._user_is_enrolled(sid),
                "enrolled_at_utc": str(
                    profile.get("enrolled_at_utc", "")
                ),
                "authorized_by": str(
                    profile.get("authorized_by", "")
                ),
                "recovery_codes_remaining": len(
                    recovery.get("unused_hashes", [])
                ),
                "recovery_codes_generated_at_utc": str(
                    recovery.get(
                        "generated_at_utc",
                        enrollment.get(
                            "recovery_codes_generated_at_utc", ""
                        ),
                    )
                ),
                "recovery_codes_version": int(
                    recovery.get(
                        "version",
                        enrollment.get("recovery_codes_version", 1),
                    )
                ),
            }
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _application_version() -> str:
        try:
            return Path(__file__).with_name("VERSION").read_text(
                encoding="utf-8"
            ).strip()
        except OSError:
            return "unknown"

    @staticmethod
    def _session_state_label(state: int) -> str:
        labels = {
            int(getattr(win32ts, "WTSActive", 0)): "Active",
            int(getattr(win32ts, "WTSConnected", 1)): "Connected",
            int(getattr(win32ts, "WTSConnectQuery", 2)): "Connecting",
            int(getattr(win32ts, "WTSShadow", 3)): "Shadow",
            int(getattr(win32ts, "WTSDisconnected", 4)): "Disconnected",
            int(getattr(win32ts, "WTSIdle", 5)): "Idle",
            int(getattr(win32ts, "WTSListen", 6)): "Listening",
            int(getattr(win32ts, "WTSReset", 7)): "Reset",
            int(getattr(win32ts, "WTSDown", 8)): "Down",
            int(getattr(win32ts, "WTSInit", 9)): "Initializing",
        }
        return labels.get(int(state), f"State {state}")

    def _service_runtime_details(self) -> dict[str, Any]:
        startup = "Unknown"
        service_state = "Running"
        scm = None
        handle = None
        try:
            scm = win32service.OpenSCManager(
                None,
                None,
                win32service.SC_MANAGER_CONNECT,
            )
            handle = win32service.OpenService(
                scm,
                self._svc_name_,
                win32service.SERVICE_QUERY_CONFIG
                | win32service.SERVICE_QUERY_STATUS,
            )
            config = win32service.QueryServiceConfig(handle)
            start_type = int(config[1])
            startup = {
                int(win32service.SERVICE_AUTO_START): "Automatic",
                int(win32service.SERVICE_DEMAND_START): "Manual",
                int(win32service.SERVICE_DISABLED): "Disabled",
                int(win32service.SERVICE_BOOT_START): "Boot",
                int(win32service.SERVICE_SYSTEM_START): "System",
            }.get(start_type, f"Type {start_type}")
            state = int(win32service.QueryServiceStatus(handle)[1])
            service_state = {
                int(win32service.SERVICE_RUNNING): "Running",
                int(win32service.SERVICE_START_PENDING): "Starting",
                int(win32service.SERVICE_STOP_PENDING): "Stopping",
                int(win32service.SERVICE_STOPPED): "Stopped",
                int(win32service.SERVICE_PAUSED): "Paused",
            }.get(state, f"State {state}")
        except Exception:
            self.logger.debug(
                "Unable to query Windows service metadata",
                exc_info=True,
            )
        finally:
            for item in (handle, scm):
                if item is not None:
                    try:
                        win32service.CloseServiceHandle(item)
                    except Exception:
                        pass
        return {
            "status": service_state,
            "startup": startup,
            "pid": os.getpid(),
            "version": self._application_version(),
            "started_at": datetime.fromtimestamp(
                self.started_at,
                tz=timezone.utc,
            ).isoformat(),
            "uptime_seconds": max(0, int(time.time() - self.started_at)),
        }

    def _health_snapshot(self) -> list[dict[str, str]]:
        checks: list[dict[str, str]] = []

        def add(key: str, label: str, status: str, detail: str) -> None:
            checks.append(
                {
                    "key": key,
                    "label": label,
                    "status": status,
                    "detail": detail,
                }
            )

        add(
            "service",
            "Windows service",
            "healthy",
            "The WindowsLoginGuard service is running.",
        )
        add(
            "ipc",
            "Local IPC",
            "healthy" if self.server_ready.is_set() and PORT_FILE.exists() else "error",
            "The Administration Console is connected to the local service."
            if self.server_ready.is_set() and PORT_FILE.exists()
            else "The local service endpoint is not ready.",
        )

        try:
            load_config()
            add(
                "configuration",
                "Configuration",
                "healthy",
                f"Configuration loaded from {CONFIG_PATH}.",
            )
        except Exception as exc:
            add(
                "configuration",
                "Configuration",
                "error",
                str(exc),
            )

        secure_ok = SECURE_DIR.exists() and os.access(SECURE_DIR, os.R_OK)
        add(
            "secure_storage",
            "Secure storage",
            "healthy" if secure_ok else "error",
            str(SECURE_DIR) if secure_ok else "Secure storage is unavailable.",
        )

        audit_parent_ok = AUDIT_PATH.parent.exists() and os.access(
            AUDIT_PATH.parent,
            os.W_OK,
        )
        add(
            "audit",
            "Audit storage",
            "healthy" if audit_parent_ok else "error",
            str(AUDIT_PATH)
            if audit_parent_ok
            else "The audit directory is not writable.",
        )

        recovery_ok = MAINTENANCE_KEY_HASH_PATH.exists()
        add(
            "recovery",
            "Maintenance recovery",
            "healthy" if recovery_ok else "warning",
            "The machine maintenance recovery key is configured."
            if recovery_ok
            else "The machine maintenance recovery key is not configured.",
        )

        try:
            probe = protect_machine_secret("wlg-health-check")
            dpapi_ok = unprotect_machine_secret(probe) == "wlg-health-check"
        except Exception:
            dpapi_ok = False
        add(
            "dpapi",
            "Windows DPAPI",
            "healthy" if dpapi_ok else "error",
            "Machine-scope encryption is available."
            if dpapi_ok
            else "Machine-scope encryption failed its round-trip check.",
        )

        remote_config_path = SECURE_DIR / "remote-agent.json"
        remote_token_path = SECURE_DIR / "remote-device-token.dpapi"
        if remote_config_path.exists():
            try:
                remote_status = win32serviceutil.QueryServiceStatus(
                    "WindowsLoginGuardRemoteAgent"
                )
                remote_running = (
                    int(remote_status[1]) == win32service.SERVICE_RUNNING
                )
            except Exception:
                remote_running = False
            remote_ready = remote_running and remote_token_path.exists()
            add(
                "remote_agent",
                "Remote management agent",
                "healthy" if remote_ready else "warning",
                "The outbound Remote Agent is running and registered."
                if remote_ready
                else "Remote management is configured, but the Remote Agent is not fully operational.",
            )
        else:
            add(
                "remote_agent",
                "Remote management agent",
                "information",
                "Remote management is not configured on this device.",
            )
        return checks

    def _dashboard_sessions(self) -> list[dict[str, Any]]:
        try:
            states = self._enumerate_sessions()
        except Exception:
            self.logger.exception("Dashboard session enumeration failed")
            states = dict(self.last_states)

        with self.lock:
            gates = dict(self.gates)

        now_monotonic = time.monotonic()
        threshold = int(self.config["recovery_otp_failure_threshold"])
        rows: list[dict[str, Any]] = []

        for session_id, state in sorted(states.items()):
            if int(session_id) <= 0:
                continue
            identity = None
            try:
                identity = self._session_identity(int(session_id))
            except Exception:
                self.logger.debug(
                    "Unable to resolve session identity for %s",
                    session_id,
                    exc_info=True,
                )

            gate = gates.get(int(session_id))
            active_failed_attempts = int(gate.failed_attempts) if gate else 0
            failed_attempts = max(
                active_failed_attempts,
                int(self.session_failed_attempts.get(int(session_id), 0)),
            )
            recovery_available = bool(
                gate is not None
                and active_failed_attempts >= threshold
            )

            remaining_seconds: int | None = None
            if gate is not None:
                deadline = (
                    gate.recovery_deadline
                    if gate.recovery_active
                    else gate.deadline
                )
                if deadline is not None:
                    remaining_seconds = max(
                        0,
                        int(deadline - now_monotonic),
                    )

            if gate is None:
                verification_state = "Not required"
                reason = ""
            elif gate.recovery_active:
                verification_state = "Recovery"
                reason = gate.reason
            elif gate.kind == "approval_wait":
                verification_state = "Waiting approval"
                reason = gate.reason
            elif gate.kind == "enroll":
                verification_state = "Enrollment"
                reason = gate.reason
            elif gate.kind == "deny":
                verification_state = "Denied"
                reason = gate.reason
            else:
                verification_state = "Waiting OTP"
                reason = gate.reason

            rows.append(
                {
                    "session_id": int(session_id),
                    "username": identity.username if identity else "Unknown",
                    "user_sid": identity.user_sid if identity else "",
                    "connection_state": self._session_state_label(int(state)),
                    "verification_required": gate is not None,
                    "verification_state": verification_state,
                    "verification_reason": reason,
                    "challenge_id": (
                        gate.challenge_id if gate is not None else ""
                    ),
                    "challenge_created_utc": (
                        gate.created_at_utc if gate is not None else ""
                    ),
                    "allowed_approval_durations": (
                        list(self.config["allowed_approval_durations"])
                        if gate is not None
                        and gate.kind == "approval_wait"
                        else []
                    ),
                    "default_approval_duration": (
                        str(self.config["default_approval_duration"])
                        if gate is not None
                        and gate.kind == "approval_wait"
                        else ""
                    ),
                    "remaining_seconds": remaining_seconds,
                    "failed_attempts": failed_attempts,
                    "last_failure_utc": self.session_last_failure_utc.get(
                        int(session_id), ""
                    ),
                    "recovery_available": recovery_available,
                }
            )
        return rows

    def _admin_dashboard(self) -> dict[str, Any]:
        accounts_response = self._admin_list_accounts()
        accounts = list(accounts_response.get("accounts", []))
        maintenance = self._maintenance_state()
        sessions = self._dashboard_sessions()
        waiting = sum(
            1 for row in sessions if row["verification_required"]
        )
        recovery_ready = sum(
            1 for row in sessions if row["recovery_available"]
        )
        health = self._health_snapshot()
        recent = list(
            self._admin_audit(limit=8).get("records", [])
        )

        notifications: list[dict[str, str]] = []
        if maintenance.get("enabled", False):
            notifications.append(
                {
                    "severity": "warning",
                    "title": "Maintenance mode is enabled",
                    "detail": str(maintenance.get("reason", "")),
                }
            )
        if waiting:
            notifications.append(
                {
                    "severity": "warning",
                    "title": f"{waiting} session(s) waiting for verification",
                    "detail": "Review the Live Sessions table.",
                }
            )
        if recovery_ready:
            notifications.append(
                {
                    "severity": "warning",
                    "title": f"F8 recovery is available in {recovery_ready} session(s)",
                    "detail": "The configured failed-attempt threshold was reached.",
                }
            )
        for record in recent[:3]:
            notifications.append(
                {
                    "severity": "information",
                    "title": str(record.get("action", "Activity")).replace(
                        "_", " "
                    ).title(),
                    "detail": str(record.get("timestamp_utc", "")),
                }
            )
        if not notifications:
            notifications.append(
                {
                    "severity": "healthy",
                    "title": "No active warnings",
                    "detail": "Windows Login Guard is operating normally.",
                }
            )

        overall = "healthy"
        if any(item["status"] == "error" for item in health):
            overall = "critical"
        elif any(item["status"] == "warning" for item in health):
            overall = "warning"

        return {
            "ok": True,
            "api_version": 2,
            "service": self._service_runtime_details(),
            "overall_health": overall,
            "health": health,
            "maintenance": maintenance,
            "counts": {
                "enrolled_accounts": len(accounts),
                "active_sessions": len(sessions),
                "waiting_for_verification": waiting,
                "recovery_available": recovery_ready,
            },
            "notifications": notifications,
            "recent_activity": recent,
            "sessions": sessions,
            "supported_approval_durations": list(APPROVAL_DURATION_ORDER),
            "configured_approval_durations": list(
                self.config["allowed_approval_durations"]
            ),
        }

    def _admin_diagnostics(self) -> dict[str, Any]:
        return {
            "ok": True,
            "api_version": 2,
            "service": self._service_runtime_details(),
            "health": self._health_snapshot(),
            "paths": {
                "configuration": str(CONFIG_PATH),
                "secure_storage": str(SECURE_DIR),
                "audit": str(AUDIT_PATH),
                "service_log": str(LOG_PATH),
                "runtime_port": str(PORT_FILE),
            },
        }

    def _admin_list_accounts(self) -> dict[str, Any]:
        accounts: list[dict[str, Any]] = []
        if USERS_DIR.exists():
            for profile_path in USERS_DIR.glob("S-*/profile.json"):
                record = self._account_management_record(profile_path)
                if record is not None:
                    accounts.append(record)
        accounts.sort(key=lambda item: str(item["username"]).lower())
        return {
            "ok": True,
            "accounts": accounts,
            "approvers": self._admin_approvers(),
            "maintenance": self._maintenance_state(),
        }

    def _admin_get_config(self) -> dict[str, Any]:
        values = {
            key: admin_config_value(self.config, key)
            for key in ADMIN_CONFIG_SCHEMA
        }
        return {
            "ok": True,
            "service_version": self._application_version(),
            "schema": ADMIN_CONFIG_SCHEMA,
            "values": values,
            "restart_required": True,
        }

    def _admin_update_config(
        self,
        *,
        approver_sid: str,
        code: str,
        updates: Any,
    ) -> dict[str, Any]:
        approver = self._management_approver(approver_sid, code)
        if approver is None:
            return {"ok": False, "error": "invalid_admin_otp"}

        try:
            normalized = validate_admin_config_updates(
                updates,
                self.config,
            )
        except ValueError as exc:
            return {
                "ok": False,
                "error": "invalid_configuration",
                "message": str(exc),
            }

        changed: dict[str, dict[str, Any]] = {}
        candidate = json.loads(json.dumps(self.config))
        for key, value in normalized.items():
            old_value = admin_config_value(self.config, key)
            if old_value == value:
                continue
            set_admin_config_value(candidate, key, value)
            changed[key] = {
                "old": old_value,
                "new": value,
            }

        if not changed:
            return {
                "ok": True,
                "saved": False,
                "changed": {},
            }

        old_file: bytes | None = None
        try:
            if CONFIG_PATH.exists():
                old_file = CONFIG_PATH.read_bytes()
            atomic_write_json(CONFIG_PATH, candidate)
            validated = load_config()
        except Exception as exc:
            try:
                if old_file is None:
                    CONFIG_PATH.unlink(missing_ok=True)
                else:
                    temporary = CONFIG_PATH.with_suffix(
                        CONFIG_PATH.suffix + ".restore"
                    )
                    temporary.write_bytes(old_file)
                    os.replace(temporary, CONFIG_PATH)
            except OSError:
                self.logger.exception(
                    "Failed to restore config.json after validation failure"
                )
            return {
                "ok": False,
                "error": "invalid_configuration",
                "message": str(exc),
            }

        self.config = validated
        actor_name = str(
            approver.get("username", approver_sid)
        )
        self._append_admin_audit(
            action="configuration_updated",
            target_sid="",
            target_username="Windows Login Guard",
            actor_sid=approver_sid,
            actor_username=actor_name,
            details={"changes": changed},
        )
        self.logger.warning(
            "Configuration updated by %s (%s): %s",
            actor_name,
            approver_sid,
            ", ".join(sorted(changed)),
        )
        return {
            "ok": True,
            "saved": True,
            "changed": changed,
            "values": {
                key: admin_config_value(self.config, key)
                for key in ADMIN_CONFIG_SCHEMA
            },
            "restart_required": True,
        }

    def _admin_regenerate_recovery(
        self,
        *,
        target_sid: str,
        approver_sid: str,
        code: str,
    ) -> dict[str, Any]:
        target = self._read_profile(target_sid)
        if not target or not self._user_is_enrolled(target_sid):
            return {"ok": False, "error": "target_not_enrolled"}
        approver = self._management_approver(approver_sid, code)
        if approver is None:
            return {"ok": False, "error": "invalid_admin_otp"}

        recovery_codes = [self._new_recovery_code() for _ in range(8)]
        old_version = 0
        try:
            old_data = json.loads(
                user_recovery_path(target_sid).read_text(
                    encoding="utf-8-sig"
                )
            )
            old_version = int(old_data.get("version", 0))
        except (OSError, json.JSONDecodeError, ValueError):
            pass

        generated_at = self._utc_now_iso()
        version = old_version + 1
        actor_name = str(approver.get("username", approver_sid))
        target_name = str(target.get("username", target_sid))
        atomic_write_json(
            user_recovery_path(target_sid),
            {
                "unused_hashes": [
                    self._hash_recovery_code(item)
                    for item in recovery_codes
                ],
                "generated_at_utc": generated_at,
                "generated_by_sid": approver_sid,
                "generated_by_username": actor_name,
                "version": version,
            },
        )

        enrollment: dict[str, Any] = {}
        try:
            enrollment = json.loads(
                user_enrollment_path(target_sid).read_text(
                    encoding="utf-8-sig"
                )
            )
        except (OSError, json.JSONDecodeError):
            pass
        enrollment.update(
            {
                "user_sid": target_sid,
                "username": target_name,
                "recovery_codes_generated_at_utc": generated_at,
                "recovery_codes_version": version,
                "recovery_codes_generated_by_sid": approver_sid,
            }
        )
        atomic_write_json(user_enrollment_path(target_sid), enrollment)
        self._append_admin_audit(
            action="regenerate_recovery_codes",
            target_sid=target_sid,
            target_username=target_name,
            actor_sid=approver_sid,
            actor_username=actor_name,
            details={"version": version, "count": 8},
        )
        self.logger.warning(
            "Recovery codes regenerated for %s (%s) by %s (%s)",
            target_name, target_sid, actor_name, approver_sid,
        )
        return {
            "ok": True,
            "generated": True,
            "recovery_codes": recovery_codes,
            "version": version,
            "generated_at_utc": generated_at,
        }

    def _admin_reset_otp(
        self,
        *,
        target_sid: str,
        approver_sid: str,
        code: str,
    ) -> dict[str, Any]:
        target = self._read_profile(target_sid)
        if not target:
            return {"ok": False, "error": "target_not_found"}
        approver = self._management_approver(approver_sid, code)
        if approver is None:
            return {"ok": False, "error": "invalid_admin_otp"}

        target_name = str(target.get("username", target_sid))
        actor_name = str(approver.get("username", approver_sid))
        for path in (
            user_secret_path(target_sid),
            user_recovery_path(target_sid),
            user_profile_path(target_sid),
            user_enrollment_path(target_sid),
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                return {"ok": False, "error": f"reset_failed:{exc}"}

        with self.lock:
            self.pending_enrollments.pop(target_sid, None)
            self.timed_grants.pop(target_sid, None)
            for session_id, grant in list(self.session_grants.items()):
                if grant.target_user_sid == target_sid:
                    self.session_grants.pop(session_id, None)
        self._save_timed_grants()
        self._append_admin_audit(
            action="reset_otp_enrollment",
            target_sid=target_sid,
            target_username=target_name,
            actor_sid=approver_sid,
            actor_username=actor_name,
        )
        self.logger.warning(
            "OTP enrollment reset for %s (%s) by %s (%s)",
            target_name, target_sid, actor_name, approver_sid,
        )
        return {"ok": True, "reset": True}

    @staticmethod
    def _new_maintenance_recovery_key() -> str:
        compact = secrets.token_hex(20).upper()
        return "-".join(
            compact[index:index + 8]
            for index in range(0, len(compact), 8)
        )

    def _admin_rotate_maintenance_key(
        self,
        *,
        approver_sid: str,
        code: str,
    ) -> dict[str, Any]:
        approver = self._management_approver(approver_sid, code)
        if approver is None:
            return {"ok": False, "error": "invalid_admin_otp"}

        recovery_key = self._new_maintenance_recovery_key()
        digest = hashlib.sha256(
            recovery_key.encode("utf-8")
        ).hexdigest()
        temporary = MAINTENANCE_KEY_HASH_PATH.with_suffix(
            MAINTENANCE_KEY_HASH_PATH.suffix + ".tmp"
        )
        try:
            MAINTENANCE_KEY_HASH_PATH.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            temporary.write_text(
                digest + "\n",
                encoding="ascii",
            )
            os.replace(temporary, MAINTENANCE_KEY_HASH_PATH)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            self.logger.exception(
                "Could not rotate the maintenance recovery key"
            )
            return {
                "ok": False,
                "error": "maintenance_key_rotation_failed",
                "message": str(exc),
            }

        actor_name = str(
            approver.get("username", approver_sid)
        )
        self._append_admin_audit(
            action="maintenance_recovery_key_rotated",
            target_sid="",
            target_username="Windows Login Guard",
            actor_sid=approver_sid,
            actor_username=actor_name,
            details={
                "previous_key_invalidated": True,
                "displayed_once": True,
            },
        )
        self.logger.critical(
            "Maintenance recovery key rotated by %s (%s)",
            actor_name,
            approver_sid,
        )
        return {
            "ok": True,
            "rotated": True,
            "maintenance_recovery_key": recovery_key,
        }

    def _admin_audit(self, *, limit: int) -> dict[str, Any]:
        limit = max(1, min(int(limit), 500))
        records: list[dict[str, Any]] = []
        try:
            lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        for line in lines[-limit:]:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        records.reverse()
        return {"ok": True, "records": records}

    def _maintenance_state(self) -> dict[str, Any]:
        try:
            value = json.loads(
                MAINTENANCE_STATE_PATH.read_text(encoding="utf-8-sig")
            )
        except (OSError, json.JSONDecodeError):
            return {"enabled": False}
        if not isinstance(value, dict):
            return {"enabled": False}
        return {
            "enabled": bool(value.get("enabled", False)),
            "enabled_at_utc": str(value.get("enabled_at_utc", "")),
            "enabled_by": str(value.get("enabled_by", "")),
            "reason": str(value.get("reason", "")),
        }

    def _maintenance_enabled(self) -> bool:
        return bool(self._maintenance_state().get("enabled", False))

    @staticmethod
    def _canonical_maintenance_key(value: str) -> str:
        compact = "".join(
            character
            for character in str(value).upper()
            if character not in {"-", " ", "\t", "\r", "\n"}
        )
        if len(compact) != 40:
            return ""
        if any(character not in string.hexdigits.upper() for character in compact):
            return ""
        return "-".join(
            compact[index:index + 8] for index in range(0, 40, 8)
        )

    def _verify_maintenance_key(self, value: str) -> bool:
        canonical = self._canonical_maintenance_key(value)
        if not canonical:
            return False
        try:
            expected = MAINTENANCE_KEY_HASH_PATH.read_text(
                encoding="ascii"
            ).strip().lower()
        except OSError:
            return False
        actual = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest().lower()
        return bool(
            expected
            and len(expected) == 64
            and hmac.compare_digest(expected, actual)
        )

    def _recovery_threshold(self) -> int:
        return int(
            self.config.get("recovery_otp_failure_threshold", 3)
        )

    def _recovery_begin(self, session_id: int) -> dict[str, Any]:
        now = time.monotonic()
        with self.lock:
            gate = self.gates.get(session_id)
            if gate is None or gate.kind != "verify":
                return {
                    "ok": False,
                    "error": "no_verification_challenge",
                }
            if gate.failed_attempts < self._recovery_threshold():
                return {
                    "ok": False,
                    "error": "recovery_not_available",
                }

            if not gate.recovery_active:
                if gate.deadline is not None:
                    gate.paused_deadline_remaining_seconds = max(
                        1,
                        int(gate.deadline - now),
                    )
                else:
                    gate.paused_deadline_remaining_seconds = None
                gate.deadline = None
                gate.recovery_active = True

            gate.recovery_deadline = (
                now
                + int(
                    self.config.get(
                        "recovery_entry_timeout_seconds",
                        600,
                    )
                )
            )
            remaining = max(
                0,
                int(gate.recovery_deadline - now),
            )

        self.logger.warning(
            "Break-glass recovery opened for session %s after %s failed OTP "
            "attempt(s)",
            session_id,
            gate.failed_attempts,
        )
        return {
            "ok": True,
            "recovery_active": True,
            "recovery_remaining_seconds": remaining,
        }

    def _recovery_activity(self, session_id: int) -> dict[str, Any]:
        now = time.monotonic()
        with self.lock:
            gate = self.gates.get(session_id)
            if (
                gate is None
                or gate.kind != "verify"
                or not gate.recovery_active
            ):
                return {
                    "ok": False,
                    "error": "recovery_not_active",
                }
            gate.recovery_deadline = (
                now
                + int(
                    self.config.get(
                        "recovery_entry_timeout_seconds",
                        600,
                    )
                )
            )
            remaining = max(
                0,
                int(gate.recovery_deadline - now),
            )
        return {
            "ok": True,
            "recovery_active": True,
            "recovery_remaining_seconds": remaining,
        }

    def _recovery_cancel(self, session_id: int) -> dict[str, Any]:
        now = time.monotonic()
        with self.lock:
            gate = self.gates.get(session_id)
            if gate is None or gate.kind != "verify":
                return {
                    "ok": False,
                    "error": "no_verification_challenge",
                }

            paused = gate.paused_deadline_remaining_seconds
            gate.recovery_active = False
            gate.recovery_deadline = None
            gate.paused_deadline_remaining_seconds = None
            if gate.timeout_seconds is None:
                gate.deadline = None
            else:
                gate.deadline = now + max(
                    15,
                    paused
                    if paused is not None
                    else int(gate.timeout_seconds),
                )

            remaining = (
                max(0, int(gate.deadline - now))
                if gate.deadline is not None
                else None
            )

        self.logger.info(
            "Break-glass recovery cancelled for session %s", session_id
        )
        response: dict[str, Any] = {
            "ok": True,
            "recovery_active": False,
        }
        if remaining is not None:
            response["remaining_seconds"] = remaining
        return response

    def _authorize_break_glass(
        self,
        *,
        session_id: int,
        recovery_key: str,
    ) -> tuple[SessionGate | None, dict[str, Any] | None]:
        now = time.monotonic()
        with self.lock:
            gate = self.gates.get(session_id)
            if (
                gate is None
                or gate.kind != "verify"
                or not gate.recovery_active
                or gate.failed_attempts < self._recovery_threshold()
            ):
                return None, {
                    "ok": False,
                    "error": "no_active_recovery_challenge",
                }
            if gate.recovery_locked_until > now:
                return None, {
                    "ok": False,
                    "error": "recovery_temporarily_locked",
                    "retry_after_seconds": max(
                        1, int(gate.recovery_locked_until - now)
                    ),
                }
            if gate.recovery_locked_until:
                gate.recovery_locked_until = 0.0
                gate.recovery_failed_attempts = 0

        if self._verify_maintenance_key(recovery_key):
            with self.lock:
                current = self.gates.get(session_id)
                if current is None:
                    return None, {
                        "ok": False,
                        "error": "no_active_recovery_challenge",
                    }
                current.recovery_failed_attempts = 0
                current.recovery_locked_until = 0.0
                current.recovery_deadline = (
                    time.monotonic()
                    + int(
                        self.config.get(
                            "recovery_entry_timeout_seconds",
                            600,
                        )
                    )
                )
                return current, None

        with self.lock:
            current = self.gates.get(session_id)
            if current is None:
                return None, {
                    "ok": False,
                    "error": "no_active_recovery_challenge",
                }
            current.recovery_failed_attempts += 1
            current.recovery_deadline = (
                time.monotonic()
                + int(
                    self.config.get(
                        "recovery_entry_timeout_seconds",
                        600,
                    )
                )
            )
            remaining = max(0, 5 - current.recovery_failed_attempts)
            if remaining <= 0:
                current.recovery_locked_until = time.monotonic() + 30
                current.recovery_failed_attempts = 0

        self.logger.warning(
            "Invalid break-glass recovery key for session %s", session_id
        )
        if remaining <= 0:
            return None, {
                "ok": False,
                "error": "recovery_temporarily_locked",
                "retry_after_seconds": 30,
            }
        return None, {
            "ok": False,
            "error": "invalid_recovery_key",
            "remaining_attempts": remaining,
        }

    def _recovery_unlock_session(
        self,
        *,
        session_id: int,
        recovery_key: str,
        reason: str,
    ) -> dict[str, Any]:
        reason = reason.strip()[:240]
        if not reason:
            return {"ok": False, "error": "recovery_reason_required"}

        gate, error = self._authorize_break_glass(
            session_id=session_id,
            recovery_key=recovery_key,
        )
        if error is not None or gate is None:
            return error or {"ok": False, "error": "recovery_failed"}

        with self.lock:
            self.recovery_session_bypasses.add(session_id)
            self.gates.pop(session_id, None)
            self.client_actions.pop(session_id, None)

        self._append_admin_audit(
            action="break_glass_session_unlock",
            target_sid=gate.user_sid,
            target_username=gate.username,
            actor_sid="",
            actor_username="Maintenance recovery key",
            details={
                "session_id": session_id,
                "reason": reason,
                "scope": "current_session_until_lock",
            },
        )
        self.logger.critical(
            "Break-glass key unlocked session %s for %s (%s); reason=%s",
            session_id,
            gate.username,
            gate.user_sid,
            reason,
        )
        return {
            "ok": True,
            "verified": True,
            "recovery_unlocked": True,
            "scope": "current_session_until_lock",
        }

    def _admin_enable_maintenance(
        self,
        *,
        approver_sid: str,
        code: str,
        recovery_key: str,
        reason: str,
    ) -> dict[str, Any]:
        reason = reason.strip()[:240]
        if not reason:
            return {
                "ok": False,
                "error": "maintenance_reason_required",
            }
        if not self._verify_maintenance_key(recovery_key):
            return {
                "ok": False,
                "error": "invalid_recovery_key",
            }

        approver = self._management_approver(approver_sid, code)
        if approver is None:
            return {
                "ok": False,
                "error": "invalid_admin_otp",
            }

        if self._maintenance_enabled():
            return {
                "ok": True,
                "maintenance_enabled": True,
                "already_enabled": True,
                "maintenance": self._maintenance_state(),
            }

        actor_name = str(
            approver.get("username", approver_sid)
        )
        enabled_at = self._utc_now_iso()
        atomic_write_json(
            MAINTENANCE_STATE_PATH,
            {
                "enabled": True,
                "enabled_at_utc": enabled_at,
                "enabled_by": actor_name,
                "enabled_by_sid": approver_sid,
                "source": "Administration Console",
                "reason": reason,
            },
        )

        with self.lock:
            self.gates.clear()
            self.client_actions.clear()
            self.recovery_session_bypasses.clear()

        self._append_admin_audit(
            action="break_glass_maintenance_enabled",
            target_sid="",
            target_username="Windows Login Guard",
            actor_sid=approver_sid,
            actor_username=actor_name,
            details={
                "enabled_at_utc": enabled_at,
                "reason": reason,
                "source": "Administration Console",
            },
        )
        self.logger.critical(
            "Maintenance mode enabled through Administration Console "
            "by %s (%s); reason=%s",
            actor_name,
            approver_sid,
            reason,
        )
        return {
            "ok": True,
            "maintenance_enabled": True,
            "enabled_at_utc": enabled_at,
        }

    def _admin_disable_maintenance(
        self,
        *,
        approver_sid: str,
        code: str,
        recovery_key: str,
    ) -> dict[str, Any]:
        if not self._verify_maintenance_key(recovery_key):
            return {
                "ok": False,
                "error": "invalid_recovery_key",
            }

        approver = self._management_approver(approver_sid, code)
        if approver is None:
            return {
                "ok": False,
                "error": "invalid_admin_otp",
            }

        actor_name = str(
            approver.get("username", approver_sid)
        )
        disabled_at = self._utc_now_iso()
        atomic_write_json(
            MAINTENANCE_STATE_PATH,
            {
                "enabled": False,
                "disabled_at_utc": disabled_at,
                "disabled_by": actor_name,
                "disabled_by_sid": approver_sid,
                "source": "Administration Console",
            },
        )
        self._append_admin_audit(
            action="break_glass_maintenance_disabled",
            target_sid="",
            target_username="Windows Login Guard",
            actor_sid=approver_sid,
            actor_username=actor_name,
            details={
                "disabled_at_utc": disabled_at,
                "source": "Administration Console",
            },
        )
        self.logger.warning(
            "Maintenance mode disabled through Administration Console "
            "by %s (%s)",
            actor_name,
            approver_sid,
        )
        return {
            "ok": True,
            "maintenance_disabled": True,
            "disabled_at_utc": disabled_at,
        }

    def _valid_ui_token(self, session_id: int, token: str) -> bool:
        with self.lock:
            expected = self.ui_tokens.get(session_id, "")
        return bool(expected and token and hmac.compare_digest(expected, token))

    def _mark_ui_presence(
        self,
        session_id: int,
        desktop_available: bool,
        interaction_context: str,
    ) -> None:
        if session_id <= 0:
            return
        now = time.monotonic()
        armed_gate: SessionGate | None = None
        with self.lock:
            self.ui_last_seen[session_id] = (now, desktop_available)
            event = self.ui_ready_events.setdefault(session_id, threading.Event())
            if desktop_available:
                event.set()
            else:
                event.clear()

            gate = self.gates.get(session_id)
            if (
                desktop_available
                and (
                    interaction_context == "isolated"
                    or (
                        interaction_context == "isolated_fallback"
                        and self.config.get("isolated_desktop_fallback")
                        == "topmost"
                    )
                )
                and self.config.get("interaction_mode") == "isolated_desktop"
                and gate is not None
                and gate.deadline is None
                and gate.timeout_seconds is not None
            ):
                gate.deadline = now + gate.timeout_seconds
                gate.activation_deadline = None
                armed_gate = gate

        if armed_gate is not None:
            if interaction_context == "isolated":
                readiness = "Isolated desktop ready"
            else:
                readiness = "Topmost fallback ready"
            self.logger.warning(
                "%s; gate armed for session %s (%s), timeout=%ss",
                readiness,
                session_id,
                armed_gate.username,
                armed_gate.timeout_seconds,
            )

    def _ui_preferences(self) -> dict[str, Any]:
        return {
            "ui_compact_verify_window": bool(
                self.config.get("ui_compact_verify_window", True)
            ),
            "ui_auto_submit_otp": bool(
                self.config.get("ui_auto_submit_otp", True)
            ),
            "ui_auto_submit_delay_ms": int(
                self.config.get("ui_auto_submit_delay_ms", 200)
            ),
            "ui_always_on_top": bool(
                self.config.get("ui_always_on_top", True)
            ),
            "ui_force_foreground": bool(
                self.config.get("ui_force_foreground", True)
            ),
            "ui_focus_retry_ms": int(
                self.config.get("ui_focus_retry_ms", 250)
            ),
            "ui_focus_retry_count": int(
                self.config.get("ui_focus_retry_count", 3)
            ),
            "interaction_mode": str(
                self.config.get("interaction_mode", "topmost")
            ),
            "isolated_desktop_start_timeout_seconds": int(
                self.config.get(
                    "isolated_desktop_start_timeout_seconds",
                    12,
                )
            ),
            "isolated_desktop_fallback": str(
                self.config.get(
                    "isolated_desktop_fallback",
                    "topmost",
                )
            ),
        }

    def _record_ui_event(
        self,
        *,
        session_id: int,
        event_name: str,
        message: str,
    ) -> dict[str, Any]:
        safe_event = (
            str(event_name).strip().replace("\n", " ")[:80]
            or "unspecified"
        )
        safe_message = str(message).strip().replace("\n", " ")[:600]
        self.logger.warning(
            "UI event session=%s event=%s message=%s",
            session_id,
            safe_event,
            safe_message,
        )

        # Give the normal-desktop fallback a small window to report ready
        # before the service applies the isolated-start failure action.
        if (
            safe_event == "isolated_desktop_failed"
            and self.config.get("isolated_desktop_fallback") == "topmost"
        ):
            with self.lock:
                gate = self.gates.get(session_id)
                if gate is not None and gate.deadline is None:
                    gate.activation_deadline = time.monotonic() + 8

        return {"ok": True}

    def _status(self, session_id: int) -> dict[str, Any]:
        ui_preferences = self._ui_preferences()
        with self.lock:
            gate = self.gates.get(session_id)
            pending_action = self.client_actions.get(session_id)
        if gate is None:
            if pending_action is not None:
                return {
                    "ok": True,
                    "required": True,
                    "mode": "client_action",
                    "client_action": self._client_action_payload(pending_action),
                    **ui_preferences,
                }
            console = self._approval_console_status(session_id)
            if console is not None:
                console.update(ui_preferences)
                return console
            return {
                "ok": True,
                "required": False,
                "mode": "idle",
                **ui_preferences,
            }

        response: dict[str, Any] = {
            "ok": True,
            "required": True,
            "mode": gate.kind,
            "username": gate.username,
            "reason": gate.reason,
            **ui_preferences,
        }
        response["failure_action"] = self._failure_action_for_gate(gate)
        if gate.kind == "verify":
            response["remote_approval_available"] = (
                self._remote_approval_available()
            )
            response["failed_attempts"] = int(gate.failed_attempts)
            response["recovery_available"] = bool(
                gate.failed_attempts >= self._recovery_threshold()
            )
            response["recovery_active"] = bool(gate.recovery_active)
            if (
                gate.recovery_active
                and gate.recovery_deadline is not None
            ):
                response["recovery_remaining_seconds"] = max(
                    0,
                    int(gate.recovery_deadline - time.monotonic()),
                )
        if pending_action is not None:
            response["client_action"] = self._client_action_payload(pending_action)
        if gate.deadline is not None:
            response["remaining_seconds"] = max(
                0, int(gate.deadline - time.monotonic())
            )

        if gate.kind == "enroll":
            pending = self._pending_enrollment(gate.user_sid)
            if pending is None:
                response.update(
                    {
                        "enrollment_stage": "authorize",
                        "initial_enrollment_allowed": self._initial_enrollment_allowed(
                            gate.user_sid
                        ),
                        "approvers": self._enrollment_approvers(),
                    }
                )
            else:
                remaining = max(
                    0,
                    int(
                        self.config["enrollment_session_timeout_seconds"]
                        - (time.monotonic() - pending.created_monotonic)
                    ),
                )
                response.update(
                    {
                        "enrollment_stage": "scan",
                        "provisioning_uri": self._provisioning_uri(pending),
                        "manual_key": pending.secret,
                        "enrollment_remaining_seconds": remaining,
                    }
                )

        if gate.kind == "approval_wait":
            mode = self.config.get("admin_approval_mode", "inline")
            response.update(
                {
                    "admin_approval_mode": mode,
                    "remote_approval_available": (
                        self._remote_approval_available()
                    ),
                    "challenge_id": gate.challenge_id,
                    "allowed_durations": self.config[
                        "allowed_approval_durations"
                    ],
                    "default_duration": self.config[
                        "default_approval_duration"
                    ],
                }
            )
            if mode in {"inline", "either"}:
                response["approvers"] = self._admin_approvers()

        return response

    @staticmethod
    def _remote_approval_available() -> bool:
        return bool(
            (SECURE_DIR / "remote-agent.json").is_file()
            and (SECURE_DIR / "remote-device-token.dpapi").is_file()
        )

    def _request_remote_approval(
        self,
        session_id: int,
    ) -> dict[str, Any]:
        if not self._remote_approval_available():
            return {
                "ok": False,
                "error": "remote_approval_unavailable",
                "message": "This protected PC is not connected to a management server.",
            }

        with self.lock:
            gate = self.gates.get(session_id)
            if gate is None or gate.kind != "verify":
                return {
                    "ok": False,
                    "error": "no_verification_challenge",
                }
            if gate.recovery_active:
                return {
                    "ok": False,
                    "error": "recovery_in_progress",
                }
            if gate.deadline is not None and time.monotonic() >= gate.deadline:
                return {"ok": False, "error": "expired"}

            gate.kind = "approval_wait"
            gate.challenge_id = secrets.token_urlsafe(18)
            gate.created_at = time.time()
            gate.created_at_utc = datetime.now(timezone.utc).isoformat()
            gate.failed_attempts = 0
            gate.recovery_active = False
            gate.recovery_deadline = None
            gate.timeout_seconds = int(
                self.config["approval_timeout_seconds"]
            )
            gate.deadline = time.monotonic() + gate.timeout_seconds
            gate.activation_deadline = None

        self._append_admin_audit(
            action="remote_approval_requested",
            target_sid=gate.user_sid,
            target_username=gate.username,
            actor_sid=gate.user_sid,
            actor_username=gate.username,
            details={
                "session_id": session_id,
                "challenge_id": gate.challenge_id,
                "reason": gate.reason,
                "timeout_seconds": gate.timeout_seconds,
            },
        )
        self.logger.warning(
            "Remote approval requested: session=%s user=%s challenge=%s",
            session_id,
            gate.username,
            gate.challenge_id,
        )
        return {
            "ok": True,
            "remote_approval_requested": True,
            "challenge_id": gate.challenge_id,
            "remaining_seconds": gate.timeout_seconds,
        }

    def _cancel_remote_approval(
        self,
        session_id: int,
    ) -> dict[str, Any]:
        with self.lock:
            gate = self.gates.get(session_id)
            if gate is None or gate.kind != "approval_wait":
                return {
                    "ok": False,
                    "error": "no_remote_approval_request",
                }
            old_challenge_id = gate.challenge_id
            gate.kind = "verify"
            gate.challenge_id = secrets.token_urlsafe(18)
            gate.created_at = time.time()
            gate.created_at_utc = datetime.now(timezone.utc).isoformat()
            gate.failed_attempts = 0
            gate.timeout_seconds = int(self.config["timeout_seconds"])
            gate.deadline = time.monotonic() + gate.timeout_seconds
            gate.activation_deadline = None

        self._append_admin_audit(
            action="remote_approval_cancelled_by_user",
            target_sid=gate.user_sid,
            target_username=gate.username,
            actor_sid=gate.user_sid,
            actor_username=gate.username,
            details={
                "session_id": session_id,
                "challenge_id": old_challenge_id,
            },
        )
        return {
            "ok": True,
            "remote_approval_cancelled": True,
        }

    def _remote_command_gate(
        self,
        *,
        target_session_id: int,
        challenge_id: str,
        target_user_sid: str,
    ) -> tuple[SessionGate | None, dict[str, Any] | None]:
        with self.lock:
            gate = self.gates.get(target_session_id)
        if gate is None or gate.kind != "approval_wait":
            return None, {
                "ok": False,
                "error": "no_approval_request",
            }
        if gate.deadline is not None and time.monotonic() >= gate.deadline:
            return None, {
                "ok": False,
                "error": "approval_request_expired",
            }
        if not challenge_id or not hmac.compare_digest(
            gate.challenge_id,
            challenge_id,
        ):
            return None, {
                "ok": False,
                "error": "approval_challenge_mismatch",
            }
        if target_user_sid and not hmac.compare_digest(
            gate.user_sid,
            target_user_sid,
        ):
            return None, {
                "ok": False,
                "error": "approval_user_mismatch",
            }
        return gate, None

    def _remote_session_identity(
        self,
        *,
        target_session_id: int,
        target_user_sid: str,
    ) -> tuple[SessionIdentity | None, dict[str, Any] | None]:
        if target_session_id <= 0:
            return None, {
                "ok": False,
                "error": "invalid_target_session",
            }
        try:
            identity = self._session_identity(target_session_id)
        except Exception as exc:
            self.logger.warning(
                "Unable to resolve remote target session %s: %s",
                target_session_id,
                exc,
            )
            return None, {
                "ok": False,
                "error": "target_session_unavailable",
                "message": str(exc),
            }
        if identity is None:
            return None, {
                "ok": False,
                "error": "target_session_unavailable",
            }
        if (
            target_user_sid
            and not hmac.compare_digest(
                identity.user_sid,
                target_user_sid,
            )
        ):
            return None, {
                "ok": False,
                "error": "target_session_identity_changed",
            }
        return identity, None

    def _disconnect_session_for_lock(self, session_id: int) -> None:
        disconnect = getattr(
            win32ts,
            "WTSDisconnectSession",
            None,
        )
        if callable(disconnect):
            disconnect(
                win32ts.WTS_CURRENT_SERVER_HANDLE,
                session_id,
                False,
            )
            return

        result = ctypes.windll.Wtsapi32.WTSDisconnectSession(
            0,
            session_id,
            False,
        )
        if not result:
            raise ctypes.WinError()

    def _remote_lock_session(
        self,
        *,
        target_session_id: int,
        target_user_sid: str,
        request_id: str,
        approver_name: str,
    ) -> dict[str, Any]:
        identity, error = self._remote_session_identity(
            target_session_id=target_session_id,
            target_user_sid=target_user_sid,
        )
        if error is not None or identity is None:
            return error or {
                "ok": False,
                "error": "remote_lock_failed",
            }

        state = self._enumerate_sessions().get(target_session_id)
        if state is None:
            return {
                "ok": False,
                "error": "target_session_unavailable",
            }
        if state == int(getattr(win32ts, "WTSDisconnected", 4)):
            return {
                "ok": True,
                "locked": True,
                "already_disconnected": True,
            }

        actor_name = (
            approver_name.strip()[:200]
            or "Remote administrator"
        )
        try:
            self._disconnect_session_for_lock(target_session_id)
        except Exception as exc:
            self.logger.exception(
                "Remote lock failed for session %s",
                target_session_id,
            )
            return {
                "ok": False,
                "error": "windows_session_lock_failed",
                "message": str(exc),
            }

        self._append_admin_audit(
            action="remote_session_locked",
            target_sid=identity.user_sid,
            target_username=identity.username,
            actor_sid=f"remote:{request_id[:80]}",
            actor_username=actor_name,
            details={
                "session_id": target_session_id,
                "request_id": request_id,
                "method": "WTSDisconnectSession",
            },
        )
        self.logger.warning(
            "Session %s for %s locked remotely by %s",
            target_session_id,
            identity.username,
            actor_name,
        )
        return {
            "ok": True,
            "locked": True,
            "session_id": target_session_id,
            "username": identity.username,
            "locked_by": actor_name,
        }

    def _remote_logoff_session(
        self,
        *,
        target_session_id: int,
        target_user_sid: str,
        request_id: str,
        approver_name: str,
    ) -> dict[str, Any]:
        identity, error = self._remote_session_identity(
            target_session_id=target_session_id,
            target_user_sid=target_user_sid,
        )
        if error is not None or identity is None:
            return error or {
                "ok": False,
                "error": "remote_logoff_failed",
            }

        actor_name = (
            approver_name.strip()[:200]
            or "Remote administrator"
        )
        try:
            win32ts.WTSLogoffSession(
                win32ts.WTS_CURRENT_SERVER_HANDLE,
                target_session_id,
                False,
            )
        except Exception as exc:
            self.logger.exception(
                "Remote logoff failed for session %s",
                target_session_id,
            )
            return {
                "ok": False,
                "error": "windows_session_logoff_failed",
                "message": str(exc),
            }

        with self.lock:
            self.gates.pop(target_session_id, None)
            self.client_actions.pop(target_session_id, None)

        self._append_admin_audit(
            action="remote_session_logged_off",
            target_sid=identity.user_sid,
            target_username=identity.username,
            actor_sid=f"remote:{request_id[:80]}",
            actor_username=actor_name,
            details={
                "session_id": target_session_id,
                "request_id": request_id,
            },
        )
        self.logger.warning(
            "Session %s for %s logged off remotely by %s",
            target_session_id,
            identity.username,
            actor_name,
        )
        return {
            "ok": True,
            "logged_off": True,
            "session_id": target_session_id,
            "username": identity.username,
            "logged_off_by": actor_name,
        }

    def _remote_approve_session(
        self,
        *,
        target_session_id: int,
        challenge_id: str,
        target_user_sid: str,
        duration: str,
        request_id: str,
        approver_name: str,
    ) -> dict[str, Any]:
        gate, error = self._remote_command_gate(
            target_session_id=target_session_id,
            challenge_id=challenge_id,
            target_user_sid=target_user_sid,
        )
        if error is not None or gate is None:
            return error or {"ok": False, "error": "approval_failed"}
        if duration not in self.config["allowed_approval_durations"]:
            return {"ok": False, "error": "duration_not_allowed"}

        actor_name = approver_name.strip()[:200] or "Remote administrator"
        grant = self._create_approval_grant(
            gate=gate,
            approver_sid=f"remote:{request_id[:80]}",
            approver_name=actor_name,
            duration=duration,
        )
        with self.lock:
            self.gates.pop(target_session_id, None)

        self._append_admin_audit(
            action="remote_session_approved",
            target_sid=gate.user_sid,
            target_username=gate.username,
            actor_sid=f"remote:{request_id[:80]}",
            actor_username=actor_name,
            details={
                "session_id": target_session_id,
                "challenge_id": challenge_id,
                "request_id": request_id,
                "duration": duration,
                "grant_type": grant.grant_type,
                "expires_at_utc": grant.expires_at_utc,
            },
        )
        self.logger.warning(
            "Session %s for %s approved remotely by %s, duration=%s",
            target_session_id,
            gate.username,
            actor_name,
            duration,
        )
        return {
            "ok": True,
            "approved": True,
            "grant_type": grant.grant_type,
            "expires_at_utc": grant.expires_at_utc,
            "approved_by": actor_name,
        }

    def _remote_deny_session(
        self,
        *,
        target_session_id: int,
        challenge_id: str,
        target_user_sid: str,
        request_id: str,
        approver_name: str,
    ) -> dict[str, Any]:
        gate, error = self._remote_command_gate(
            target_session_id=target_session_id,
            challenge_id=challenge_id,
            target_user_sid=target_user_sid,
        )
        if error is not None or gate is None:
            return error or {"ok": False, "error": "denial_failed"}

        actor_name = approver_name.strip()[:200] or "Remote administrator"
        self._append_admin_audit(
            action="remote_session_denied",
            target_sid=gate.user_sid,
            target_username=gate.username,
            actor_sid=f"remote:{request_id[:80]}",
            actor_username=actor_name,
            details={
                "session_id": target_session_id,
                "challenge_id": challenge_id,
                "request_id": request_id,
                "configured_failure_action": (
                    self._failure_action_for_gate(gate)
                ),
            },
        )
        self.logger.warning(
            "Session %s for %s denied remotely by %s",
            target_session_id,
            gate.username,
            actor_name,
        )
        self._schedule_gate_failure(
            target_session_id,
            trigger="remote_denied",
        )
        return {
            "ok": True,
            "denied": True,
            "failure_action": self._failure_action_for_gate(gate),
        }

    def _verify_user(self, session_id: int, code: str) -> dict[str, Any]:
        with self.lock:
            gate = self.gates.get(session_id)
            if gate is None or gate.kind != "verify":
                return {"ok": False, "error": "no_verification_challenge"}
            if gate.recovery_active:
                return {
                    "ok": False,
                    "error": "recovery_in_progress",
                    "recovery_available": True,
                }
            if gate.deadline is not None and time.monotonic() >= gate.deadline:
                return {"ok": False, "error": "expired"}
            if gate.failed_attempts >= self.config["max_otp_attempts"]:
                self._schedule_gate_failure(session_id, trigger="attempt_limit")
                return {"ok": False, "error": "attempt_limit"}

        valid = self._verify_account_code(gate.user_sid, code, consume_recovery=True)
        if valid:
            with self.lock:
                failed_attempts = int(gate.failed_attempts)
                self.session_failed_attempts[session_id] = failed_attempts
                self.gates.pop(session_id, None)
            self._append_admin_audit(
                action="otp_verification_succeeded",
                target_sid=gate.user_sid,
                target_username=gate.username,
                actor_sid=gate.user_sid,
                actor_username=gate.username,
                details={
                    "session_id": session_id,
                    "reason": gate.reason,
                    "failed_attempts_before_success": failed_attempts,
                },
            )
            self.logger.info(
                "Session %s verified for %s (%s)",
                session_id,
                gate.username,
                gate.user_sid,
            )
            return {"ok": True, "verified": True}

        with self.lock:
            current = self.gates.get(session_id)
            if current is not None:
                current.failed_attempts += 1
                failed_attempts = int(current.failed_attempts)
                self.session_failed_attempts[session_id] = failed_attempts
                self.session_last_failure_utc[session_id] = self._utc_now_iso()
                remaining = max(
                    0,
                    self.config["max_otp_attempts"] - failed_attempts,
                )
            else:
                failed_attempts = int(
                    self.session_failed_attempts.get(session_id, 0)
                )
                remaining = 0
        self.logger.warning(
            "Invalid OTP for session %s (%s); %s attempt(s) remain",
            session_id,
            gate.username,
            remaining,
        )
        recovery_available = bool(
            current is not None
            and current.failed_attempts >= self._recovery_threshold()
        )
        self._append_admin_audit(
            action="otp_verification_failed",
            target_sid=gate.user_sid,
            target_username=gate.username,
            actor_sid=gate.user_sid,
            actor_username=gate.username,
            details={
                "session_id": session_id,
                "reason": gate.reason,
                "failed_attempts": failed_attempts,
                "remaining_attempts": remaining,
                "recovery_available": recovery_available,
            },
        )
        if remaining <= 0 and not recovery_available:
            self._schedule_gate_failure(session_id, trigger="attempt_limit")
        return {
            "ok": False,
            "error": "invalid_code",
            "remaining_attempts": remaining,
            "failed_attempts": (
                int(current.failed_attempts)
                if current is not None
                else 0
            ),
            "recovery_available": recovery_available,
        }

    def _authorize_enrollment(
        self,
        *,
        session_id: int,
        approver_id: str,
        code: str,
    ) -> dict[str, Any]:
        with self.lock:
            gate = self.gates.get(session_id)
        if gate is None or gate.kind != "enroll":
            return {"ok": False, "error": "no_enrollment_session"}
        if self._user_is_enrolled(gate.user_sid):
            return {"ok": False, "error": "already_enrolled"}
        if gate.failed_attempts >= self.config["max_otp_attempts"]:
            return {"ok": False, "error": "attempt_limit"}

        authorized_by = ""
        if approver_id == "__initial__":
            if not self._initial_enrollment_allowed(gate.user_sid):
                return {"ok": False, "error": "initial_enrollment_not_allowed"}
            authorized_by = "trusted_installer"
        elif approver_id == "__bootstrap__":
            if not self.config["allow_bootstrap_enrollment"]:
                return {"ok": False, "error": "bootstrap_disabled"}
            if not self._verify_bootstrap_code(code):
                return self._gate_failure_response(
                    session_id, "invalid_authorization_code"
                )
            authorized_by = "bootstrap_otp"
        else:
            profile = self._read_profile(approver_id)
            if not profile or not bool(profile.get("is_administrator", False)):
                return {"ok": False, "error": "invalid_approver"}
            if not self._verify_account_code(approver_id, code, consume_recovery=True):
                return self._gate_failure_response(
                    session_id, "invalid_authorization_code"
                )
            authorized_by = f"admin:{approver_id}"

        secret = pyotp.random_base32()
        pending = PendingEnrollment(
            user_sid=gate.user_sid,
            username=gate.username,
            is_administrator=self._identity_admin_for_session(session_id),
            secret=secret,
            authorized_by=authorized_by,
            created_monotonic=time.monotonic(),
        )
        with self.lock:
            self.pending_enrollments[gate.user_sid] = pending
        self.logger.warning(
            "Enrollment authorized for %s (%s) by %s",
            gate.username,
            gate.user_sid,
            authorized_by,
        )
        return {
            "ok": True,
            "authorized": True,
            "provisioning_uri": self._provisioning_uri(pending),
            "manual_key": secret,
        }

    def _complete_enrollment(self, session_id: int, code: str) -> dict[str, Any]:
        with self.lock:
            gate = self.gates.get(session_id)
        if gate is None or gate.kind != "enroll":
            return {"ok": False, "error": "no_enrollment_session"}

        pending = self._pending_enrollment(gate.user_sid)
        if pending is None:
            return {"ok": False, "error": "enrollment_authorization_expired"}
        if pending.failed_attempts >= self.config["max_otp_attempts"]:
            return {"ok": False, "error": "attempt_limit"}
        if not (code.isdigit() and len(code) == 6) or not pyotp.TOTP(
            pending.secret
        ).verify(code, valid_window=1):
            pending.failed_attempts += 1
            return {
                "ok": False,
                "error": "invalid_new_otp",
                "remaining_attempts": max(
                    0,
                    self.config["max_otp_attempts"] - pending.failed_attempts,
                ),
            }

        recovery_codes = [self._new_recovery_code() for _ in range(8)]
        directory = sid_directory(gate.user_sid)
        directory.mkdir(parents=True, exist_ok=True)
        user_secret_path(gate.user_sid).write_bytes(
            protect_machine_secret(pending.secret)
        )
        enrolled_at = self._utc_now_iso()
        atomic_write_json(
            user_recovery_path(gate.user_sid),
            {
                "unused_hashes": [
                    self._hash_recovery_code(item)
                    for item in recovery_codes
                ],
                "generated_at_utc": enrolled_at,
                "generated_by_sid": pending.authorized_by,
                "generated_by_username": pending.authorized_by,
                "version": 1,
            },
        )
        atomic_write_json(
            user_profile_path(gate.user_sid),
            {
                "user_sid": gate.user_sid,
                "username": gate.username,
                "is_administrator": pending.is_administrator,
                "enrolled_at_utc": enrolled_at,
                "authorized_by": pending.authorized_by,
            },
        )
        atomic_write_json(
            user_enrollment_path(gate.user_sid),
            {
                "user_sid": gate.user_sid,
                "username": gate.username,
                "enrolled_at_utc": enrolled_at,
                "authorized_by": pending.authorized_by,
                "recovery_codes_generated_at_utc": enrolled_at,
                "recovery_codes_version": 1,
            },
        )
        self._consume_initial_enrollment_sid(gate.user_sid)
        with self.lock:
            self.pending_enrollments.pop(gate.user_sid, None)
            self.gates.pop(session_id, None)

        self.logger.warning(
            "Per-user OTP enrollment completed for %s (%s)",
            gate.username,
            gate.user_sid,
        )
        return {
            "ok": True,
            "enrolled": True,
            "recovery_codes": recovery_codes,
        }

    def _approve_current_session(
        self,
        *,
        target_session_id: int,
        approver_id: str,
        code: str,
        duration: str,
    ) -> dict[str, Any]:
        mode = str(self.config.get("admin_approval_mode", "inline"))
        if mode not in {"inline", "either"}:
            return {"ok": False, "error": "inline_approval_disabled"}

        with self.lock:
            gate = self.gates.get(target_session_id)

        if gate is None or gate.kind != "approval_wait":
            return {"ok": False, "error": "no_approval_request"}
        if gate.deadline is not None and time.monotonic() >= gate.deadline:
            return {"ok": False, "error": "approval_request_expired"}
        if gate.failed_attempts >= self.config["max_otp_attempts"]:
            return {"ok": False, "error": "attempt_limit"}
        if duration not in self.config["allowed_approval_durations"]:
            return {"ok": False, "error": "duration_not_allowed"}

        approver_id = str(approver_id).strip()
        approver = next(
            (
                item
                for item in self._admin_approvers()
                if str(item.get("id", "")) == approver_id
            ),
            None,
        )
        if approver is None or not self._approver_profile_valid(approver_id):
            return {"ok": False, "error": "approver_not_authorized"}

        if not self._verify_account_code(
            approver_id, code, consume_recovery=True
        ):
            return self._gate_failure_response(
                target_session_id, "invalid_admin_otp"
            )

        approver_name = str(approver.get("label", approver_id))
        grant = self._create_approval_grant(
            gate=gate,
            approver_sid=approver_id,
            approver_name=approver_name,
            duration=duration,
        )
        with self.lock:
            self.gates.pop(target_session_id, None)

        self.logger.warning(
            "Session %s for %s (%s) approved inline by %s (%s), duration=%s",
            target_session_id,
            gate.username,
            gate.user_sid,
            approver_name,
            approver_id,
            duration,
        )
        return {
            "ok": True,
            "approved": True,
            "grant_type": grant.grant_type,
            "expires_at_utc": grant.expires_at_utc,
            "approved_by": approver_name,
        }

    def _approve_session(
        self,
        *,
        admin_session_id: int,
        target_session_id: int,
        code: str,
        duration: str,
    ) -> dict[str, Any]:
        admin_identity = self._session_identity(admin_session_id)
        if (
            admin_identity is None
            or not admin_identity.is_administrator
            or not self._user_is_enrolled(admin_identity.user_sid)
        ):
            return {"ok": False, "error": "admin_session_not_authorized"}

        with self.lock:
            gate = self.gates.get(target_session_id)
        if gate is None or gate.kind != "approval_wait":
            return {"ok": False, "error": "no_approval_request"}
        if gate.deadline is not None and time.monotonic() >= gate.deadline:
            return {"ok": False, "error": "approval_request_expired"}
        if gate.failed_attempts >= self.config["max_otp_attempts"]:
            return {"ok": False, "error": "attempt_limit"}
        if duration not in self.config["allowed_approval_durations"]:
            return {"ok": False, "error": "duration_not_allowed"}
        if not self._verify_account_code(
            admin_identity.user_sid, code, consume_recovery=True
        ):
            return self._gate_failure_response(
                target_session_id, "invalid_admin_otp"
            )

        grant = self._create_approval_grant(
            gate=gate,
            approver_sid=admin_identity.user_sid,
            approver_name=admin_identity.username,
            duration=duration,
        )
        with self.lock:
            self.gates.pop(target_session_id, None)

        self.logger.warning(
            "Session %s for %s (%s) approved from admin session %s by %s (%s), duration=%s",
            target_session_id,
            gate.username,
            gate.user_sid,
            admin_session_id,
            admin_identity.username,
            admin_identity.user_sid,
            duration,
        )
        return {
            "ok": True,
            "approved": True,
            "grant_type": grant.grant_type,
            "expires_at_utc": grant.expires_at_utc,
        }

    def _approval_console_status(
        self, session_id: int
    ) -> dict[str, Any] | None:
        if self.config.get("admin_approval_mode", "inline") not in {
            "admin_session",
            "either",
        }:
            return None
        identity = self._session_identity(session_id)
        if (
            identity is None
            or not identity.is_administrator
            or not self._user_is_enrolled(identity.user_sid)
        ):
            return None
        requests = self._pending_approval_requests()
        if not requests:
            return None
        return {
            "ok": True,
            "required": True,
            "mode": "approval_console",
            "username": identity.username,
            "requests": requests,
            "allowed_durations": self.config["allowed_approval_durations"],
            "default_duration": self.config["default_approval_duration"],
        }

    def _pending_approval_requests(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self.lock:
            gates = list(self.gates.values())
        requests: list[dict[str, Any]] = []
        for gate in gates:
            if gate.kind != "approval_wait":
                continue
            remaining = (
                max(0, int(gate.deadline - now))
                if gate.deadline is not None
                else 0
            )
            requests.append(
                {
                    "session_id": gate.session_id,
                    "username": gate.username,
                    "user_sid": gate.user_sid,
                    "remaining_seconds": remaining,
                    "reason": gate.reason,
                }
            )
        requests.sort(key=lambda item: item["remaining_seconds"])
        return requests

    def _notify_active_admin_sessions(self, target_session_id: int) -> None:
        if self.config.get("admin_approval_mode", "inline") not in {
            "admin_session",
            "either",
        }:
            return
        try:
            for session_id, state in self._enumerate_sessions().items():
                if (
                    session_id <= 0
                    or session_id == target_session_id
                    or state != win32ts.WTSActive
                ):
                    continue
                identity = self._session_identity(session_id)
                if (
                    identity
                    and identity.is_administrator
                    and self._user_is_enrolled(identity.user_sid)
                ):
                    threading.Thread(
                        target=self._ensure_ui_ready,
                        args=(session_id, identity),
                        daemon=True,
                    ).start()
        except Exception:
            self.logger.exception("Could not notify active administrator sessions")

    def _gate_failure_response(
        self, session_id: int, error: str
    ) -> dict[str, Any]:
        with self.lock:
            gate = self.gates.get(session_id)
            if gate is None:
                return {"ok": False, "error": "no_active_gate"}
            gate.failed_attempts += 1
            failed_attempts = int(gate.failed_attempts)
            self.session_failed_attempts[session_id] = failed_attempts
            self.session_last_failure_utc[session_id] = self._utc_now_iso()
            remaining = max(
                0, self.config["max_otp_attempts"] - failed_attempts
            )
        self._append_admin_audit(
            action="gate_credential_failed",
            target_sid=gate.user_sid,
            target_username=gate.username,
            actor_sid=gate.user_sid,
            actor_username=gate.username,
            details={
                "session_id": session_id,
                "kind": gate.kind,
                "reason": gate.reason,
                "error": error,
                "failed_attempts": failed_attempts,
                "remaining_attempts": remaining,
            },
        )
        self.logger.warning(
            "Invalid gate credential: session=%s kind=%s remaining=%s",
            session_id,
            gate.kind,
            remaining,
        )
        if remaining <= 0 and gate.kind != "enroll":
            self._schedule_gate_failure(session_id, trigger="attempt_limit")
        return {
            "ok": False,
            "error": error,
            "remaining_attempts": remaining,
        }

    def _failure_policy_key(self, gate: SessionGate) -> str:
        if gate.kind == "approval_wait":
            return "admin_approval_timeout"
        if gate.kind == "deny":
            return "out_of_scope_deny"
        if gate.reason == "unlock":
            return "unlock"
        if gate.reason == "service_start":
            return "service_start"
        return "logon"

    def _failure_action_for_gate(self, gate: SessionGate) -> str:
        key = self._failure_policy_key(gate)
        return str(self.config["failure_actions"][key])

    def _client_action_payload(
        self, pending: PendingClientAction
    ) -> dict[str, Any]:
        return {
            "request_id": pending.request_id,
            "type": pending.action,
            "policy_key": pending.policy_key,
            "reason": pending.reason,
        }

    def _schedule_gate_failure(self, session_id: int, *, trigger: str) -> None:
        threading.Thread(
            target=self._apply_gate_failure,
            args=(session_id, trigger),
            daemon=True,
        ).start()

    def _apply_gate_failure(self, session_id: int, trigger: str) -> None:
        with self.lock:
            gate = self.gates.get(session_id)
            if gate is None or gate.kind == "enroll":
                return
            if session_id in self.client_actions:
                return
            action = self._failure_action_for_gate(gate)
            policy_key = self._failure_policy_key(gate)
            gate.recovery_active = False
            gate.recovery_deadline = None
            gate.paused_deadline_remaining_seconds = None

        self.logger.error(
            "Gate failure: session=%s user=%s kind=%s reason=%s "
            "trigger=%s policy=%s action=%s",
            session_id,
            gate.username,
            gate.kind,
            gate.reason,
            trigger,
            policy_key,
            action,
        )
        self._append_admin_audit(
            action="verification_failure_action",
            target_sid=gate.user_sid,
            target_username=gate.username,
            actor_sid="",
            actor_username="Windows Login Guard Service",
            details={
                "session_id": session_id,
                "kind": gate.kind,
                "reason": gate.reason,
                "trigger": trigger,
                "policy": policy_key,
                "action": action,
                "failed_attempts": int(gate.failed_attempts),
            },
        )

        if action == "allow":
            self.logger.warning(
                "Fail-open policy allowed session %s (%s)",
                session_id,
                gate.username,
            )
            self._clear_gate(session_id)
            return

        if action == "logoff":
            self._logoff_session(session_id, gate.username)
            return

        if action == "lock":
            pending = PendingClientAction(
                request_id=secrets.token_urlsafe(18),
                action="lock",
                policy_key=policy_key,
                gate_kind=gate.kind,
                reason=gate.reason,
                deadline=(
                    time.monotonic()
                    + int(self.config["lock_action_timeout_seconds"])
                ),
            )
            with self.lock:
                current = self.gates.get(session_id)
                if current is None:
                    return
                current.deadline = None
                self.client_actions[session_id] = pending
            self.logger.warning(
                "Lock command queued for session %s; request=%s",
                session_id,
                pending.request_id,
            )
            return

        self.logger.error("Unsupported failure action %r", action)
        self._logoff_session(session_id, gate.username)

    def _client_action_result(
        self,
        *,
        session_id: int,
        request_id: str,
        success: bool,
        error: str,
    ) -> dict[str, Any]:
        with self.lock:
            pending = self.client_actions.get(session_id)
        if pending is None or not hmac.compare_digest(
            pending.request_id, request_id
        ):
            return {"ok": False, "error": "no_pending_client_action"}

        if success:
            # Keep the command until Windows emits WTS_SESSION_LOCK. The lock
            # event clears both the command and its gate.
            self.logger.info(
                "UI accepted lock command for session %s request=%s",
                session_id,
                request_id,
            )
            return {"ok": True, "accepted": True}

        self.logger.error(
            "UI failed client action for session %s request=%s error=%s",
            session_id,
            request_id,
            error or "unknown",
        )
        self._apply_lock_failure_fallback(session_id, pending)
        return {"ok": False, "error": "client_action_failed"}

    def _apply_lock_failure_fallback(
        self, session_id: int, pending: PendingClientAction
    ) -> None:
        with self.lock:
            current = self.client_actions.get(session_id)
            if current is None or current.request_id != pending.request_id:
                return
            self.client_actions.pop(session_id, None)
            gate = self.gates.get(session_id)

        fallback = str(self.config["lock_failure_action"])
        username = gate.username if gate else f"session-{session_id}"
        self.logger.error(
            "Lock command failed or timed out for session %s; fallback=%s",
            session_id,
            fallback,
        )
        if fallback == "allow":
            self._clear_gate(session_id)
        else:
            self._logoff_session(session_id, username)

    def _logoff_session(self, session_id: int, username: str) -> None:
        try:
            win32ts.WTSLogoffSession(
                win32ts.WTS_CURRENT_SERVER_HANDLE, session_id, False
            )
        except Exception:
            self.logger.exception("Failed to log off session %s", session_id)
        finally:
            with self.lock:
                self.gates.pop(session_id, None)
                self.client_actions.pop(session_id, None)
        self.logger.warning(
            "Windows logoff initiated for session %s (%s)",
            session_id,
            username,
        )

    def _queue_evaluation(self, session_id: int, *, reason: str, replace: bool) -> None:
        if session_id <= 0 or self.stop_requested.is_set():
            return
        with self.lock:
            if session_id in self.challenge_jobs:
                return
            self.challenge_jobs.add(session_id)
        threading.Thread(
            target=self._evaluate_session,
            args=(session_id, reason, replace),
            daemon=True,
        ).start()

    def _evaluate_session(self, session_id: int, reason: str, replace: bool) -> None:
        try:
            identity = self._session_identity(session_id)
            if identity is None:
                return

            maintenance = self._maintenance_state()
            if maintenance.get("enabled"):
                self._clear_gate(session_id)
                self.logger.critical(
                    "OTP enforcement bypassed by maintenance mode: "
                    "session=%s user=%s enabled_by=%s reason=%s",
                    session_id,
                    identity.username,
                    maintenance.get("enabled_by", ""),
                    maintenance.get("reason", ""),
                )
                return

            with self.lock:
                recovery_bypass = (
                    session_id in self.recovery_session_bypasses
                )
            if recovery_bypass:
                self._clear_gate(session_id)
                self.logger.warning(
                    "OTP enforcement bypassed for recovered session %s (%s)",
                    session_id,
                    identity.username,
                )
                return

            self._refresh_profile(identity)

            # An enrolled administrator may need an approval console even when
            # that administrator is outside protection_scope and otherwise
            # allowed without a gate. Launch the authenticated UI whenever a
            # pending request exists. Approval still requires the admin's own
            # per-user OTP.
            if (
                identity.is_administrator
                and self._user_is_enrolled(identity.user_sid)
                and self._pending_approval_requests()
            ):
                self._ensure_ui_ready(session_id, identity)

            if identity.user_sid in set(self.config["excluded_user_sids"]):
                self._clear_gate(session_id)
                self.logger.info(
                    "Session %s (%s) is excluded from Login Guard",
                    session_id,
                    identity.username,
                )
                return

            if self._identity_in_scope(identity):
                if self._user_is_enrolled(identity.user_sid):
                    self._set_gate(
                        identity,
                        kind="verify",
                        reason=reason,
                        timeout=self.config["timeout_seconds"],
                        replace=replace,
                    )
                else:
                    # Enrollment is non-destructive: no countdown and no logoff
                    # until this user has scanned and tested their own OTP.
                    self._set_gate(
                        identity,
                        kind="enroll",
                        reason=reason,
                        timeout=None,
                        replace=True,
                    )

                # The gate must exist before UI readiness is awaited. The UI's
                # first status poll then sees required=True immediately and can
                # switch to the isolated desktop without exposing the normal
                # desktop for the readiness round trip.
                if not self._ensure_ui_ready(session_id, identity):
                    self._clear_gate(session_id)
                    self.logger.error(
                        "UI unavailable for protected session %s (%s); fail-open",
                        session_id,
                        identity.username,
                    )
                    return
                return

            policy = self.config["out_of_scope_policy"]
            if policy == "allow":
                self._clear_gate(session_id)
                return

            if policy == "require_admin_approval":
                if self._approval_grant_valid(identity):
                    self._clear_gate(session_id)
                    return
                if not self._admin_approvers():
                    fallback = self.config["no_approver_policy"]
                    self.logger.error(
                        "No enrolled administrator can approve %s; fallback=%s",
                        identity.username,
                        fallback,
                    )
                    if fallback == "allow":
                        self._clear_gate(session_id)
                        return
                    policy = "deny"
                else:
                    self._set_gate(
                        identity,
                        kind="approval_wait",
                        reason=reason,
                        timeout=self.config["approval_timeout_seconds"],
                        replace=replace,
                    )
                    if not self._ensure_ui_ready(session_id, identity):
                        self._clear_gate(session_id)
                        self.logger.error(
                            "Approval UI unavailable for session %s; fail-open",
                            session_id,
                        )
                        return
                    self._notify_active_admin_sessions(identity.session_id)
                    return

            if policy == "deny":
                self._set_gate(
                    identity,
                    kind="deny",
                    reason=reason,
                    timeout=self.config["approval_timeout_seconds"],
                    replace=replace,
                )
                if not self._ensure_ui_ready(session_id, identity):
                    self._clear_gate(session_id)
                    self.logger.error(
                        "Deny UI unavailable for session %s; fail-open",
                        session_id,
                    )
                    return
        except Exception:
            self.logger.exception("Session evaluation failed for %s", session_id)
            self._clear_gate(session_id)
        finally:
            with self.lock:
                self.challenge_jobs.discard(session_id)

    def _set_gate(
        self,
        identity: SessionIdentity,
        *,
        kind: str,
        reason: str,
        timeout: int | None,
        replace: bool,
    ) -> None:
        with self.lock:
            existing = self.gates.get(identity.session_id)
            if existing and not replace and existing.kind == kind:
                if existing.deadline is None or existing.deadline > time.monotonic():
                    return
            now = time.monotonic()
            timeout_seconds = None if timeout is None else int(timeout)
            isolated = (
                self.config.get("interaction_mode") == "isolated_desktop"
            )
            if isolated and timeout_seconds is not None:
                deadline = None
                activation_deadline = (
                    now
                    + int(
                        self.config[
                            "isolated_desktop_start_timeout_seconds"
                        ]
                    )
                )
            else:
                deadline = (
                    None
                    if timeout_seconds is None
                    else now + timeout_seconds
                )
                activation_deadline = None

            self.gates[identity.session_id] = SessionGate(
                session_id=identity.session_id,
                username=identity.username,
                user_sid=identity.user_sid,
                kind=kind,
                reason=reason,
                deadline=deadline,
                timeout_seconds=timeout_seconds,
                activation_deadline=activation_deadline,
            )
            self.session_failed_attempts[identity.session_id] = 0
            self.session_last_failure_utc.pop(identity.session_id, None)
        self._append_admin_audit(
            action="verification_challenge_started",
            target_sid=identity.user_sid,
            target_username=identity.username,
            actor_sid="",
            actor_username="Windows Login Guard Service",
            details={
                "session_id": identity.session_id,
                "kind": kind,
                "reason": reason,
                "timeout_seconds": timeout,
            },
        )
        self.logger.warning(
            "Session gate created: session=%s user=%s sid=%s kind=%s reason=%s timeout=%s",
            identity.session_id,
            identity.username,
            identity.user_sid,
            kind,
            reason,
            timeout,
        )

    def _clear_gate(self, session_id: int) -> None:
        with self.lock:
            self.gates.pop(session_id, None)

    def _ui_is_ready(self, session_id: int) -> bool:
        with self.lock:
            last_seen = self.ui_last_seen.get(session_id)
        if last_seen is None:
            return False
        seen_at, desktop_available = last_seen
        return desktop_available and (time.monotonic() - seen_at) <= 3.0

    def _ensure_ui_ready(self, session_id: int, identity: SessionIdentity) -> bool:
        launch_lock = self._get_ui_launch_lock(session_id)
        with launch_lock:
            return self._ensure_ui_ready_serial(session_id, identity)

    def _get_ui_launch_lock(self, session_id: int) -> threading.Lock:
        with self.lock:
            return self.ui_launch_locks.setdefault(session_id, threading.Lock())

    def _ensure_ui_ready_serial(
        self, session_id: int, identity: SessionIdentity
    ) -> bool:
        if self._ui_is_ready(session_id):
            return True

        timeout = int(self.config["ui_ready_timeout_seconds"])
        retries = int(self.config["ui_launch_retries"])
        event = self._get_ui_ready_event(session_id)

        # On unlock, the existing authenticated UI usually reports that the
        # default desktop is visible within one polling interval. Wait briefly
        # before rotating its token and starting a replacement process.
        with self.lock:
            has_existing_token = session_id in self.ui_tokens
        if has_existing_token:
            event.clear()
            if event.wait(timeout=min(2, timeout)) and self._ui_is_ready(session_id):
                return True

        for attempt in range(retries + 1):
            if self.stop_requested.is_set():
                return False
            event.clear()
            token = secrets.token_urlsafe(32)
            with self.lock:
                self.ui_tokens[session_id] = token
                self.ui_last_seen.pop(session_id, None)
            launched = self._launch_ui_in_session(session_id, identity, token)
            if launched and event.wait(timeout=timeout) and self._ui_is_ready(session_id):
                self.logger.info(
                    "UI ready on visible desktop for session %s (%s)",
                    session_id,
                    identity.username,
                )
                return True
            self.logger.warning(
                "UI readiness timeout for session %s (%s), attempt %s/%s",
                session_id,
                identity.username,
                attempt + 1,
                retries + 1,
            )
        return False

    def _get_ui_ready_event(self, session_id: int) -> threading.Event:
        with self.lock:
            return self.ui_ready_events.setdefault(session_id, threading.Event())

    def _launch_ui_in_session(
        self, session_id: int, identity: SessionIdentity, token_value: str
    ) -> bool:
        install_dir = Path(__file__).resolve().parent
        ui_script = install_dir / "ui.pyw"
        pythonw_exe = Path(sys.executable).resolve().with_name("pythonw.exe")
        if not ui_script.exists() or not pythonw_exe.exists():
            self.logger.error("UI runtime missing: %s / %s", ui_script, pythonw_exe)
            return False

        token_handle = None
        environment = None
        process_handle = None
        thread_handle = None
        try:
            token_handle = win32ts.WTSQueryUserToken(session_id)
            environment = win32profile.CreateEnvironmentBlock(token_handle, False)
            startup = win32process.STARTUPINFO()
            startup.lpDesktop = r"winsta0\default"
            command_line = subprocess.list2cmdline(
                [
                    str(pythonw_exe),
                    str(ui_script),
                    "--session-id",
                    str(session_id),
                    "--token",
                    token_value,
                ]
            )
            process_handle, thread_handle, process_id, _thread_id = (
                win32process.CreateProcessAsUser(
                    token_handle,
                    str(pythonw_exe),
                    command_line,
                    None,
                    None,
                    False,
                    win32con.CREATE_UNICODE_ENVIRONMENT,
                    environment,
                    str(install_dir),
                    startup,
                )
            )
            self.logger.info(
                "Started authenticated UI pid=%s in session %s (%s)",
                process_id,
                session_id,
                identity.username,
            )
            return True
        except Exception:
            self.logger.exception(
                "Failed to launch UI in session %s (%s)",
                session_id,
                identity.username,
            )
            return False
        finally:
            for handle in (thread_handle, process_handle, token_handle):
                if handle is not None:
                    try:
                        handle.Close()
                    except Exception:
                        pass

    def _identity_in_scope(self, identity: SessionIdentity) -> bool:
        scope = self.config["protection_scope"]
        if scope == "all_users":
            return True
        if scope == "administrators":
            return identity.is_administrator
        if scope == "installer_user":
            return identity.user_sid == self.config["installer_user_sid"]
        raise RuntimeError(f"Unsupported protection scope: {scope}")

    def _session_identity(self, session_id: int) -> SessionIdentity | None:
        username = self._query_session_text(session_id, win32ts.WTSUserName)
        if not username:
            return None
        domain = self._query_session_text(session_id, win32ts.WTSDomainName)
        display_name = f"{domain}\\{username}" if domain else username

        token = win32ts.WTSQueryUserToken(session_id)
        try:
            token_user = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )
            user_sid_object = token_user[0] if isinstance(token_user, tuple) else token_user
            user_sid = win32security.ConvertSidToStringSid(user_sid_object)
            token_groups = win32security.GetTokenInformation(
                token, win32security.TokenGroups
            )
            group_sids = {
                win32security.ConvertSidToStringSid(group[0]) for group in token_groups
            }
            is_administrator = "S-1-5-32-544" in group_sids
        finally:
            token.Close()

        return SessionIdentity(
            session_id=session_id,
            username=display_name,
            user_sid=user_sid,
            is_administrator=is_administrator,
        )

    def _identity_admin_for_session(self, session_id: int) -> bool:
        identity = self._session_identity(session_id)
        return bool(identity and identity.is_administrator)

    def _query_session_text(self, session_id: int, info_class: int) -> str:
        value = win32ts.WTSQuerySessionInformation(
            win32ts.WTS_CURRENT_SERVER_HANDLE, session_id, info_class
        )
        return str(value).strip() if value is not None else ""

    def _evaluate_active_sessions_on_start(self) -> None:
        if self.stop_requested.wait(1.0):
            return
        try:
            for session_id, state in self._enumerate_sessions().items():
                if session_id > 0 and state == win32ts.WTSActive:
                    self._queue_evaluation(
                        session_id, reason="service_start", replace=True
                    )
        except Exception:
            self.logger.exception("Service-start session evaluation failed")

    def _monitor(self) -> None:
        self.last_states = self._enumerate_sessions()
        interval = float(self.config["poll_interval_seconds"])
        while not self.stop_requested.wait(interval):
            try:
                current = self._enumerate_sessions()
                if self.config["verify_on_logon"]:
                    for session_id, state in current.items():
                        if (
                            session_id > 0
                            and state == win32ts.WTSActive
                            and session_id not in self.last_states
                        ):
                            self._queue_evaluation(
                                session_id,
                                reason="new_session_fallback",
                                replace=False,
                            )
                self._enforce_deadlines(current)
                self._enforce_client_action_deadlines(current)
                self._expire_pending_enrollments()
                self._expire_timed_grants()
                self.last_states = current
            except Exception:
                self.logger.exception("Session monitor iteration failed")

    def _enumerate_sessions(self) -> dict[int, int]:
        return {
            int(item["SessionId"]): int(item["State"])
            for item in win32ts.WTSEnumerateSessions(
                win32ts.WTS_CURRENT_SERVER_HANDLE, 1, 0
            )
        }

    def _enforce_deadlines(self, current: dict[int, int]) -> None:
        with self.lock:
            gates = list(self.gates.items())
        now = time.monotonic()
        for session_id, gate in gates:
            if session_id not in current:
                self._clear_gate(session_id)
                with self.lock:
                    self.client_actions.pop(session_id, None)
                    self.session_failed_attempts.pop(session_id, None)
                    self.session_last_failure_utc.pop(session_id, None)
                continue

            if gate.recovery_active:
                if (
                    gate.recovery_deadline is not None
                    and now >= gate.recovery_deadline
                ):
                    with self.lock:
                        current_gate = self.gates.get(session_id)
                        if current_gate is not None:
                            current_gate.recovery_active = False
                            current_gate.recovery_deadline = None
                            current_gate.paused_deadline_remaining_seconds = None
                    self._apply_gate_failure(
                        session_id,
                        trigger="recovery_timeout",
                    )
                continue

            if (
                gate.activation_deadline is not None
                and now >= gate.activation_deadline
            ):
                if gate.kind == "enroll":
                    # Enrollment remains non-destructive.
                    gate.activation_deadline = None
                    continue
                self.logger.error(
                    "Isolated desktop did not become ready for session %s "
                    "(%s) before the startup deadline",
                    session_id,
                    gate.username,
                )
                self._apply_gate_failure(
                    session_id,
                    trigger="isolated_desktop_start_timeout",
                )
                continue

            if gate.deadline is None or now < gate.deadline:
                continue
            if gate.kind == "enroll":
                # Enrollment is explicitly non-destructive.
                continue
            self._apply_gate_failure(session_id, trigger="timeout")

    def _enforce_client_action_deadlines(
        self, current: dict[int, int]
    ) -> None:
        now = time.monotonic()
        with self.lock:
            pending_items = list(self.client_actions.items())
        for session_id, pending in pending_items:
            if session_id not in current:
                with self.lock:
                    self.client_actions.pop(session_id, None)
                    self.gates.pop(session_id, None)
                continue
            if now >= pending.deadline:
                self._apply_lock_failure_fallback(session_id, pending)

    def _user_is_enrolled(self, user_sid: str) -> bool:
        return user_secret_path(user_sid).exists() and user_profile_path(user_sid).exists()

    def _read_profile(self, user_sid: str) -> dict[str, Any] | None:
        path = user_profile_path(user_sid)
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
            return value if isinstance(value, dict) else None
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def _refresh_profile(self, identity: SessionIdentity) -> None:
        profile = self._read_profile(identity.user_sid)
        if not profile:
            return
        changed = False
        if profile.get("username") != identity.username:
            profile["username"] = identity.username
            changed = True
        if bool(profile.get("is_administrator", False)) != identity.is_administrator:
            profile["is_administrator"] = identity.is_administrator
            changed = True
        if changed:
            profile["last_refreshed_at_utc"] = self._utc_now_iso()
            atomic_write_json(user_profile_path(identity.user_sid), profile)

    def _verify_account_code(
        self, user_sid: str, code: str, *, consume_recovery: bool
    ) -> bool:
        if code.isdigit() and len(code) == 6:
            try:
                secret = unprotect_machine_secret(
                    user_secret_path(user_sid).read_bytes()
                )
            except OSError:
                return False
            if pyotp.TOTP(secret).verify(code, valid_window=1):
                return True
        return consume_recovery and self._consume_user_recovery_code(user_sid, code)

    def _consume_user_recovery_code(self, user_sid: str, code: str) -> bool:
        normalized = code.replace("-", "").strip().upper()
        if len(normalized) != 12:
            return False
        path = user_recovery_path(user_sid)
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            hashes = list(data.get("unused_hashes", []))
        except (OSError, json.JSONDecodeError):
            return False
        code_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        if code_hash not in hashes:
            return False
        hashes.remove(code_hash)
        data["unused_hashes"] = hashes
        atomic_write_json(path, data)
        self.logger.warning("A recovery code was consumed for SID %s", user_sid)
        return True

    def _verify_bootstrap_code(self, code: str) -> bool:
        if not (code.isdigit() and len(code) == 6 and BOOTSTRAP_SECRET_PATH.exists()):
            return False
        try:
            secret = unprotect_machine_secret(BOOTSTRAP_SECRET_PATH.read_bytes())
        except OSError:
            return False
        return bool(pyotp.TOTP(secret).verify(code, valid_window=1))

    def _pending_enrollment(self, user_sid: str) -> PendingEnrollment | None:
        with self.lock:
            pending = self.pending_enrollments.get(user_sid)
        if pending is None:
            return None
        if (
            time.monotonic() - pending.created_monotonic
            > self.config["enrollment_session_timeout_seconds"]
        ):
            with self.lock:
                self.pending_enrollments.pop(user_sid, None)
            return None
        return pending

    def _expire_pending_enrollments(self) -> None:
        with self.lock:
            user_sids = list(self.pending_enrollments)
        for user_sid in user_sids:
            self._pending_enrollment(user_sid)

    def _provisioning_uri(self, pending: PendingEnrollment) -> str:
        return pyotp.TOTP(pending.secret).provisioning_uri(
            name=pending.username,
            issuer_name=self.config["issuer"],
        )

    def _initial_enrollment_allowed(self, user_sid: str) -> bool:
        return user_sid in set(self.config.get("initial_enrollment_sids", []))

    def _consume_initial_enrollment_sid(self, user_sid: str) -> None:
        sids = list(self.config.get("initial_enrollment_sids", []))
        if user_sid not in sids:
            return
        sids.remove(user_sid)
        self.config["initial_enrollment_sids"] = sids
        atomic_write_json(CONFIG_PATH, self.config)

    def _enrollment_approvers(self) -> list[dict[str, str]]:
        values = self._admin_approvers()
        if self.config["allow_bootstrap_enrollment"] and BOOTSTRAP_SECRET_PATH.exists():
            values.append(
                {
                    "id": "__bootstrap__",
                    "label": "Existing shared/bootstrap authenticator",
                }
            )
        return values

    def _admin_approvers(self) -> list[dict[str, str]]:
        approvers: list[dict[str, str]] = []
        if not USERS_DIR.exists():
            return approvers
        for profile_path in USERS_DIR.glob("S-*/profile.json"):
            try:
                profile = json.loads(profile_path.read_text(encoding="utf-8-sig"))
                sid = str(profile.get("user_sid", profile_path.parent.name))
                if (
                    bool(profile.get("is_administrator", False))
                    and user_secret_path(sid).exists()
                ):
                    approvers.append(
                        {"id": sid, "label": str(profile.get("username", sid))}
                    )
            except (OSError, json.JSONDecodeError, ValueError):
                continue
        approvers.sort(key=lambda item: item["label"].lower())
        return approvers

    def _new_recovery_code(self) -> str:
        alphabet = string.ascii_uppercase + string.digits
        raw = "".join(secrets.choice(alphabet) for _ in range(12))
        return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"

    def _hash_recovery_code(self, code: str) -> str:
        return hashlib.sha256(
            code.replace("-", "").upper().encode("utf-8")
        ).hexdigest()

    def _create_approval_grant(
        self,
        *,
        gate: SessionGate,
        approver_sid: str,
        approver_name: str,
        duration: str,
    ) -> ApprovalGrant:
        now = datetime.now(timezone.utc)
        expires_at: datetime | None = None
        session_id: int | None = None
        if duration in {"until_lock", "session"}:
            session_id = gate.session_id
        elif duration in DURATION_SECONDS:
            expires_at = datetime.fromtimestamp(
                now.timestamp() + DURATION_SECONDS[duration], timezone.utc
            )

        grant = ApprovalGrant(
            target_user_sid=gate.user_sid,
            target_username=gate.username,
            approved_by_sid=approver_sid,
            approved_by_name=approver_name,
            grant_type=duration,
            session_id=session_id,
            created_at_utc=now.isoformat(),
            expires_at_utc=expires_at.isoformat() if expires_at else None,
        )
        with self.lock:
            if duration in {"until_lock", "session"}:
                self.session_grants[gate.session_id] = grant
            elif duration in DURATION_SECONDS:
                self.timed_grants[gate.user_sid] = grant
                self._persist_timed_grants_locked()
        return grant

    def _approval_grant_valid(self, identity: SessionIdentity) -> bool:
        now = datetime.now(timezone.utc)
        with self.lock:
            session_grant = self.session_grants.get(identity.session_id)
            if session_grant and session_grant.target_user_sid == identity.user_sid:
                if self._approver_profile_valid(session_grant.approved_by_sid):
                    return True
                self.session_grants.pop(identity.session_id, None)

            timed = self.timed_grants.get(identity.user_sid)
            if timed and timed.expires_at_utc:
                try:
                    expiry = datetime.fromisoformat(timed.expires_at_utc)
                except ValueError:
                    expiry = now
                if expiry > now and self._approver_profile_valid(
                    timed.approved_by_sid
                ):
                    return True
                self.timed_grants.pop(identity.user_sid, None)
                self._persist_timed_grants_locked()
        return False

    def _approver_profile_valid(self, user_sid: str) -> bool:
        profile = self._read_profile(user_sid)
        return bool(
            profile
            and profile.get("is_administrator", False)
            and user_secret_path(user_sid).exists()
        )

    def _invalidate_until_lock_grant(self, session_id: int) -> None:
        with self.lock:
            grant = self.session_grants.get(session_id)
            if grant and grant.grant_type == "until_lock":
                self.session_grants.pop(session_id, None)
                self.logger.info("Until-lock approval expired for session %s", session_id)

    def _load_timed_grants(self) -> None:
        self.timed_grants = {}
        try:
            values = json.loads(APPROVALS_PATH.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(values, list):
            return
        now = datetime.now(timezone.utc)
        for item in values:
            try:
                grant = ApprovalGrant(**item)
                if grant.expires_at_utc and datetime.fromisoformat(
                    grant.expires_at_utc
                ) > now:
                    self.timed_grants[grant.target_user_sid] = grant
            except (TypeError, ValueError):
                continue

    def _expire_timed_grants(self) -> None:
        now = datetime.now(timezone.utc)
        expired_sids: set[str] = set()
        with self.lock:
            for sid, grant in list(self.timed_grants.items()):
                try:
                    expiry = datetime.fromisoformat(grant.expires_at_utc or "")
                except ValueError:
                    expiry = now
                if expiry <= now:
                    self.timed_grants.pop(sid, None)
                    expired_sids.add(sid)
            if expired_sids:
                self._persist_timed_grants_locked()

        # A time-limited approval is an access lease, not just a cache entry.
        # When it expires while the user is still signed in, reevaluate that
        # active session and require a new approval rather than waiting for the
        # next lock or logon event.
        if not expired_sids:
            return
        try:
            for session_id, state in self._enumerate_sessions().items():
                if session_id <= 0 or state != win32ts.WTSActive:
                    continue
                identity = self._session_identity(session_id)
                if identity and identity.user_sid in expired_sids:
                    self._queue_evaluation(
                        session_id, reason="approval_expired", replace=True
                    )
        except Exception:
            self.logger.exception("Could not reevaluate expired approval grants")

    def _persist_timed_grants_locked(self) -> None:
        atomic_write_json(
            APPROVALS_PATH,
            [grant.__dict__ for grant in self.timed_grants.values()],
        )

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(LoginGuardService)
