from __future__ import annotations

import argparse
from collections.abc import Iterator
from contextlib import contextmanager
import json
import logging
import os
import secrets
import shutil
import socket
import sqlite3
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pyotp
import win32event
import win32service
import win32serviceutil

from remote_common import (
    MAX_AUDIT_RECORDS,
    MAX_JSON_BYTES,
    MAX_LOG_TEXT_BYTES,
    REMOTE_ADMIN_CERT,
    REMOTE_ADMIN_CONFIG,
    REMOTE_ADMIN_DATA,
    REMOTE_ADMIN_TOKEN,
    REMOTE_API_VERSION,
    REMOTE_SERVER_CONFIG,
    REMOTE_SERVER_DATA,
    REMOTE_SERVER_DB,
    REMOTE_SERVER_LOG,
    REMOTE_SERVER_SECURE,
    REMOTE_SERVER_SERVICE,
    WLG_USERS,
    atomic_write_json,
    decode_machine_secret,
    encode_machine_secret,
    new_token,
    parse_utc,
    protect_user_text,
    read_json,
    safe_text,
    sha256_token,
    sign_remote_command,
    truncate_utf8,
    unprotect_machine_text,
    utc_now_iso,
    validate_server_url,
)

APP_VERSION = Path(__file__).with_name("VERSION").read_text(
    encoding="utf-8"
).strip()


def default_server_config() -> dict[str, Any]:
    return {
        "bind_address": "0.0.0.0",
        "port": 8443,
        "tls_cert_path": str(REMOTE_SERVER_SECURE / "server.crt"),
        "tls_key_path": str(REMOTE_SERVER_SECURE / "server.key"),
        "allow_insecure_http": False,
        "database_path": str(REMOTE_SERVER_DB),
        "admin_session_hours": 8,
        "offline_after_seconds": 45,
        "maximum_sync_age_seconds": 300,
    }


def load_server_config() -> dict[str, Any]:
    config = default_server_config()
    stored = read_json(REMOTE_SERVER_CONFIG, {})
    if isinstance(stored, dict):
        config.update(stored)

    port = config.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not isinstance(config.get("allow_insecure_http"), bool):
        raise ValueError("allow_insecure_http must be true or false")
    session_hours = config.get("admin_session_hours")
    if (
        isinstance(session_hours, bool)
        or not isinstance(session_hours, int)
        or not 1 <= session_hours <= 24
    ):
        raise ValueError("admin_session_hours must be between 1 and 24")
    return config


@contextmanager
def db_connect(
    config: dict[str, Any],
) -> Iterator[sqlite3.Connection]:
    database_path = Path(str(config["database_path"]))
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=30)
    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def _table_columns(
    db: sqlite3.Connection,
    table_name: str,
) -> set[str]:
    return {
        str(row["name"])
        for row in db.execute(f"PRAGMA table_info({table_name})").fetchall()
    }


def _ensure_column(
    db: sqlite3.Connection,
    table_name: str,
    column_name: str,
    declaration: str,
) -> None:
    if column_name not in _table_columns(db, table_name):
        db.execute(
            f"ALTER TABLE {table_name} ADD COLUMN "
            f"{column_name} {declaration}"
        )


def initialize_database(config: dict[str, Any]) -> None:
    with db_connect(config) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                totp_secret_dpapi TEXT NOT NULL,
                auth_source TEXT NOT NULL DEFAULT 'server_totp',
                windows_sid TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_utc TEXT NOT NULL,
                last_login_utc TEXT
            );

            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL CHECK(kind IN ('device', 'workstation')),
                token_hash TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL,
                created_utc TEXT NOT NULL,
                expires_utc TEXT NOT NULL,
                used_utc TEXT,
                used_by TEXT
            );

            CREATE TABLE IF NOT EXISTS workstations (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_utc TEXT NOT NULL,
                last_seen_utc TEXT,
                revoked_utc TEXT,
                remote_address TEXT,
                is_local_server INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash TEXT PRIMARY KEY,
                admin_id INTEGER NOT NULL REFERENCES admins(id),
                workstation_id TEXT NOT NULL REFERENCES workstations(id),
                created_utc TEXT NOT NULL,
                expires_utc TEXT NOT NULL,
                last_seen_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                display_name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                registered_utc TEXT NOT NULL,
                last_seen_utc TEXT,
                remote_address TEXT,
                endpoint_version TEXT,
                operating_system TEXT,
                dashboard_json TEXT NOT NULL DEFAULT '{}',
                sessions_json TEXT NOT NULL DEFAULT '[]',
                diagnostics_json TEXT NOT NULL DEFAULT '{}',
                audit_json TEXT NOT NULL DEFAULT '[]',
                logs_text TEXT NOT NULL DEFAULT '',
                agent_status TEXT NOT NULL DEFAULT 'registered',
                last_error TEXT NOT NULL DEFAULT '',
                revoked_utc TEXT
            );

            CREATE TABLE IF NOT EXISTS approval_requests (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL REFERENCES devices(id)
                    ON DELETE CASCADE,
                challenge_id TEXT NOT NULL,
                session_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                user_sid TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_utc TEXT NOT NULL,
                expires_utc TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                decision_utc TEXT,
                decided_by_admin_id INTEGER REFERENCES admins(id),
                decided_by_username TEXT,
                duration TEXT,
                allowed_durations_json TEXT NOT NULL DEFAULT '[]',
                default_duration TEXT NOT NULL DEFAULT 'session',
                command_id TEXT,
                command_type TEXT,
                command_json TEXT,
                command_signature TEXT,
                command_delivered_utc TEXT,
                completed_utc TEXT,
                result_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(device_id, challenge_id)
            );

            CREATE INDEX IF NOT EXISTS idx_approval_requests_device_status
                ON approval_requests(device_id, status);
            CREATE INDEX IF NOT EXISTS idx_approval_requests_expires
                ON approval_requests(expires_utc);

            CREATE TABLE IF NOT EXISTS device_actions (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL REFERENCES devices(id)
                    ON DELETE CASCADE,
                action_type TEXT NOT NULL,
                session_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                user_sid TEXT NOT NULL,
                requested_utc TEXT NOT NULL,
                expires_utc TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending_delivery',
                requested_by_admin_id INTEGER REFERENCES admins(id),
                requested_by_username TEXT NOT NULL,
                command_id TEXT NOT NULL UNIQUE,
                command_json TEXT NOT NULL,
                command_signature TEXT NOT NULL,
                delivered_utc TEXT,
                completed_utc TEXT,
                result_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_device_actions_device_status
                ON device_actions(device_id, status);
            CREATE INDEX IF NOT EXISTS idx_device_actions_expires
                ON device_actions(expires_utc);

            CREATE TABLE IF NOT EXISTS central_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                action TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                remote_address TEXT,
                details_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_devices_last_seen
                ON devices(last_seen_utc);
            CREATE INDEX IF NOT EXISTS idx_central_audit_timestamp
                ON central_audit(timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_enrollment_token_hash
                ON enrollment_tokens(token_hash);
            """
        )
        _ensure_column(
            db,
            "admins",
            "auth_source",
            "TEXT NOT NULL DEFAULT 'server_totp'",
        )
        _ensure_column(db, "admins", "windows_sid", "TEXT")
        _ensure_column(
            db,
            "workstations",
            "is_local_server",
            "INTEGER NOT NULL DEFAULT 0",
        )
        _ensure_column(
            db,
            "devices",
            "machine_identity",
            "TEXT",
        )
        _ensure_column(
            db,
            "devices",
            "command_secret_dpapi",
            "TEXT",
        )
        _ensure_column(
            db,
            "devices",
            "command_channel_ready",
            "INTEGER NOT NULL DEFAULT 0",
        )
        db.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_machine_identity
            ON devices(machine_identity)
            WHERE machine_identity IS NOT NULL
              AND machine_identity <> ''
            """
        )
        db.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_windows_sid
            ON admins(windows_sid)
            WHERE windows_sid IS NOT NULL AND windows_sid <> ''
            """
        )


def _local_wlg_admin_profile(windows_sid: str) -> dict[str, Any]:
    sid = safe_text(windows_sid, 200)
    if not sid.startswith("S-") or any(
        character not in "S-0123456789" for character in sid
    ):
        raise ValueError("The current Windows account SID is invalid")

    profile_path = WLG_USERS / sid / "profile.json"
    secret_path = WLG_USERS / sid / "secret.dpapi"
    if not profile_path.is_file() or not secret_path.is_file():
        raise ValueError(
            "The current Windows account is not enrolled in Windows Login Guard"
        )

    profile = read_json(profile_path, {})
    if not isinstance(profile, dict):
        raise ValueError("The local Windows Login Guard profile is invalid")
    if not bool(profile.get("is_administrator", False)):
        raise ValueError(
            "The current Windows Login Guard account is not an administrator"
        )

    username = safe_text(profile.get("username"), 200)
    if not username:
        raise ValueError("The local Windows Login Guard profile has no username")
    return {**profile, "username": username, "windows_sid": sid}


def _verify_local_wlg_admin_otp(windows_sid: str, otp: str) -> bool:
    code = safe_text(otp, 20).replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    try:
        profile = _local_wlg_admin_profile(windows_sid)
        secret_path = WLG_USERS / str(profile["windows_sid"]) / "secret.dpapi"
        secret = unprotect_machine_text(secret_path.read_bytes())
        return bool(pyotp.TOTP(secret).verify(code, valid_window=1))
    except Exception:
        return False


def central_audit(
    config: dict[str, Any],
    *,
    action: str,
    actor_type: str,
    actor_id: str,
    target_type: str = "",
    target_id: str = "",
    remote_address: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    with db_connect(config) as db:
        db.execute(
            """
            INSERT INTO central_audit (
                timestamp_utc, action, actor_type, actor_id,
                target_type, target_id, remote_address, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                safe_text(action, 100),
                safe_text(actor_type, 50),
                safe_text(actor_id, 200),
                safe_text(target_type, 50),
                safe_text(target_id, 200),
                safe_text(remote_address, 100),
                json.dumps(details or {}, sort_keys=True),
            ),
        )


def bearer_token(headers: Any) -> str:
    value = str(headers.get("Authorization", ""))
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return ""


def row_json(row: sqlite3.Row, key: str, default: Any) -> Any:
    try:
        value = json.loads(str(row[key]))
    except (KeyError, TypeError, json.JSONDecodeError):
        return default
    return value


def is_recent(timestamp_utc: str | None, seconds: int) -> bool:
    if not timestamp_utc:
        return False
    try:
        age = datetime.now(timezone.utc) - parse_utc(timestamp_utc)
    except ValueError:
        return False
    return age.total_seconds() <= seconds


class ManagementServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: dict[str, Any], logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.auth_lock = threading.Lock()
        self.login_failures: dict[str, list[float]] = {}
        super().__init__(
            (str(config["bind_address"]), int(config["port"])),
            ManagementRequestHandler,
        )


class ManagementRequestHandler(BaseHTTPRequestHandler):
    server: ManagementServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format_string: str, *args: Any) -> None:
        self.server.logger.info(
            "%s - %s", self.client_address[0], format_string % args
        )

    @property
    def remote_address(self) -> str:
        return safe_text(self.client_address[0], 100)

    def _json_response(
        self,
        status: int,
        payload: dict[str, Any],
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header(
                "Strict-Transport-Security",
                "max-age=31536000",
            )
        self.end_headers()
        self.wfile.write(body)

    def _html_response(
        self,
        status: int,
        document: str,
    ) -> None:
        body = document.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'",
        )
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header(
                "Strict-Transport-Security",
                "max-age=31536000",
            )
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length <= 0 or length > MAX_JSON_BYTES:
            raise ValueError("Request body is empty or too large")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object")
        return value

    def _route_error(self, exc: Exception) -> None:
        self.server.logger.exception("Remote API request failed")
        self._json_response(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            {
                "ok": False,
                "error": "server_error",
                "message": "The management server encountered an internal error.",
            },
        )

    def _registered_workstation(self) -> sqlite3.Row | None:
        token = safe_text(
            self.headers.get("X-WLG-Workstation-Token", ""),
            1000,
        )
        if not token:
            return None

        with db_connect(self.server.config) as db:
            row = db.execute(
                """
                SELECT * FROM workstations
                WHERE token_hash = ? AND revoked_utc IS NULL
                """,
                (sha256_token(token),),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                """
                UPDATE workstations
                SET last_seen_utc = ?, remote_address = ?
                WHERE id = ?
                """,
                (
                    utc_now_iso(),
                    self.remote_address,
                    row["id"],
                ),
            )
            return row

    def _require_workstation(self) -> sqlite3.Row | None:
        workstation = self._registered_workstation()
        if workstation is None:
            self._json_response(
                HTTPStatus.UNAUTHORIZED,
                {
                    "ok": False,
                    "error": "workstation_authentication_required",
                    "message": (
                        "A valid registered administrator workstation "
                        "identity is required."
                    ),
                },
            )
        return workstation

    def _admin_session(self) -> sqlite3.Row | None:
        token = bearer_token(self.headers)
        if not token:
            return None
        now = datetime.now(timezone.utc)
        token_hash = sha256_token(token)
        with db_connect(self.server.config) as db:
            row = db.execute(
                """
                SELECT s.*, a.username, a.enabled, w.revoked_utc
                FROM admin_sessions s
                JOIN admins a ON a.id = s.admin_id
                JOIN workstations w ON w.id = s.workstation_id
                WHERE s.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            try:
                expires = parse_utc(str(row["expires_utc"]))
            except ValueError:
                return None
            if expires <= now or not bool(row["enabled"]) or row["revoked_utc"]:
                db.execute(
                    "DELETE FROM admin_sessions WHERE token_hash = ?",
                    (token_hash,),
                )
                return None
            db.execute(
                "UPDATE admin_sessions SET last_seen_utc = ? WHERE token_hash = ?",
                (utc_now_iso(), token_hash),
            )
            return row

    def _require_admin(self) -> sqlite3.Row | None:
        session = self._admin_session()
        if session is None:
            self._json_response(
                HTTPStatus.UNAUTHORIZED,
                {
                    "ok": False,
                    "error": "authentication_required",
                    "message": "A valid administrator session is required.",
                },
            )
        return session

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            if path == "/":
                self._html_response(
                    HTTPStatus.OK,
                    f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Login Guard Remote Management</title>
<style>
body {{
    margin: 0;
    background: #111827;
    color: #e5e7eb;
    font-family: "Segoe UI", Arial, sans-serif;
}}
main {{
    max-width: 760px;
    margin: 8vh auto;
    padding: 32px;
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 12px;
}}
h1 {{ margin-top: 0; font-size: 28px; }}
.status {{
    display: inline-block;
    padding: 5px 10px;
    border-radius: 999px;
    background: #064e3b;
    color: #d1fae5;
    font-weight: 600;
}}
code {{
    background: #111827;
    padding: 2px 6px;
    border-radius: 4px;
}}
.note {{ color: #9ca3af; }}
</style>
</head>
<body>
<main>
<h1>Windows Login Guard Remote Management</h1>
<p><span class="status">Server running</span></p>
<p>Version: <strong>{APP_VERSION}</strong></p>
<p>
This address hosts the secured management API. It is not the management
dashboard.
</p>
<p>
Open the desktop shortcut
<strong>Windows Login Guard Remote Administration</strong>
on the management computer.
</p>
<p class="note">
The browser may show a warning because the server uses a private,
self-signed certificate. The desktop application uses the pinned server
certificate.
</p>
<p>Health endpoint: <code>/health</code></p>
</main>
</body>
</html>""",
                )
                return

            if path == "/health":
                self._json_response(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "service": REMOTE_SERVER_SERVICE,
                        "version": APP_VERSION,
                        "api_version": REMOTE_API_VERSION,
                        "timestamp_utc": utc_now_iso(),
                    },
                )
                return

            if path == "/api/v1/workstation/approval-notifications":
                workstation = self._require_workstation()
                if workstation is None:
                    return
                self._get_workstation_approval_notifications(
                    workstation=workstation,
                    limit=int(query.get("limit", ["250"])[0]),
                )
                return

            session = self._require_admin()
            if session is None:
                return

            if path == "/api/v1/admin/me":
                self._json_response(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "username": session["username"],
                        "workstation_id": session["workstation_id"],
                        "expires_utc": session["expires_utc"],
                    },
                )
                return

            if path == "/api/v1/admin/devices":
                self._get_devices()
                return

            if path == "/api/v1/admin/approval-requests":
                self._get_approval_requests(
                    device_id=safe_text(
                        query.get("device_id", [""])[0],
                        100,
                    ),
                    status=safe_text(
                        query.get("status", [""])[0],
                        50,
                    ),
                    limit=int(query.get("limit", ["250"])[0]),
                )
                return

            if path.startswith("/api/v1/admin/devices/"):
                suffix = path[len("/api/v1/admin/devices/"):]
                parts = suffix.split("/")
                device_id = parts[0]
                if len(parts) == 1:
                    self._get_device(device_id, session)
                    return
                if len(parts) == 2 and parts[1] == "audit":
                    limit = int(query.get("limit", ["250"])[0])
                    self._get_device_audit(device_id, limit, session)
                    return
                if len(parts) == 2 and parts[1] == "logs":
                    self._get_device_logs(device_id, session)
                    return

            if path == "/api/v1/admin/central-audit":
                limit = int(query.get("limit", ["250"])[0])
                self._get_central_audit(limit)
                return

            self._json_response(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "not_found"},
            )
        except (ValueError, TypeError) as exc:
            self._json_response(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": "invalid_request", "message": str(exc)},
            )
        except Exception as exc:
            self._route_error(exc)

    def do_POST(self) -> None:
        try:
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/api/v1/workstations/register":
                self._register_workstation(self._read_json())
                return
            if path == "/api/v1/admin/login":
                self._admin_login(self._read_json())
                return
            if path == "/api/v1/devices/register":
                self._register_device(self._read_json())
                return
            if path == "/api/v1/devices/sync":
                self._device_sync(self._read_json())
                return
            if path == "/api/v1/devices/command-results":
                self._device_command_result(self._read_json())
                return
            if path.startswith("/api/v1/admin/devices/"):
                session = self._require_admin()
                if session is None:
                    return
                suffix = path[len("/api/v1/admin/devices/"):]
                parts = suffix.split("/")
                if (
                    len(parts) == 4
                    and parts[0]
                    and parts[1] == "sessions"
                    and parts[2]
                    and parts[3] in {"lock", "logoff"}
                ):
                    self._queue_session_action(
                        device_id=parts[0],
                        session_id=int(parts[2]),
                        action=parts[3],
                        payload=self._read_json(),
                        session=session,
                    )
                    return

            if path.startswith("/api/v1/admin/approval-requests/"):
                session = self._require_admin()
                if session is None:
                    return
                suffix = path[
                    len("/api/v1/admin/approval-requests/"):
                ]
                parts = suffix.split("/")
                if len(parts) == 2 and parts[0]:
                    payload = self._read_json()
                    if parts[1] == "approve":
                        self._decide_approval_request(
                            request_id=parts[0],
                            decision="approve",
                            payload=payload,
                            session=session,
                        )
                        return
                    if parts[1] == "deny":
                        self._decide_approval_request(
                            request_id=parts[0],
                            decision="deny",
                            payload=payload,
                            session=session,
                        )
                        return
            if path == "/api/v1/admin/logout":
                session = self._require_admin()
                if session is not None:
                    self._admin_logout()
                return
            self._json_response(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "not_found"},
            )
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json_response(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": "invalid_request", "message": str(exc)},
            )
        except Exception as exc:
            self._route_error(exc)

    def do_DELETE(self) -> None:
        try:
            path = urlparse(self.path).path.rstrip("/") or "/"
            session = self._require_admin()
            if session is None:
                return

            if path.startswith("/api/v1/admin/devices/"):
                suffix = path[len("/api/v1/admin/devices/"):]
                parts = suffix.split("/")
                if len(parts) == 1 and parts[0]:
                    self._delete_device(parts[0], session)
                    return

            self._json_response(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "not_found"},
            )
        except (ValueError, TypeError) as exc:
            self._json_response(
                HTTPStatus.BAD_REQUEST,
                {
                    "ok": False,
                    "error": "invalid_request",
                    "message": str(exc),
                },
            )
        except Exception as exc:
            self._route_error(exc)

    def _consume_enrollment_token(
        self,
        db: sqlite3.Connection,
        *,
        kind: str,
        token: str,
        used_by: str,
    ) -> sqlite3.Row | None:
        row = db.execute(
            """
            SELECT * FROM enrollment_tokens
            WHERE token_hash = ? AND kind = ? AND used_utc IS NULL
            """,
            (sha256_token(token), kind),
        ).fetchone()
        if row is None:
            return None
        try:
            expires = parse_utc(str(row["expires_utc"]))
        except ValueError:
            return None
        if expires <= datetime.now(timezone.utc):
            return None
        db.execute(
            """
            UPDATE enrollment_tokens
            SET used_utc = ?, used_by = ?
            WHERE id = ? AND used_utc IS NULL
            """,
            (utc_now_iso(), used_by, row["id"]),
        )
        return row

    def _register_workstation(self, payload: dict[str, Any]) -> None:
        enrollment_token = safe_text(payload.get("enrollment_token"), 500)
        label = safe_text(payload.get("label"), 200)
        if not enrollment_token or not label:
            raise ValueError("enrollment_token and label are required")

        workstation_id = str(uuid.uuid4())
        workstation_token = new_token(40)
        with db_connect(self.server.config) as db:
            consumed = self._consume_enrollment_token(
                db,
                kind="workstation",
                token=enrollment_token,
                used_by=workstation_id,
            )
            if consumed is None:
                self._json_response(
                    HTTPStatus.UNAUTHORIZED,
                    {
                        "ok": False,
                        "error": "invalid_enrollment_token",
                        "message": "The workstation enrollment token is invalid or expired.",
                    },
                )
                return
            db.execute(
                """
                INSERT INTO workstations (
                    id, label, token_hash, created_utc,
                    last_seen_utc, remote_address
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    workstation_id,
                    label,
                    sha256_token(workstation_token),
                    utc_now_iso(),
                    utc_now_iso(),
                    self.remote_address,
                ),
            )
        central_audit(
            self.server.config,
            action="workstation_registered",
            actor_type="workstation",
            actor_id=workstation_id,
            target_type="workstation",
            target_id=workstation_id,
            remote_address=self.remote_address,
            details={"label": label},
        )
        self._json_response(
            HTTPStatus.CREATED,
            {
                "ok": True,
                "workstation_id": workstation_id,
                "workstation_token": workstation_token,
                "server_version": APP_VERSION,
            },
        )

    def _login_rate_key(self, username: str, workstation_token: str) -> str:
        return "|".join(
            [
                self.remote_address.lower(),
                username.lower(),
                sha256_token(workstation_token)[:16],
            ]
        )

    def _login_is_rate_limited(self, key: str) -> bool:
        now = time.monotonic()
        with self.server.auth_lock:
            attempts = [
                value
                for value in self.server.login_failures.get(key, [])
                if now - value <= 300
            ]
            self.server.login_failures[key] = attempts
            return len(attempts) >= 5

    def _record_login_failure(self, key: str) -> None:
        now = time.monotonic()
        with self.server.auth_lock:
            attempts = [
                value
                for value in self.server.login_failures.get(key, [])
                if now - value <= 300
            ]
            attempts.append(now)
            self.server.login_failures[key] = attempts

    def _clear_login_failures(self, key: str) -> None:
        with self.server.auth_lock:
            self.server.login_failures.pop(key, None)

    def _admin_login(self, payload: dict[str, Any]) -> None:
        workstation_token = safe_text(
            self.headers.get("X-WLG-Workstation-Token", ""), 1000
        )
        username = safe_text(payload.get("username"), 200)
        otp = safe_text(payload.get("otp"), 20).replace(" ", "")
        if not workstation_token or not username or not otp:
            raise ValueError("username, OTP, and workstation identity are required")
        rate_key = self._login_rate_key(username, workstation_token)
        if self._login_is_rate_limited(rate_key):
            self._json_response(
                HTTPStatus.TOO_MANY_REQUESTS,
                {
                    "ok": False,
                    "error": "login_rate_limited",
                    "message": "Too many failed sign-in attempts. Try again after five minutes.",
                },
            )
            return

        with db_connect(self.server.config) as db:
            workstation = db.execute(
                """
                SELECT * FROM workstations
                WHERE token_hash = ? AND revoked_utc IS NULL
                """,
                (sha256_token(workstation_token),),
            ).fetchone()
            admin = db.execute(
                "SELECT * FROM admins WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
            valid = False
            if workstation is not None and admin is not None and bool(admin["enabled"]):
                auth_source = str(admin["auth_source"] or "server_totp")
                if auth_source == "local_wlg":
                    valid = _verify_local_wlg_admin_otp(
                        str(admin["windows_sid"] or ""),
                        otp,
                    )
                else:
                    try:
                        secret = decode_machine_secret(
                            str(admin["totp_secret_dpapi"])
                        )
                        valid = pyotp.TOTP(secret).verify(
                            otp,
                            valid_window=1,
                        )
                    except Exception:
                        valid = False
            if not valid:
                self._record_login_failure(rate_key)
                central_audit(
                    self.server.config,
                    action="admin_login_failed",
                    actor_type="admin",
                    actor_id=username,
                    target_type="workstation",
                    target_id=str(workstation["id"]) if workstation else "unknown",
                    remote_address=self.remote_address,
                    details={},
                )
                self._json_response(
                    HTTPStatus.UNAUTHORIZED,
                    {
                        "ok": False,
                        "error": "invalid_admin_authentication",
                        "message": "The administrator OTP or workstation identity is invalid.",
                    },
                )
                return

            now = datetime.now(timezone.utc)
            expires = now + timedelta(
                hours=int(self.server.config["admin_session_hours"])
            )
            session_token = new_token(40)
            db.execute(
                "DELETE FROM admin_sessions WHERE expires_utc <= ?",
                (now.isoformat(),),
            )
            db.execute(
                """
                INSERT INTO admin_sessions (
                    token_hash, admin_id, workstation_id,
                    created_utc, expires_utc, last_seen_utc
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sha256_token(session_token),
                    admin["id"],
                    workstation["id"],
                    now.isoformat(),
                    expires.isoformat(),
                    now.isoformat(),
                ),
            )
            db.execute(
                "UPDATE admins SET last_login_utc = ? WHERE id = ?",
                (now.isoformat(), admin["id"]),
            )
            db.execute(
                """
                UPDATE workstations
                SET last_seen_utc = ?, remote_address = ?
                WHERE id = ?
                """,
                (now.isoformat(), self.remote_address, workstation["id"]),
            )

        self._clear_login_failures(rate_key)
        central_audit(
            self.server.config,
            action="admin_login_succeeded",
            actor_type="admin",
            actor_id=username,
            target_type="workstation",
            target_id=str(workstation["id"]),
            remote_address=self.remote_address,
            details={},
        )
        self._json_response(
            HTTPStatus.OK,
            {
                "ok": True,
                "session_token": session_token,
                "username": str(admin["username"]),
                "workstation_id": str(workstation["id"]),
                "expires_utc": expires.isoformat(),
                "server_version": APP_VERSION,
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _admin_logout(self) -> None:
        token = bearer_token(self.headers)
        with db_connect(self.server.config) as db:
            db.execute(
                "DELETE FROM admin_sessions WHERE token_hash = ?",
                (sha256_token(token),),
            )
        self._json_response(HTTPStatus.OK, {"ok": True})

    def _register_device(self, payload: dict[str, Any]) -> None:
        enrollment_token = safe_text(payload.get("enrollment_token"), 500)
        hostname = safe_text(payload.get("hostname"), 200)
        machine_identity = safe_text(
            payload.get("machine_identity"),
            100,
        )
        display_name = safe_text(
            payload.get("display_name") or hostname,
            200,
        )
        endpoint_version = safe_text(payload.get("endpoint_version"), 100)
        operating_system = safe_text(payload.get("operating_system"), 500)
        if not enrollment_token or not hostname:
            raise ValueError("enrollment_token and hostname are required")

        enrollment_hash = sha256_token(enrollment_token)
        device_token = new_token(48)
        command_secret = new_token(48)
        now = utc_now_iso()
        device_id = ""
        replayed_registration = False

        with db_connect(self.server.config) as db:
            enrollment = db.execute(
                """
                SELECT * FROM enrollment_tokens
                WHERE token_hash = ? AND kind = 'device'
                """,
                (enrollment_hash,),
            ).fetchone()

            if enrollment is None:
                self._json_response(
                    HTTPStatus.UNAUTHORIZED,
                    {
                        "ok": False,
                        "error": "invalid_enrollment_token",
                        "message": (
                            "The device enrollment token is invalid "
                            "or expired."
                        ),
                    },
                )
                return

            try:
                expires = parse_utc(str(enrollment["expires_utc"]))
            except ValueError:
                expires = datetime.min.replace(tzinfo=timezone.utc)

            if expires <= datetime.now(timezone.utc):
                self._json_response(
                    HTTPStatus.UNAUTHORIZED,
                    {
                        "ok": False,
                        "error": "invalid_enrollment_token",
                        "message": (
                            "The device enrollment token is invalid "
                            "or expired."
                        ),
                    },
                )
                return

            if enrollment["used_utc"]:
                existing = db.execute(
                    "SELECT * FROM devices WHERE id = ?",
                    (str(enrollment["used_by"] or ""),),
                ).fetchone()

                same_machine = (
                    existing is not None
                    and machine_identity
                    and str(existing["machine_identity"] or "")
                    == machine_identity
                )
                if not same_machine:
                    self._json_response(
                        HTTPStatus.UNAUTHORIZED,
                        {
                            "ok": False,
                            "error": "invalid_enrollment_token",
                            "message": (
                                "The device enrollment token has "
                                "already been used."
                            ),
                        },
                    )
                    return

                replayed_registration = True
                device_id = str(existing["id"])
                db.execute(
                    """
                    UPDATE devices SET
                        hostname = ?, display_name = ?, token_hash = ?,
                        last_seen_utc = ?, remote_address = ?,
                        endpoint_version = ?, operating_system = ?,
                        agent_status = 'registered', last_error = '',
                        revoked_utc = NULL, command_secret_dpapi = ?,
                        command_channel_ready = 0
                    WHERE id = ?
                    """,
                    (
                        hostname,
                        display_name,
                        sha256_token(device_token),
                        now,
                        self.remote_address,
                        endpoint_version,
                        operating_system,
                        encode_machine_secret(command_secret),
                        device_id,
                    ),
                )
            else:
                existing = None
                if machine_identity:
                    existing = db.execute(
                        """
                        SELECT * FROM devices
                        WHERE machine_identity = ?
                        ORDER BY last_seen_utc DESC
                        LIMIT 1
                        """,
                        (machine_identity,),
                    ).fetchone()

                if existing is None:
                    existing = db.execute(
                        """
                        SELECT * FROM devices
                        WHERE hostname = ? COLLATE NOCASE
                          AND revoked_utc IS NULL
                        ORDER BY last_seen_utc DESC
                        LIMIT 1
                        """,
                        (hostname,),
                    ).fetchone()

                if existing is not None:
                    device_id = str(existing["id"])
                    db.execute(
                        """
                        UPDATE devices SET
                            hostname = ?, machine_identity = ?,
                            display_name = ?, token_hash = ?,
                            last_seen_utc = ?, remote_address = ?,
                            endpoint_version = ?, operating_system = ?,
                            agent_status = 'registered',
                            last_error = '', revoked_utc = NULL,
                            command_secret_dpapi = ?,
                            command_channel_ready = 0
                        WHERE id = ?
                        """,
                        (
                            hostname,
                            machine_identity or existing["machine_identity"],
                            display_name,
                            sha256_token(device_token),
                            now,
                            self.remote_address,
                            endpoint_version,
                            operating_system,
                            encode_machine_secret(command_secret),
                            device_id,
                        ),
                    )
                else:
                    device_id = str(uuid.uuid4())
                    db.execute(
                        """
                        INSERT INTO devices (
                            id, hostname, machine_identity, display_name,
                            token_hash, registered_utc, last_seen_utc,
                            remote_address, endpoint_version,
                            operating_system, command_secret_dpapi,
                            command_channel_ready, agent_status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'registered')
                        """,
                        (
                            device_id,
                            hostname,
                            machine_identity or None,
                            display_name,
                            sha256_token(device_token),
                            now,
                            now,
                            self.remote_address,
                            endpoint_version,
                            operating_system,
                            encode_machine_secret(command_secret),
                        ),
                    )

                db.execute(
                    """
                    UPDATE enrollment_tokens
                    SET used_utc = ?, used_by = ?
                    WHERE id = ? AND used_utc IS NULL
                    """,
                    (now, device_id, enrollment["id"]),
                )

        central_audit(
            self.server.config,
            action="device_registered",
            actor_type="device",
            actor_id=device_id,
            target_type="device",
            target_id=device_id,
            remote_address=self.remote_address,
            details={
                "hostname": hostname,
                "display_name": display_name,
                "idempotent_registration": replayed_registration,
            },
        )
        self._json_response(
            HTTPStatus.CREATED,
            {
                "ok": True,
                "device_id": device_id,
                "device_token": device_token,
                "command_secret": command_secret,
                "server_version": APP_VERSION,
                "sync_interval_seconds": 10,
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _device_sync(self, payload: dict[str, Any]) -> None:
        token = bearer_token(self.headers)
        if not token:
            self._json_response(
                HTTPStatus.UNAUTHORIZED,
                {"ok": False, "error": "device_authentication_required"},
            )
            return

        dashboard = payload.get("dashboard", {})
        sessions = payload.get("sessions", [])
        diagnostics = payload.get("diagnostics", {})
        audit_records = payload.get("audit", [])
        logs = str(payload.get("logs", ""))
        if not isinstance(dashboard, dict):
            raise ValueError("dashboard must be an object")
        if not isinstance(sessions, list):
            raise ValueError("sessions must be an array")
        if not isinstance(diagnostics, dict):
            raise ValueError("diagnostics must be an object")
        if not isinstance(audit_records, list):
            raise ValueError("audit must be an array")
        audit_records = audit_records[:MAX_AUDIT_RECORDS]
        logs = truncate_utf8(logs, MAX_LOG_TEXT_BYTES)

        token_hash = sha256_token(token)
        now = utc_now_iso()
        bootstrap_secret = ""
        commands: list[dict[str, Any]] = []
        with db_connect(self.server.config) as db:
            device = db.execute(
                """
                SELECT * FROM devices
                WHERE token_hash = ? AND revoked_utc IS NULL
                """,
                (token_hash,),
            ).fetchone()
            if device is None:
                self._json_response(
                    HTTPStatus.UNAUTHORIZED,
                    {"ok": False, "error": "invalid_device_token"},
                )
                return

            command_secret_dpapi = str(
                device["command_secret_dpapi"] or ""
            )
            if command_secret_dpapi:
                command_secret = decode_machine_secret(
                    command_secret_dpapi
                )
            else:
                command_secret = new_token(48)
                command_secret_dpapi = encode_machine_secret(
                    command_secret
                )
                db.execute(
                    """
                    UPDATE devices
                    SET command_secret_dpapi = ?
                    WHERE id = ?
                    """,
                    (command_secret_dpapi, device["id"]),
                )

            if not bool(payload.get("command_secret_ready", False)):
                bootstrap_secret = command_secret

            db.execute(
                """
                UPDATE devices SET
                    hostname = ?, display_name = ?, last_seen_utc = ?,
                    remote_address = ?, endpoint_version = ?,
                    operating_system = ?, dashboard_json = ?, sessions_json = ?,
                    diagnostics_json = ?, audit_json = ?, logs_text = ?,
                    agent_status = ?, last_error = ?,
                    command_channel_ready = ?
                WHERE id = ?
                """,
                (
                    safe_text(payload.get("hostname") or device["hostname"], 200),
                    safe_text(
                        payload.get("display_name") or device["display_name"], 200
                    ),
                    now,
                    self.remote_address,
                    safe_text(payload.get("endpoint_version"), 100),
                    safe_text(payload.get("operating_system"), 500),
                    json.dumps(dashboard, separators=(",", ":")),
                    json.dumps(sessions, separators=(",", ":")),
                    json.dumps(diagnostics, separators=(",", ":")),
                    json.dumps(audit_records, separators=(",", ":")),
                    logs,
                    safe_text(payload.get("agent_status") or "online", 50),
                    safe_text(payload.get("last_error"), 1000),
                    1 if bool(payload.get("command_secret_ready", False)) else 0,
                    device["id"],
                ),
            )
            self._synchronize_approval_requests(
                db,
                device_id=str(device["id"]),
                sessions=sessions,
                now_utc=now,
            )
            commands = self._pending_device_commands(
                db,
                device_id=str(device["id"]),
                now_utc=now,
            )

        response: dict[str, Any] = {
            "ok": True,
            "server_time_utc": now,
            "next_sync_seconds": 10,
            "commands": commands,
            "api_version": REMOTE_API_VERSION,
        }
        if bootstrap_secret:
            response["command_secret"] = bootstrap_secret
        self._json_response(HTTPStatus.OK, response)

    def _synchronize_approval_requests(
        self,
        db: sqlite3.Connection,
        *,
        device_id: str,
        sessions: list[Any],
        now_utc: str,
    ) -> None:
        now = parse_utc(now_utc)
        active_challenges: set[str] = set()

        for raw in sessions[:500]:
            if not isinstance(raw, dict):
                continue
            if str(raw.get("verification_state", "")) != "Waiting approval":
                continue
            challenge_id = safe_text(raw.get("challenge_id"), 200)
            if not challenge_id:
                continue
            active_challenges.add(challenge_id)
            session_id = int(raw.get("session_id", -1))
            if session_id <= 0:
                continue
            remaining = raw.get("remaining_seconds")
            try:
                remaining_seconds = max(15, min(int(remaining), 3600))
            except (TypeError, ValueError):
                remaining_seconds = 300
            expires = now + timedelta(seconds=remaining_seconds)
            requested = safe_text(
                raw.get("challenge_created_utc"),
                100,
            ) or now_utc

            db.execute(
                """
                INSERT INTO approval_requests (
                    id, device_id, challenge_id, session_id,
                    username, user_sid, reason, requested_utc,
                    expires_utc, allowed_durations_json,
                    default_duration, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                ON CONFLICT(device_id, challenge_id) DO UPDATE SET
                    session_id = excluded.session_id,
                    username = excluded.username,
                    user_sid = excluded.user_sid,
                    reason = excluded.reason,
                    expires_utc = excluded.expires_utc,
                    allowed_durations_json = excluded.allowed_durations_json,
                    default_duration = excluded.default_duration
                """,
                (
                    str(uuid.uuid4()),
                    device_id,
                    challenge_id,
                    session_id,
                    safe_text(raw.get("username"), 200),
                    safe_text(raw.get("user_sid"), 200),
                    safe_text(raw.get("verification_reason"), 100),
                    requested,
                    expires.isoformat(),
                    json.dumps(
                        raw.get("allowed_approval_durations", []),
                        separators=(",", ":"),
                    ),
                    safe_text(
                        raw.get("default_approval_duration") or "session",
                        50,
                    ),
                ),
            )

        pending_rows = db.execute(
            """
            SELECT id, challenge_id, status, expires_utc
            FROM approval_requests
            WHERE device_id = ?
              AND status IN (
                  'pending',
                  'approved_pending_delivery',
                  'denied_pending_delivery'
              )
            """,
            (device_id,),
        ).fetchall()
        for row in pending_rows:
            status = str(row["status"])
            try:
                expired = parse_utc(str(row["expires_utc"])) <= now
            except ValueError:
                expired = True
            if expired and status == "pending":
                db.execute(
                    """
                    UPDATE approval_requests
                    SET status = 'expired', completed_utc = ?
                    WHERE id = ? AND status = 'pending'
                    """,
                    (now_utc, row["id"]),
                )
            elif (
                status == "pending"
                and str(row["challenge_id"]) not in active_challenges
            ):
                db.execute(
                    """
                    UPDATE approval_requests
                    SET status = 'cancelled', completed_utc = ?
                    WHERE id = ? AND status = 'pending'
                    """,
                    (now_utc, row["id"]),
                )

    def _pending_device_commands(
        self,
        db: sqlite3.Connection,
        *,
        device_id: str,
        now_utc: str,
    ) -> list[dict[str, Any]]:
        db.execute(
            """
            UPDATE device_actions
            SET status = 'expired', completed_utc = ?
            WHERE device_id = ?
              AND status IN ('pending_delivery', 'delivered')
              AND expires_utc <= ?
            """,
            (now_utc, device_id, now_utc),
        )

        approval_rows = db.execute(
            """
            SELECT * FROM approval_requests
            WHERE device_id = ?
              AND status IN (
                  'approved_pending_delivery',
                  'denied_pending_delivery'
              )
              AND command_json IS NOT NULL
              AND command_signature IS NOT NULL
              AND expires_utc > ?
            ORDER BY decision_utc, requested_utc
            LIMIT 20
            """,
            (device_id, now_utc),
        ).fetchall()

        commands: list[dict[str, Any]] = []
        for row in approval_rows:
            try:
                command = json.loads(str(row["command_json"]))
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(command, dict):
                continue
            command["signature"] = str(row["command_signature"])
            commands.append(command)
            db.execute(
                """
                UPDATE approval_requests
                SET command_delivered_utc = COALESCE(
                    command_delivered_utc,
                    ?
                )
                WHERE id = ?
                """,
                (now_utc, row["id"]),
            )

        remaining = max(0, 20 - len(commands))
        if remaining:
            action_rows = db.execute(
                """
                SELECT * FROM device_actions
                WHERE device_id = ?
                  AND status IN ('pending_delivery', 'delivered')
                  AND expires_utc > ?
                ORDER BY requested_utc
                LIMIT ?
                """,
                (device_id, now_utc, remaining),
            ).fetchall()
            for row in action_rows:
                try:
                    command = json.loads(str(row["command_json"]))
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(command, dict):
                    continue
                command["signature"] = str(row["command_signature"])
                commands.append(command)
                db.execute(
                    """
                    UPDATE device_actions
                    SET
                        status = 'delivered',
                        delivered_utc = COALESCE(delivered_utc, ?)
                    WHERE id = ?
                    """,
                    (now_utc, row["id"]),
                )

        return commands

    def _get_devices(self) -> None:
        offline_after = int(self.server.config["offline_after_seconds"])
        with db_connect(self.server.config) as db:
            rows = db.execute(
                """
                SELECT d.id, d.hostname, d.display_name, d.registered_utc,
                       d.last_seen_utc, d.endpoint_version, d.operating_system,
                       d.agent_status, d.last_error, d.revoked_utc,
                       d.dashboard_json, d.command_channel_ready,
                       (
                           SELECT COUNT(*)
                           FROM approval_requests r
                           WHERE r.device_id = d.id
                             AND r.status = 'pending'
                       ) AS pending_approval_count
                FROM devices d
                WHERE revoked_utc IS NULL
                ORDER BY display_name COLLATE NOCASE, hostname COLLATE NOCASE
                """
            ).fetchall()
        devices: list[dict[str, Any]] = []
        for row in rows:
            dashboard = row_json(row, "dashboard_json", {})
            online = not row["revoked_utc"] and is_recent(
                row["last_seen_utc"], offline_after
            )
            devices.append(
                {
                    "id": row["id"],
                    "hostname": row["hostname"],
                    "display_name": row["display_name"],
                    "registered_utc": row["registered_utc"],
                    "last_seen_utc": row["last_seen_utc"],
                    "online": online,
                    "revoked": bool(row["revoked_utc"]),
                    "endpoint_version": row["endpoint_version"],
                    "operating_system": row["operating_system"],
                    "agent_status": row["agent_status"],
                    "last_error": row["last_error"],
                    "remote_approval_ready": bool(
                        row["command_channel_ready"]
                    ),
                    "remote_session_control_ready": bool(
                        row["command_channel_ready"]
                    ),
                    "overall_health": dashboard.get("overall_health", "unknown"),
                    "maintenance_enabled": bool(
                        dashboard.get("maintenance", {}).get("enabled", False)
                    ),
                    "pending_approval_count": int(
                        row["pending_approval_count"] or 0
                    ),
                }
            )
        self._json_response(
            HTTPStatus.OK,
            {
                "ok": True,
                "devices": devices,
                "server_version": APP_VERSION,
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _device_row(self, device_id: str) -> sqlite3.Row | None:
        with db_connect(self.server.config) as db:
            return db.execute(
                "SELECT * FROM devices WHERE id = ?",
                (safe_text(device_id, 100),),
            ).fetchone()

    def _get_device(self, device_id: str, session: sqlite3.Row) -> None:
        row = self._device_row(device_id)
        if row is None:
            self._json_response(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "device_not_found"},
            )
            return
        offline_after = int(self.server.config["offline_after_seconds"])
        approval_requests = self._approval_rows(
            device_id=str(row["id"]),
            status="",
            limit=100,
        )
        self._json_response(
            HTTPStatus.OK,
            {
                "ok": True,
                "device": {
                    "id": row["id"],
                    "hostname": row["hostname"],
                    "display_name": row["display_name"],
                    "registered_utc": row["registered_utc"],
                    "last_seen_utc": row["last_seen_utc"],
                    "online": is_recent(row["last_seen_utc"], offline_after)
                    and not bool(row["revoked_utc"]),
                    "revoked": bool(row["revoked_utc"]),
                    "remote_address": row["remote_address"],
                    "endpoint_version": row["endpoint_version"],
                    "operating_system": row["operating_system"],
                    "agent_status": row["agent_status"],
                    "last_error": row["last_error"],
                    "remote_approval_ready": bool(
                        row["command_channel_ready"]
                    ),
                    "dashboard": row_json(row, "dashboard_json", {}),
                    "sessions": row_json(row, "sessions_json", []),
                    "diagnostics": row_json(row, "diagnostics_json", {}),
                    "audit": row_json(row, "audit_json", []),
                    "logs": row["logs_text"],
                    "approval_requests": approval_requests,
                },
                "read_only": False,
                "capabilities": {
                    "remote_approval": True,
                    "remote_session_control": True,
                    "remote_configuration": False,
                },
                "api_version": REMOTE_API_VERSION,
            },
        )

    @staticmethod
    def _approval_payload(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "device_id": row["device_id"],
            "challenge_id": row["challenge_id"],
            "session_id": int(row["session_id"]),
            "username": row["username"],
            "user_sid": row["user_sid"],
            "reason": row["reason"],
            "requested_utc": row["requested_utc"],
            "expires_utc": row["expires_utc"],
            "status": row["status"],
            "decision_utc": row["decision_utc"],
            "decided_by_username": row["decided_by_username"],
            "duration": row["duration"],
            "allowed_durations": row_json(
                row,
                "allowed_durations_json",
                [],
            ),
            "default_duration": row["default_duration"],
            "command_delivered_utc": row["command_delivered_utc"],
            "completed_utc": row["completed_utc"],
            "result": row_json(row, "result_json", {}),
        }

    def _approval_rows(
        self,
        *,
        device_id: str,
        status: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if device_id:
            clauses.append("device_id = ?")
            parameters.append(device_id)
        if status:
            allowed = {
                "pending",
                "approved_pending_delivery",
                "denied_pending_delivery",
                "approved",
                "denied",
                "expired",
                "cancelled",
                "failed",
            }
            if status not in allowed:
                raise ValueError("Unsupported approval-request status")
            clauses.append("status = ?")
            parameters.append(status)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        safe_limit = max(1, min(int(limit), 500))
        parameters.append(safe_limit)
        with db_connect(self.server.config) as db:
            rows = db.execute(
                """
                SELECT * FROM approval_requests
                """
                + where
                + " ORDER BY requested_utc DESC LIMIT ?",
                tuple(parameters),
            ).fetchall()
        return [self._approval_payload(row) for row in rows]

    def _get_workstation_approval_notifications(
        self,
        *,
        workstation: sqlite3.Row,
        limit: int,
    ) -> None:
        safe_limit = max(1, min(int(limit), 250))
        now_utc = utc_now_iso()
        with db_connect(self.server.config) as db:
            db.execute(
                """
                UPDATE approval_requests
                SET status = 'expired', completed_utc = ?
                WHERE status = 'pending' AND expires_utc <= ?
                """,
                (now_utc, now_utc),
            )
            rows = db.execute(
                """
                SELECT
                    r.id,
                    r.device_id,
                    r.session_id,
                    r.username,
                    r.reason,
                    r.requested_utc,
                    r.expires_utc,
                    d.display_name AS device_display_name,
                    d.hostname AS device_hostname
                FROM approval_requests r
                JOIN devices d ON d.id = r.device_id
                WHERE r.status = 'pending'
                  AND r.expires_utc > ?
                  AND d.revoked_utc IS NULL
                ORDER BY r.requested_utc
                LIMIT ?
                """,
                (now_utc, safe_limit),
            ).fetchall()

        requests = [
            {
                "id": str(row["id"]),
                "device_id": str(row["device_id"]),
                "device_display_name": str(
                    row["device_display_name"]
                    or row["device_hostname"]
                    or "Protected PC"
                ),
                "device_hostname": str(row["device_hostname"] or ""),
                "session_id": int(row["session_id"]),
                "username": str(row["username"] or "Unknown user"),
                "reason": str(row["reason"] or ""),
                "requested_utc": str(row["requested_utc"]),
                "expires_utc": str(row["expires_utc"]),
            }
            for row in rows
        ]
        self._json_response(
            HTTPStatus.OK,
            {
                "ok": True,
                "approval_requests": requests,
                "workstation_id": str(workstation["id"]),
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _get_approval_requests(
        self,
        *,
        device_id: str,
        status: str,
        limit: int,
    ) -> None:
        self._json_response(
            HTTPStatus.OK,
            {
                "ok": True,
                "approval_requests": self._approval_rows(
                    device_id=device_id,
                    status=status,
                    limit=limit,
                ),
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _verify_admin_decision_otp(
        self,
        session: sqlite3.Row,
        otp: str,
    ) -> bool:
        code = safe_text(otp, 20).replace(" ", "")
        if not code.isdigit() or len(code) != 6:
            return False
        with db_connect(self.server.config) as db:
            admin = db.execute(
                "SELECT * FROM admins WHERE id = ?",
                (session["admin_id"],),
            ).fetchone()
        if admin is None or not bool(admin["enabled"]):
            return False
        auth_source = str(admin["auth_source"] or "server_totp")
        if auth_source == "local_wlg":
            return _verify_local_wlg_admin_otp(
                str(admin["windows_sid"] or ""),
                code,
            )
        try:
            secret = decode_machine_secret(
                str(admin["totp_secret_dpapi"])
            )
            return bool(
                pyotp.TOTP(secret).verify(code, valid_window=1)
            )
        except Exception:
            return False

    def _decide_approval_request(
        self,
        *,
        request_id: str,
        decision: str,
        payload: dict[str, Any],
        session: sqlite3.Row,
    ) -> None:
        clean_request_id = safe_text(request_id, 100)
        duration = safe_text(payload.get("duration"), 50)
        if decision not in {"approve", "deny"}:
            raise ValueError("Unsupported approval decision")

        now = datetime.now(timezone.utc)
        now_utc = now.isoformat()
        with db_connect(self.server.config) as db:
            row = db.execute(
                "SELECT * FROM approval_requests WHERE id = ?",
                (clean_request_id,),
            ).fetchone()
            if row is None:
                self._json_response(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "approval_request_not_found"},
                )
                return
            if str(row["status"]) != "pending":
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "approval_request_not_pending",
                        "message": (
                            "This approval request has already been resolved."
                        ),
                    },
                )
                return
            try:
                request_expires = parse_utc(str(row["expires_utc"]))
            except ValueError:
                request_expires = now
            if request_expires <= now:
                db.execute(
                    """
                    UPDATE approval_requests
                    SET status = 'expired', completed_utc = ?
                    WHERE id = ? AND status = 'pending'
                    """,
                    (now_utc, clean_request_id),
                )
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "approval_request_expired",
                    },
                )
                return

            device = db.execute(
                "SELECT * FROM devices WHERE id = ? AND revoked_utc IS NULL",
                (row["device_id"],),
            ).fetchone()
            if device is None:
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {"ok": False, "error": "device_unavailable"},
                )
                return
            if not is_recent(
                device["last_seen_utc"],
                int(self.server.config["offline_after_seconds"]),
            ):
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "device_offline",
                        "message": (
                            "The protected PC is offline. The request was not approved."
                        ),
                    },
                )
                return

            command_secret_dpapi = str(
                device["command_secret_dpapi"] or ""
            )
            if (
                not command_secret_dpapi
                or not bool(device["command_channel_ready"])
            ):
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "device_command_key_pending",
                        "message": (
                            "The protected PC has not completed the v1.9.0 command-key handshake yet."
                        ),
                    },
                )
                return
            command_secret = decode_machine_secret(
                command_secret_dpapi
            )

            if decision == "approve":
                try:
                    allowed_durations = json.loads(
                        str(row["allowed_durations_json"] or "[]")
                    )
                except json.JSONDecodeError:
                    allowed_durations = []
                if not isinstance(allowed_durations, list):
                    allowed_durations = []
                allowed_durations = {
                    safe_text(value, 50)
                    for value in allowed_durations
                    if safe_text(value, 50)
                }
                if not allowed_durations:
                    allowed_durations = {"session"}
                if duration not in allowed_durations:
                    raise ValueError(
                        "The selected approval duration is not allowed by the protected PC policy"
                    )
                command_type = "approve_session"
                pending_status = "approved_pending_delivery"
            else:
                duration = ""
                command_type = "deny_session"
                pending_status = "denied_pending_delivery"

            command_id = str(uuid.uuid4())
            command_expires = min(
                request_expires,
                now + timedelta(seconds=90),
            )
            command = {
                "command_id": command_id,
                "request_id": clean_request_id,
                "type": command_type,
                "device_id": str(row["device_id"]),
                "challenge_id": str(row["challenge_id"]),
                "session_id": int(row["session_id"]),
                "username": str(row["username"]),
                "user_sid": str(row["user_sid"]),
                "reason": str(row["reason"]),
                "duration": duration,
                "approver_username": str(session["username"]),
                "issued_utc": now_utc,
                "expires_utc": command_expires.isoformat(),
                "nonce": new_token(24),
            }
            signature = sign_remote_command(
                command,
                command_secret,
            )
            updated = db.execute(
                """
                UPDATE approval_requests SET
                    status = ?, decision_utc = ?,
                    decided_by_admin_id = ?,
                    decided_by_username = ?, duration = ?,
                    command_id = ?, command_type = ?,
                    command_json = ?, command_signature = ?
                WHERE id = ? AND status = 'pending'
                """,
                (
                    pending_status,
                    now_utc,
                    session["admin_id"],
                    session["username"],
                    duration,
                    command_id,
                    command_type,
                    json.dumps(command, separators=(",", ":")),
                    signature,
                    clean_request_id,
                ),
            ).rowcount
            if updated != 1:
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {"ok": False, "error": "approval_request_changed"},
                )
                return

        central_audit(
            self.server.config,
            action=(
                "remote_approval_queued"
                if decision == "approve"
                else "remote_denial_queued"
            ),
            actor_type="admin",
            actor_id=str(session["username"]),
            target_type="approval_request",
            target_id=clean_request_id,
            remote_address=self.remote_address,
            details={
                "device_id": str(row["device_id"]),
                "session_id": int(row["session_id"]),
                "username": str(row["username"]),
                "duration": duration,
                "command_id": command_id,
                "authentication": "admin_session",
                "workstation_id": str(session["workstation_id"]),
                "admin_session_created_utc": str(session["created_utc"]),
                "otp_reauthentication_required": False,
            },
        )
        self._json_response(
            HTTPStatus.ACCEPTED,
            {
                "ok": True,
                "queued": True,
                "decision": decision,
                "request_id": clean_request_id,
                "command_id": command_id,
                "message": (
                    "The decision was queued for the protected PC."
                ),
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _queue_session_action(
        self,
        *,
        device_id: str,
        session_id: int,
        action: str,
        payload: dict[str, Any],
        session: sqlite3.Row,
    ) -> None:
        clean_device_id = safe_text(device_id, 100)
        expected_user_sid = safe_text(payload.get("user_sid"), 300)
        expected_username = safe_text(payload.get("username"), 300)
        if session_id <= 0:
            raise ValueError("A valid Windows session is required")
        if action not in {"lock", "logoff"}:
            raise ValueError("Unsupported session action")
        if not expected_user_sid:
            raise ValueError("The selected session has no user SID")

        now = datetime.now(timezone.utc)
        now_utc = now.isoformat()
        with db_connect(self.server.config) as db:
            device = db.execute(
                """
                SELECT * FROM devices
                WHERE id = ? AND revoked_utc IS NULL
                """,
                (clean_device_id,),
            ).fetchone()
            if device is None:
                self._json_response(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "device_not_found"},
                )
                return

            if not is_recent(
                device["last_seen_utc"],
                int(self.server.config["offline_after_seconds"]),
            ):
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "device_offline",
                        "message": (
                            "The protected PC is offline. "
                            "The session action was not queued."
                        ),
                    },
                )
                return

            command_secret_dpapi = str(
                device["command_secret_dpapi"] or ""
            )
            if (
                not command_secret_dpapi
                or not bool(device["command_channel_ready"])
            ):
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "device_command_channel_not_ready",
                        "message": (
                            "The protected PC command channel is not ready."
                        ),
                    },
                )
                return

            sessions = row_json(device, "sessions_json", [])
            if not isinstance(sessions, list):
                sessions = []
            target = next(
                (
                    value
                    for value in sessions
                    if isinstance(value, dict)
                    and int(value.get("session_id", -1)) == session_id
                ),
                None,
            )
            if target is None:
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "windows_session_not_found",
                        "message": (
                            "The selected Windows session is no longer "
                            "present on the protected PC."
                        ),
                    },
                )
                return

            actual_user_sid = safe_text(target.get("user_sid"), 300)
            actual_username = safe_text(target.get("username"), 300)
            if (
                not actual_user_sid
                or actual_user_sid != expected_user_sid
                or (
                    expected_username
                    and actual_username
                    and actual_username.casefold()
                    != expected_username.casefold()
                )
            ):
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "windows_session_identity_changed",
                        "message": (
                            "The selected Windows session changed identity. "
                            "Refresh the device and try again."
                        ),
                    },
                )
                return

            connection_state = safe_text(
                target.get("connection_state"),
                100,
            ).lower()
            if action == "lock" and connection_state == "disconnected":
                self._json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "error": "windows_session_already_disconnected",
                        "message": (
                            "The selected Windows session is already "
                            "disconnected or locked."
                        ),
                    },
                )
                return

            action_id = str(uuid.uuid4())
            command_id = str(uuid.uuid4())
            expires = now + timedelta(seconds=90)
            command_type = (
                "lock_session" if action == "lock" else "logoff_session"
            )
            command = {
                "command_id": command_id,
                "request_id": action_id,
                "type": command_type,
                "device_id": clean_device_id,
                "challenge_id": new_token(18),
                "session_id": session_id,
                "username": actual_username,
                "user_sid": actual_user_sid,
                "reason": f"administrator_requested_{action}",
                "approver_username": str(session["username"]),
                "issued_utc": now_utc,
                "expires_utc": expires.isoformat(),
                "nonce": new_token(24),
            }
            command_secret = decode_machine_secret(
                command_secret_dpapi
            )
            signature = sign_remote_command(
                command,
                command_secret,
            )
            db.execute(
                """
                INSERT INTO device_actions (
                    id, device_id, action_type, session_id,
                    username, user_sid, requested_utc, expires_utc,
                    status, requested_by_admin_id,
                    requested_by_username, command_id,
                    command_json, command_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    clean_device_id,
                    command_type,
                    session_id,
                    actual_username,
                    actual_user_sid,
                    now_utc,
                    expires.isoformat(),
                    "pending_delivery",
                    session["admin_id"],
                    session["username"],
                    command_id,
                    json.dumps(command, separators=(",", ":")),
                    signature,
                ),
            )

        central_audit(
            self.server.config,
            action="remote_session_action_queued",
            actor_type="admin",
            actor_id=str(session["username"]),
            target_type="device_action",
            target_id=action_id,
            remote_address=self.remote_address,
            details={
                "device_id": clean_device_id,
                "command_id": command_id,
                "action": action,
                "session_id": session_id,
                "username": actual_username,
                "user_sid": actual_user_sid,
                "authentication": "admin_session",
                "workstation_id": str(session["workstation_id"]),
            },
        )
        self._json_response(
            HTTPStatus.ACCEPTED,
            {
                "ok": True,
                "queued": True,
                "action_id": action_id,
                "command_id": command_id,
                "action": action,
                "session_id": session_id,
                "message": (
                    "The session action was queued for the protected PC."
                ),
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _device_command_result(
        self,
        payload: dict[str, Any],
    ) -> None:
        token = bearer_token(self.headers)
        if not token:
            self._json_response(
                HTTPStatus.UNAUTHORIZED,
                {"ok": False, "error": "device_authentication_required"},
            )
            return
        command_id = safe_text(payload.get("command_id"), 100)
        request_id = safe_text(payload.get("request_id"), 100)
        if not command_id or not request_id:
            raise ValueError("command_id and request_id are required")

        now = utc_now_iso()
        record_type = ""
        final_status = ""
        target_type = ""
        action_name = ""
        with db_connect(self.server.config) as db:
            device = db.execute(
                """
                SELECT * FROM devices
                WHERE token_hash = ? AND revoked_utc IS NULL
                """,
                (sha256_token(token),),
            ).fetchone()
            if device is None:
                self._json_response(
                    HTTPStatus.UNAUTHORIZED,
                    {"ok": False, "error": "invalid_device_token"},
                )
                return

            approval = db.execute(
                """
                SELECT * FROM approval_requests
                WHERE id = ? AND command_id = ? AND device_id = ?
                """,
                (request_id, command_id, device["id"]),
            ).fetchone()
            action = None
            if approval is None:
                action = db.execute(
                    """
                    SELECT * FROM device_actions
                    WHERE id = ? AND command_id = ? AND device_id = ?
                    """,
                    (request_id, command_id, device["id"]),
                ).fetchone()

            if approval is None and action is None:
                self._json_response(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "remote_command_not_found"},
                )
                return

            success = bool(payload.get("ok"))
            if approval is not None:
                record_type = "approval"
                command_type = str(approval["command_type"] or "")
                if success:
                    final_status = (
                        "approved"
                        if command_type == "approve_session"
                        else "denied"
                    )
                else:
                    final_status = "failed"
                db.execute(
                    """
                    UPDATE approval_requests SET
                        status = ?, completed_utc = ?, result_json = ?
                    WHERE id = ? AND command_id = ?
                    """,
                    (
                        final_status,
                        now,
                        json.dumps(payload, separators=(",", ":")),
                        request_id,
                        command_id,
                    ),
                )
                target_type = "approval_request"
                action_name = "remote_approval_command_completed"
            else:
                record_type = "session_action"
                final_status = "completed" if success else "failed"
                db.execute(
                    """
                    UPDATE device_actions SET
                        status = ?, completed_utc = ?, result_json = ?
                    WHERE id = ? AND command_id = ?
                    """,
                    (
                        final_status,
                        now,
                        json.dumps(payload, separators=(",", ":")),
                        request_id,
                        command_id,
                    ),
                )
                target_type = "device_action"
                action_name = "remote_session_action_completed"

        central_audit(
            self.server.config,
            action=action_name,
            actor_type="device",
            actor_id=str(device["id"]),
            target_type=target_type,
            target_id=request_id,
            remote_address=self.remote_address,
            details={
                "command_id": command_id,
                "record_type": record_type,
                "status": final_status,
                "success": bool(payload.get("ok")),
                "action": str(payload.get("action", "")),
                "error": str(payload.get("error", "")),
            },
        )
        self._json_response(
            HTTPStatus.OK,
            {
                "ok": True,
                "status": final_status,
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _delete_device(
        self,
        device_id: str,
        session: sqlite3.Row,
    ) -> None:
        clean_device_id = safe_text(device_id, 100)
        with db_connect(self.server.config) as db:
            row = db.execute(
                "SELECT * FROM devices WHERE id = ?",
                (clean_device_id,),
            ).fetchone()
            if row is None:
                self._json_response(
                    HTTPStatus.NOT_FOUND,
                    {
                        "ok": False,
                        "error": "device_not_found",
                        "message": "The device registration was not found.",
                    },
                )
                return

            details = {
                "display_name": row["display_name"],
                "hostname": row["hostname"],
                "last_seen_utc": row["last_seen_utc"],
                "endpoint_version": row["endpoint_version"],
            }
            db.execute(
                "DELETE FROM devices WHERE id = ?",
                (clean_device_id,),
            )

        central_audit(
            self.server.config,
            action="device_registration_removed",
            actor_type="admin",
            actor_id=str(session["username"]),
            target_type="device",
            target_id=clean_device_id,
            remote_address=self.remote_address,
            details=details,
        )
        self._json_response(
            HTTPStatus.OK,
            {
                "ok": True,
                "removed_device_id": clean_device_id,
                "api_version": REMOTE_API_VERSION,
            },
        )

    def _get_device_audit(
        self, device_id: str, limit: int, session: sqlite3.Row
    ) -> None:
        row = self._device_row(device_id)
        if row is None:
            self._json_response(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "device_not_found"},
            )
            return
        limit = max(1, min(limit, MAX_AUDIT_RECORDS))
        records = row_json(row, "audit_json", [])[:limit]
        self._json_response(
            HTTPStatus.OK,
            {"ok": True, "device_id": device_id, "records": records},
        )

    def _get_device_logs(self, device_id: str, session: sqlite3.Row) -> None:
        row = self._device_row(device_id)
        if row is None:
            self._json_response(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "device_not_found"},
            )
            return
        self._json_response(
            HTTPStatus.OK,
            {"ok": True, "device_id": device_id, "logs": row["logs_text"]},
        )

    def _get_central_audit(self, limit: int) -> None:
        limit = max(1, min(limit, 1000))
        with db_connect(self.server.config) as db:
            rows = db.execute(
                """
                SELECT * FROM central_audit
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        records = []
        for row in rows:
            records.append(
                {
                    "timestamp_utc": row["timestamp_utc"],
                    "action": row["action"],
                    "actor_type": row["actor_type"],
                    "actor_id": row["actor_id"],
                    "target_type": row["target_type"],
                    "target_id": row["target_id"],
                    "remote_address": row["remote_address"],
                    "details": row_json(row, "details_json", {}),
                }
            )
        self._json_response(HTTPStatus.OK, {"ok": True, "records": records})


def configure_logger() -> logging.Logger:
    REMOTE_SERVER_SECURE.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("WindowsLoginGuardRemoteServer")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(
            REMOTE_SERVER_LOG,
            maxBytes=2_000_000,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        logger.addHandler(handler)
    return logger


def build_server(config: dict[str, Any], logger: logging.Logger) -> ManagementServer:
    server = ManagementServer(config, logger)
    cert_path = Path(str(config.get("tls_cert_path", "")))
    key_path = Path(str(config.get("tls_key_path", "")))
    if cert_path.is_file() and key_path.is_file():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        logger.info("TLS enabled with certificate %s", cert_path)
    elif not bool(config.get("allow_insecure_http", False)):
        server.server_close()
        raise RuntimeError(
            "TLS certificate and key are required unless allow_insecure_http is enabled"
        )
    else:
        bind_address = str(config["bind_address"])
        if bind_address not in {"127.0.0.1", "localhost", "::1"}:
            server.server_close()
            raise RuntimeError(
                "Insecure HTTP may bind only to a loopback address"
            )
        logger.warning("Insecure loopback HTTP test mode is enabled")
    return server


class RemoteManagementService(win32serviceutil.ServiceFramework):
    _svc_name_ = REMOTE_SERVER_SERVICE
    _svc_display_name_ = "Windows Login Guard Management Server"
    _svc_description_ = (
        "Central read-only fleet management and device telemetry for "
        "Windows Login Guard."
    )

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.server: ManagementServer | None = None

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.server is not None:
            self.server.shutdown()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self) -> None:
        logger = configure_logger()
        try:
            config = load_server_config()
            initialize_database(config)
            self.server = build_server(config, logger)
            logger.info(
                "Management server v%s listening on %s:%s",
                APP_VERSION,
                config["bind_address"],
                config["port"],
            )
            self.server.serve_forever(poll_interval=0.5)
        except Exception:
            logger.exception("Management server stopped due to an error")
            raise
        finally:
            if self.server is not None:
                self.server.server_close()


def command_init(args: argparse.Namespace) -> int:
    REMOTE_SERVER_SECURE.mkdir(parents=True, exist_ok=True)
    config = default_server_config()
    config.update(
        {
            "bind_address": args.bind,
            "port": args.port,
            "tls_cert_path": str(Path(args.cert).resolve()) if args.cert else "",
            "tls_key_path": str(Path(args.key).resolve()) if args.key else "",
            "allow_insecure_http": bool(args.allow_insecure_http),
            "database_path": str(REMOTE_SERVER_DB),
        }
    )
    if args.allow_insecure_http and args.bind not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise ValueError("Insecure HTTP can bind only to loopback")
    if not args.allow_insecure_http and (not args.cert or not args.key):
        raise ValueError("--cert and --key are required for HTTPS")
    if not args.allow_insecure_http:
        if not Path(args.cert).is_file() or not Path(args.key).is_file():
            raise ValueError("The HTTPS certificate or private key file does not exist")
    atomic_write_json(REMOTE_SERVER_CONFIG, config)
    initialize_database(config)
    print(f"Server configuration written to {REMOTE_SERVER_CONFIG}")
    print(f"Database initialized at {REMOTE_SERVER_DB}")
    return 0


def command_create_admin(args: argparse.Namespace) -> int:
    config = load_server_config()
    initialize_database(config)
    username = safe_text(args.username, 200)
    if not username:
        raise ValueError("username is required")
    secret = pyotp.random_base32()
    encrypted = encode_machine_secret(secret)
    with db_connect(config) as db:
        db.execute(
            """
            INSERT INTO admins (
                username, totp_secret_dpapi, auth_source,
                windows_sid, enabled, created_utc
            ) VALUES (?, ?, 'server_totp', NULL, 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                totp_secret_dpapi = excluded.totp_secret_dpapi,
                auth_source = 'server_totp',
                windows_sid = NULL,
                enabled = 1
            """,
            (username, encrypted, utc_now_iso()),
        )
        db.execute(
            """
            DELETE FROM admin_sessions
            WHERE admin_id = (
                SELECT id FROM admins WHERE username = ? COLLATE NOCASE
            )
            """,
            (username,),
        )
    issuer = args.issuer or "Windows Login Guard Remote Management"
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    print("Administrator created or reset.")
    print(f"Username: {username}")
    print(f"TOTP secret: {secret}")
    print(f"Provisioning URI: {uri}")
    if args.qr:
        import qrcode

        output = Path(args.qr).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        qrcode.make(uri).save(output)
        print(f"QR code: {output}")
    print("Save the secret securely. It will not be displayed by the server UI.")
    central_audit(
        config,
        action="admin_created_or_reset",
        actor_type="server_cli",
        actor_id=os.environ.get("USERNAME", "local_administrator"),
        target_type="admin",
        target_id=username,
        details={},
    )
    return 0


def command_link_local_admin(args: argparse.Namespace) -> int:
    config = load_server_config()
    initialize_database(config)

    profile = _local_wlg_admin_profile(args.sid)
    username = str(profile["username"])

    server_url = validate_server_url(str(args.server_url), False)
    certificate_source = Path(args.cert).resolve()
    if not certificate_source.is_file():
        raise ValueError("The management-server certificate was not found")

    workstation_label = safe_text(
        args.workstation_label or f"{socket.gethostname()} - {username}",
        200,
    )
    workstation_id = str(uuid.uuid4())
    workstation_token = new_token(40)
    now = utc_now_iso()

    with db_connect(config) as db:
        existing_admin = db.execute(
            """
            SELECT id FROM admins
            WHERE windows_sid = ? OR username = ? COLLATE NOCASE
            ORDER BY CASE WHEN windows_sid = ? THEN 0 ELSE 1 END
            LIMIT 1
            """,
            (profile["windows_sid"], username, profile["windows_sid"]),
        ).fetchone()
        if existing_admin is None:
            db.execute(
                """
                INSERT INTO admins (
                    username, totp_secret_dpapi, auth_source,
                    windows_sid, enabled, created_utc
                ) VALUES (?, '', 'local_wlg', ?, 1, ?)
                """,
                (username, profile["windows_sid"], now),
            )
        else:
            db.execute(
                """
                UPDATE admins
                SET username = ?, totp_secret_dpapi = '',
                    auth_source = 'local_wlg', windows_sid = ?, enabled = 1
                WHERE id = ?
                """,
                (username, profile["windows_sid"], existing_admin["id"]),
            )
            db.execute(
                "DELETE FROM admin_sessions WHERE admin_id = ?",
                (existing_admin["id"],),
            )

        existing_workstation = db.execute(
            """
            SELECT id FROM workstations
            WHERE is_local_server = 1
            ORDER BY created_utc LIMIT 1
            """
        ).fetchone()
        if existing_workstation is not None:
            workstation_id = str(existing_workstation["id"])
            db.execute(
                """
                UPDATE workstations
                SET label = ?, token_hash = ?, last_seen_utc = ?,
                    revoked_utc = NULL, remote_address = '127.0.0.1',
                    is_local_server = 1
                WHERE id = ?
                """,
                (
                    workstation_label,
                    sha256_token(workstation_token),
                    now,
                    workstation_id,
                ),
            )
            db.execute(
                "DELETE FROM admin_sessions WHERE workstation_id = ?",
                (workstation_id,),
            )
        else:
            db.execute(
                """
                INSERT INTO workstations (
                    id, label, token_hash, created_utc,
                    last_seen_utc, remote_address, is_local_server
                ) VALUES (?, ?, ?, ?, ?, '127.0.0.1', 1)
                """,
                (
                    workstation_id,
                    workstation_label,
                    sha256_token(workstation_token),
                    now,
                    now,
                ),
            )

    REMOTE_ADMIN_DATA.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(certificate_source, REMOTE_ADMIN_CERT)
    REMOTE_ADMIN_TOKEN.write_bytes(protect_user_text(workstation_token))
    atomic_write_json(
        REMOTE_ADMIN_CONFIG,
        {
            "server_url": server_url,
            "ca_cert_path": str(REMOTE_ADMIN_CERT),
            "workstation_id": workstation_id,
            "workstation_label": workstation_label,
            "allow_insecure_http": False,
            "linked_username": username,
            "linked_windows_sid": str(profile["windows_sid"]),
            "linked_utc": now,
        },
    )

    central_audit(
        config,
        action="local_wlg_admin_linked",
        actor_type="local_wlg_admin",
        actor_id=username,
        target_type="workstation",
        target_id=workstation_id,
        remote_address="127.0.0.1",
        details={
            "windows_sid": profile["windows_sid"],
            "workstation_label": workstation_label,
        },
    )

    print("Existing Windows Login Guard administrator linked.")
    print(f"Administrator: {username}")
    print(f"Windows SID: {profile['windows_sid']}")
    print(f"Administrator computer: {workstation_label}")
    print("The existing Windows Login Guard OTP will be used at sign-in.")
    print("No additional OTP secret was created or copied.")
    return 0


def command_list_admins(_args: argparse.Namespace) -> int:
    config = load_server_config()
    initialize_database(config)
    with db_connect(config) as db:
        rows = db.execute(
            """
            SELECT username, auth_source, windows_sid,
                   enabled, created_utc, last_login_utc
            FROM admins ORDER BY username COLLATE NOCASE
            """
        ).fetchall()
    if not rows:
        print("No remote administrators are configured.")
        return 0
    for row in rows:
        state = "enabled" if row["enabled"] else "disabled"
        print(
            f"{row['username']}  {state}  source={row['auth_source']}  "
            f"sid={row['windows_sid'] or '-'}  "
            f"created={row['created_utc']}  "
            f"last_login={row['last_login_utc'] or 'never'}"
        )
    return 0


def command_set_admin_state(args: argparse.Namespace) -> int:
    config = load_server_config()
    username = safe_text(args.username, 200)
    enabled = 1 if args.state == "enabled" else 0
    with db_connect(config) as db:
        row = db.execute(
            "SELECT id FROM admins WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if row is None:
            raise ValueError("Remote administrator was not found")
        db.execute(
            "UPDATE admins SET enabled = ? WHERE id = ?",
            (enabled, row["id"]),
        )
        if not enabled:
            db.execute(
                "DELETE FROM admin_sessions WHERE admin_id = ?",
                (row["id"],),
            )
    central_audit(
        config,
        action=f"admin_{args.state}",
        actor_type="server_cli",
        actor_id=os.environ.get("USERNAME", "local_administrator"),
        target_type="admin",
        target_id=username,
        details={},
    )
    print(f"Central administrator {username} is now {args.state}.")
    return 0


def command_create_enrollment(args: argparse.Namespace) -> int:
    config = load_server_config()
    initialize_database(config)
    kind = args.kind
    label = safe_text(args.label, 200)
    if not label:
        raise ValueError("label is required")
    token = new_token(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=args.hours)
    with db_connect(config) as db:
        db.execute(
            """
            INSERT INTO enrollment_tokens (
                kind, token_hash, label, created_utc, expires_utc
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (kind, sha256_token(token), label, now.isoformat(), expires.isoformat()),
        )
    registration_name = (
        "Protected-device"
        if kind == "device"
        else "Admin-computer"
    )
    print(f"{registration_name} registration code created.")
    print(f"Label: {label}")
    print(f"Expires UTC: {expires.isoformat()}")
    print(f"Registration code: {token}")
    print(
        "This registration code is single-use and is not recoverable "
        "after this output."
    )
    central_audit(
        config,
        action=f"{kind}_enrollment_token_created",
        actor_type="server_cli",
        actor_id=os.environ.get("USERNAME", "local_administrator"),
        target_type=kind,
        target_id=label,
        details={"expires_utc": expires.isoformat()},
    )
    return 0


def command_list_devices(_args: argparse.Namespace) -> int:
    config = load_server_config()
    initialize_database(config)
    with db_connect(config) as db:
        rows = db.execute(
            """
            SELECT id, display_name, hostname, last_seen_utc,
                   endpoint_version, revoked_utc
            FROM devices ORDER BY display_name COLLATE NOCASE
            """
        ).fetchall()
    if not rows:
        print("No devices are registered.")
        return 0
    for row in rows:
        status = "revoked" if row["revoked_utc"] else "registered"
        print(
            f"{row['id']}  {row['display_name']}  {row['hostname']}  "
            f"{status}  last={row['last_seen_utc'] or 'never'}  "
            f"version={row['endpoint_version'] or 'unknown'}"
        )
    return 0


def command_list_workstations(_args: argparse.Namespace) -> int:
    config = load_server_config()
    initialize_database(config)
    with db_connect(config) as db:
        rows = db.execute(
            """
            SELECT id, label, created_utc, last_seen_utc,
                   remote_address, revoked_utc
            FROM workstations ORDER BY label COLLATE NOCASE
            """
        ).fetchall()
    if not rows:
        print("No administrator workstations are registered.")
        return 0
    for row in rows:
        status = "revoked" if row["revoked_utc"] else "registered"
        print(
            f"{row['id']}  {row['label']}  {status}  "
            f"last={row['last_seen_utc'] or 'never'}  "
            f"address={row['remote_address'] or 'unknown'}"
        )
    return 0


def command_revoke(args: argparse.Namespace) -> int:
    config = load_server_config()
    table = "devices" if args.kind == "device" else "workstations"
    with db_connect(config) as db:
        cursor = db.execute(
            f"UPDATE {table} SET revoked_utc = ? WHERE id = ? AND revoked_utc IS NULL",
            (utc_now_iso(), args.id),
        )
    if cursor.rowcount != 1:
        raise ValueError(f"Active {args.kind} was not found")
    central_audit(
        config,
        action=f"{args.kind}_revoked",
        actor_type="server_cli",
        actor_id=os.environ.get("USERNAME", "local_administrator"),
        target_type=args.kind,
        target_id=args.id,
        details={},
    )
    print(f"{args.kind.title()} revoked: {args.id}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Windows Login Guard central management server"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--bind", default="0.0.0.0")
    init_parser.add_argument("--port", type=int, default=8443)
    init_parser.add_argument("--cert", default="")
    init_parser.add_argument("--key", default="")
    init_parser.add_argument("--allow-insecure-http", action="store_true")
    init_parser.set_defaults(handler=command_init)

    admin_parser = subparsers.add_parser("create-admin")
    admin_parser.add_argument("--username", required=True)
    admin_parser.add_argument("--issuer", default="")
    admin_parser.add_argument("--qr", default="")
    admin_parser.set_defaults(handler=command_create_admin)

    link_admin_parser = subparsers.add_parser("link-local-admin")
    link_admin_parser.add_argument("--sid", required=True)
    link_admin_parser.add_argument("--server-url", required=True)
    link_admin_parser.add_argument("--cert", required=True)
    link_admin_parser.add_argument("--workstation-label", default="")
    link_admin_parser.set_defaults(handler=command_link_local_admin)

    list_admins_parser = subparsers.add_parser("list-admins")
    list_admins_parser.set_defaults(handler=command_list_admins)

    admin_state_parser = subparsers.add_parser("set-admin-state")
    admin_state_parser.add_argument("--username", required=True)
    admin_state_parser.add_argument(
        "--state", choices=["enabled", "disabled"], required=True
    )
    admin_state_parser.set_defaults(handler=command_set_admin_state)

    enrollment_parser = subparsers.add_parser("create-enrollment-token")
    enrollment_parser.add_argument(
        "--kind", choices=["device", "workstation"], required=True
    )
    enrollment_parser.add_argument("--label", required=True)
    enrollment_parser.add_argument("--hours", type=int, default=24)
    enrollment_parser.set_defaults(handler=command_create_enrollment)

    list_parser = subparsers.add_parser("list-devices")
    list_parser.set_defaults(handler=command_list_devices)

    workstation_list_parser = subparsers.add_parser("list-workstations")
    workstation_list_parser.set_defaults(handler=command_list_workstations)

    revoke_parser = subparsers.add_parser("revoke")
    revoke_parser.add_argument("--kind", choices=["device", "workstation"], required=True)
    revoke_parser.add_argument("--id", required=True)
    revoke_parser.set_defaults(handler=command_revoke)
    return parser


def main() -> int:
    custom_commands = {
        "init",
        "create-admin",
        "link-local-admin",
        "list-admins",
        "set-admin-state",
        "create-enrollment-token",
        "list-devices",
        "list-workstations",
        "revoke",
    }
    if len(sys.argv) > 1 and sys.argv[1] in custom_commands:
        parser = build_parser()
        args = parser.parse_args()
        if getattr(args, "hours", 1) < 1 or getattr(args, "hours", 1) > 168:
            raise ValueError("hours must be between 1 and 168")
        return int(args.handler(args))
    win32serviceutil.HandleCommandLine(RemoteManagementService)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
