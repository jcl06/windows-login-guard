from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import win32event
import winreg
import win32service
import win32serviceutil

from common import (
    HOST,
    LOG_PATH,
    MANAGEMENT_TOKEN_PATH,
    PORT_FILE,
    recv_json,
    send_json,
)
from remote_common import (
    REMOTE_API_VERSION,
    REMOTE_AGENT_CONFIG,
    REMOTE_AGENT_COMMAND_SECRET,
    REMOTE_AGENT_COMMAND_STATE,
    REMOTE_AGENT_LOG,
    REMOTE_AGENT_SERVICE,
    REMOTE_AGENT_TOKEN,
    atomic_write_json,
    hostname,
    http_json,
    protect_machine_text,
    read_json,
    safe_text,
    unprotect_machine_text,
    utc_now_iso,
    verify_remote_command,
    parse_utc,
    validate_server_url,
)

APP_VERSION = Path(__file__).with_name("VERSION").read_text(
    encoding="utf-8"
).strip()
DEFAULT_SYNC_INTERVAL = 10
MAX_RETRY_INTERVAL_SECONDS = 15 * 60



def retry_delay_seconds(
    normal_interval: int,
    consecutive_failures: int,
) -> int:
    """Return exponential retry delay capped at fifteen minutes."""
    safe_interval = max(5, int(normal_interval))
    failure_count = max(1, int(consecutive_failures))
    delay = safe_interval * (2 ** (failure_count - 1))
    return min(delay, MAX_RETRY_INTERVAL_SECONDS)


def machine_identity() -> str:
    """Return a stable, non-secret hash for this Windows installation."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        normalized = str(machine_guid).strip().lower()
        if normalized:
            return hashlib.sha256(
                normalized.encode("utf-8")
            ).hexdigest()
    except OSError:
        pass

    fallback = "|".join(
        [
            hostname().lower(),
            platform.platform().lower(),
        ]
    )
    return hashlib.sha256(fallback.encode("utf-8")).hexdigest()


class LocalAdminClient:
    def __init__(self) -> None:
        self.token = MANAGEMENT_TOKEN_PATH.read_text(
            encoding="ascii"
        ).strip()

    def request(self, payload: dict[str, Any], timeout: float = 8.0) -> dict[str, Any]:
        try:
            port = int(PORT_FILE.read_text(encoding="ascii").strip())
            with socket.create_connection((HOST, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                send_json(
                    sock,
                    {"session_id": -1, "token": self.token, **payload},
                )
                response = recv_json(sock)
                if not isinstance(response, dict):
                    raise RuntimeError("Local service returned an invalid response")
                return response
        except Exception as exc:
            return {
                "ok": False,
                "error": "local_service_unavailable",
                "message": str(exc),
            }


def load_agent_config() -> dict[str, Any]:
    config = read_json(REMOTE_AGENT_CONFIG, {})
    if not isinstance(config, dict):
        raise ValueError("remote-agent.json must contain an object")
    required = ["server_url", "device_id", "ca_cert_path"]
    for key in required:
        if not str(config.get(key, "")).strip():
            raise ValueError(f"{key} is required in remote-agent.json")
    interval = config.get("sync_interval_seconds", DEFAULT_SYNC_INTERVAL)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 5 <= interval <= 300:
        raise ValueError("sync_interval_seconds must be between 5 and 300")
    config["sync_interval_seconds"] = interval
    config["display_name"] = safe_text(
        config.get("display_name") or hostname(), 200
    )
    config["allow_insecure_http"] = bool(config.get("allow_insecure_http", False))
    config["server_url"] = validate_server_url(
        str(config["server_url"]), config["allow_insecure_http"]
    )
    return config


def read_device_token() -> str:
    return unprotect_machine_text(REMOTE_AGENT_TOKEN.read_bytes())


def redact_log_line(line: str) -> str:
    value = line
    patterns = [
        r"(?i)(otp|totp|code|token|secret|recovery[_ -]?key)\s*[=:]\s*\S+",
        r"(?i)(authorization)\s*:\s*bearer\s+\S+",
    ]
    for pattern in patterns:
        value = re.sub(pattern, r"\1=[REDACTED]", value)
    return value


def tail_service_log(max_lines: int = 500) -> str:
    try:
        lines = LOG_PATH.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError as exc:
        return f"Service log unavailable: {exc}"
    return "\n".join(redact_log_line(line) for line in lines[-max_lines:])


def read_command_secret() -> str:
    try:
        return unprotect_machine_text(
            REMOTE_AGENT_COMMAND_SECRET.read_bytes()
        )
    except OSError:
        return ""


def store_command_secret(secret: str) -> None:
    value = str(secret).strip()
    if not value:
        return
    REMOTE_AGENT_COMMAND_SECRET.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    REMOTE_AGENT_COMMAND_SECRET.write_bytes(
        protect_machine_text(value)
    )


def read_command_state() -> dict[str, Any]:
    value = read_json(
        REMOTE_AGENT_COMMAND_STATE,
        {"processed": []},
    )
    if not isinstance(value, dict):
        return {"processed": []}
    processed = value.get("processed", [])
    if not isinstance(processed, list):
        processed = []
    value["processed"] = processed[-100:]
    return value


def remember_command_result(
    command_id: str,
    result: dict[str, Any],
) -> None:
    state = read_command_state()
    processed = [
        item
        for item in state.get("processed", [])
        if isinstance(item, dict)
        and str(item.get("command_id", "")) != command_id
    ]
    processed.append(
        {
            "command_id": command_id,
            "result": result,
            "processed_utc": utc_now_iso(),
        }
    )
    atomic_write_json(
        REMOTE_AGENT_COMMAND_STATE,
        {"processed": processed[-100:]},
    )


def previous_command_result(
    command_id: str,
) -> dict[str, Any] | None:
    for item in read_command_state().get("processed", []):
        if (
            isinstance(item, dict)
            and str(item.get("command_id", "")) == command_id
            and isinstance(item.get("result"), dict)
        ):
            return dict(item["result"])
    return None


def validate_remote_command(
    command: dict[str, Any],
    *,
    config: dict[str, Any],
    secret: str,
) -> None:
    if not verify_remote_command(command, secret):
        raise ValueError("Remote command signature is invalid")
    if str(command.get("device_id", "")) != str(config["device_id"]):
        raise ValueError("Remote command is for another device")
    command_type = str(command.get("type", ""))
    if command_type not in {
        "approve_session",
        "deny_session",
        "lock_session",
        "logoff_session",
    }:
        raise ValueError("Remote command type is unsupported")
    command_id = safe_text(command.get("command_id"), 100)
    request_id = safe_text(command.get("request_id"), 100)
    challenge_id = safe_text(command.get("challenge_id"), 200)
    if not command_id or not request_id or not challenge_id:
        raise ValueError("Remote command binding is incomplete")
    expires = parse_utc(str(command.get("expires_utc", "")))
    now = datetime.now(timezone.utc)
    if expires <= now:
        raise ValueError("Remote command has expired")
    issued = parse_utc(str(command.get("issued_utc", "")))
    if issued > now + timedelta(minutes=2):
        raise ValueError("Remote command issue time is invalid")


def execute_remote_command(
    command: dict[str, Any],
    *,
    config: dict[str, Any],
    secret: str,
) -> dict[str, Any]:
    command_id = safe_text(command.get("command_id"), 100)
    previous = previous_command_result(command_id)
    if previous is not None:
        return previous

    try:
        validate_remote_command(
            command,
            config=config,
            secret=secret,
        )
        local = LocalAdminClient()
        local_payload: dict[str, Any] = {
            "target_session_id": int(command.get("session_id", -1)),
            "challenge_id": str(command.get("challenge_id", "")),
            "target_user_sid": str(command.get("user_sid", "")),
            "request_id": str(command.get("request_id", "")),
            "approver_name": str(
                command.get("approver_username", "Remote administrator")
            ),
        }
        command_type = str(command.get("type"))
        if command_type == "approve_session":
            local_payload.update(
                {
                    "action": "remote_approve_session",
                    "duration": str(command.get("duration", "")),
                }
            )
        elif command_type == "deny_session":
            local_payload["action"] = "remote_deny_session"
        elif command_type == "lock_session":
            local_payload["action"] = "remote_lock_session"
        elif command_type == "logoff_session":
            local_payload["action"] = "remote_logoff_session"
        else:
            raise ValueError("Remote command type is unsupported")

        local_response = local.request(local_payload, timeout=10.0)
        result = {
            "command_id": command_id,
            "request_id": str(command.get("request_id", "")),
            "ok": bool(local_response.get("ok")),
            "action": str(command.get("type", "")),
            "local_response": local_response,
            "processed_utc": utc_now_iso(),
        }
    except Exception as exc:
        result = {
            "command_id": command_id,
            "request_id": str(command.get("request_id", "")),
            "ok": False,
            "action": str(command.get("type", "")),
            "error": str(exc),
            "processed_utc": utc_now_iso(),
        }

    if command_id:
        remember_command_result(command_id, result)
    return result


def report_command_result(
    config: dict[str, Any],
    result: dict[str, Any],
) -> None:
    http_json(
        method="POST",
        url=(
            f"{config['server_url']}"
            "/api/v1/devices/command-results"
        ),
        payload=result,
        bearer_token=read_device_token(),
        ca_cert_path=str(config.get("ca_cert_path") or "") or None,
        timeout=20.0,
    )


def build_snapshot() -> dict[str, Any]:
    try:
        local = LocalAdminClient()
        dashboard = local.request({"action": "admin_dashboard"})
        diagnostics = local.request({"action": "admin_diagnostics"})
        audit = local.request({"action": "admin_audit", "limit": 500})
    except Exception as exc:
        unavailable = {
            "ok": False,
            "error": "local_service_unavailable",
            "message": str(exc),
        }
        dashboard = dict(unavailable)
        diagnostics = dict(unavailable)
        audit = dict(unavailable)

    local_errors = []
    for name, response in (
        ("dashboard", dashboard),
        ("diagnostics", diagnostics),
        ("audit", audit),
    ):
        if not response.get("ok"):
            local_errors.append(
                f"{name}: {response.get('message') or response.get('error')}"
            )

    sessions = dashboard.get("sessions", []) if dashboard.get("ok") else []
    records = audit.get("records", []) if audit.get("ok") else []
    return {
        "hostname": hostname(),
        "endpoint_version": APP_VERSION,
        "operating_system": platform.platform(),
        "dashboard": dashboard if dashboard.get("ok") else {
            "ok": False,
            "overall_health": "critical",
            "error": dashboard.get("message") or dashboard.get("error"),
        },
        "sessions": sessions if isinstance(sessions, list) else [],
        "diagnostics": diagnostics if diagnostics.get("ok") else {
            "ok": False,
            "error": diagnostics.get("message") or diagnostics.get("error"),
        },
        "audit": records if isinstance(records, list) else [],
        "logs": tail_service_log(),
        "agent_status": "degraded" if local_errors else "online",
        "last_error": "; ".join(local_errors),
        "collected_utc": utc_now_iso(),
    }


def sync_once(config: dict[str, Any], logger: logging.Logger | None = None) -> dict[str, Any]:
    payload = build_snapshot()
    payload["display_name"] = config["display_name"]
    payload["device_id"] = config["device_id"]
    command_secret = read_command_secret()
    payload["command_secret_ready"] = bool(command_secret)
    response = http_json(
        method="POST",
        url=f"{config['server_url']}/api/v1/devices/sync",
        payload=payload,
        bearer_token=read_device_token(),
        ca_cert_path=str(config.get("ca_cert_path") or "") or None,
        timeout=20.0,
    )
    if int(response.get("api_version", -1)) != REMOTE_API_VERSION:
        raise RuntimeError(
            "The management server API version is not compatible with this Remote Agent"
        )

    bootstrap_secret = str(response.get("command_secret", "")).strip()
    if bootstrap_secret:
        store_command_secret(bootstrap_secret)
        command_secret = bootstrap_secret

    commands = response.get("commands", [])
    if not isinstance(commands, list):
        raise RuntimeError("Management server returned an invalid command list")
    for command in commands[:20]:
        if not isinstance(command, dict):
            continue
        result = execute_remote_command(
            command,
            config=config,
            secret=command_secret,
        )
        try:
            report_command_result(config, result)
        except Exception:
            if logger:
                logger.exception(
                    "Could not report remote command result: command=%s",
                    result.get("command_id", ""),
                )

    if logger:
        logger.info(
            "Remote synchronization completed: device=%s status=%s commands=%s",
            config["device_id"],
            payload["agent_status"],
            len(commands),
        )
    return response


def configure_logger() -> logging.Logger:
    REMOTE_AGENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("WindowsLoginGuardRemoteAgent")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(
            REMOTE_AGENT_LOG,
            maxBytes=1_000_000,
            backupCount=4,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        logger.addHandler(handler)
    return logger


class RemoteAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = REMOTE_AGENT_SERVICE
    _svc_display_name_ = "Windows Login Guard Remote Agent"
    _svc_description_ = (
        "Sends read-only Windows Login Guard health, session, audit, log, "
        "and diagnostic data to the configured central management server."
    )

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.stop_requested = threading.Event()

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_requested.set()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self) -> None:
        logger = configure_logger()
        logger.info("Remote Agent v%s starting", APP_VERSION)
        consecutive_failures = 0

        while not self.stop_requested.is_set():
            normal_interval = DEFAULT_SYNC_INTERVAL
            try:
                config = load_agent_config()
                normal_interval = int(config["sync_interval_seconds"])
                sync_once(config, logger)

                if consecutive_failures:
                    logger.info(
                        "Management server connectivity restored after "
                        "%s failed synchronization attempt(s); returning "
                        "to the normal %s-second interval",
                        consecutive_failures,
                        normal_interval,
                    )
                consecutive_failures = 0
                wait_seconds = normal_interval
            except Exception:
                consecutive_failures += 1
                wait_seconds = retry_delay_seconds(
                    normal_interval,
                    consecutive_failures,
                )
                logger.exception(
                    "Remote synchronization failed; retry attempt %s "
                    "will run in %s second(s)",
                    consecutive_failures,
                    wait_seconds,
                )

            self.stop_requested.wait(wait_seconds)

        logger.info("Remote Agent stopped")


def command_register(args: argparse.Namespace) -> int:
    server_url = validate_server_url(args.server, args.allow_insecure_http)
    ca_cert = str(Path(args.ca_cert).resolve()) if args.ca_cert else ""
    if server_url.startswith("https://") and not ca_cert:
        raise ValueError("--ca-cert is required for HTTPS certificate validation")

    display_name = safe_text(args.display_name or hostname(), 200)
    response = http_json(
        method="POST",
        url=f"{server_url}/api/v1/devices/register",
        payload={
            "enrollment_token": args.enrollment_token,
            "hostname": hostname(),
            "machine_identity": machine_identity(),
            "display_name": display_name,
            "endpoint_version": APP_VERSION,
            "operating_system": platform.platform(),
        },
        ca_cert_path=ca_cert or None,
        timeout=20.0,
    )
    if not response.get("ok"):
        raise RuntimeError(str(response.get("message") or response.get("error")))
    if int(response.get("api_version", -1)) != REMOTE_API_VERSION:
        raise RuntimeError(
            "The management server API version is not compatible with this Remote Agent"
        )

    REMOTE_AGENT_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    REMOTE_AGENT_TOKEN.write_bytes(
        protect_machine_text(str(response["device_token"]))
    )
    command_secret = str(response.get("command_secret", "")).strip()
    if command_secret:
        store_command_secret(command_secret)
    config = {
        "server_url": server_url,
        "device_id": str(response["device_id"]),
        "display_name": display_name,
        "ca_cert_path": ca_cert,
        "sync_interval_seconds": max(5, min(int(args.sync_interval), 300)),
        "allow_insecure_http": bool(args.allow_insecure_http),
        "registered_utc": utc_now_iso(),
    }
    atomic_write_json(REMOTE_AGENT_CONFIG, config)
    print("Protected device registered for remote management.")
    print(f"Device ID: {config['device_id']}")
    print(f"Display name: {display_name}")
    print(f"Server: {server_url}")
    return 0


def command_test(_args: argparse.Namespace) -> int:
    config = load_agent_config()
    response = sync_once(config)
    print(json.dumps(response, indent=2, sort_keys=True))
    return 0


def command_status(_args: argparse.Namespace) -> int:
    config = load_agent_config()
    safe_config = dict(config)
    safe_config["device_token"] = "stored with machine DPAPI"
    print(json.dumps(safe_config, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Windows Login Guard outbound remote-management agent"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register")
    register.add_argument("--server", required=True)
    register.add_argument("--enrollment-token", required=True)
    register.add_argument("--display-name", default="")
    register.add_argument("--ca-cert", default="")
    register.add_argument("--sync-interval", type=int, default=10)
    register.add_argument("--allow-insecure-http", action="store_true")
    register.set_defaults(handler=command_register)

    test = subparsers.add_parser("test")
    test.set_defaults(handler=command_test)

    status = subparsers.add_parser("status")
    status.set_defaults(handler=command_status)
    return parser


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in {"register", "test", "status"}:
        args = build_parser().parse_args()
        return int(args.handler(args))
    win32serviceutil.HandleCommandLine(RemoteAgentService)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
