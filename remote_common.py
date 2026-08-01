from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REMOTE_API_VERSION = 1
REMOTE_SERVER_APP = "WindowsLoginGuardRemoteServer"
REMOTE_AGENT_SERVICE = "WindowsLoginGuardRemoteAgent"
REMOTE_SERVER_SERVICE = "WindowsLoginGuardManagementServer"

PROGRAM_DATA = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
REMOTE_SERVER_DATA = PROGRAM_DATA / REMOTE_SERVER_APP
REMOTE_SERVER_SECURE = REMOTE_SERVER_DATA / "secure"
REMOTE_SERVER_CONFIG = REMOTE_SERVER_SECURE / "server.json"
REMOTE_SERVER_DB = REMOTE_SERVER_SECURE / "management.db"
REMOTE_SERVER_LOG = REMOTE_SERVER_SECURE / "server.log"

WLG_DATA = PROGRAM_DATA / "WindowsLoginGuard"
WLG_SECURE = WLG_DATA / "secure"
WLG_USERS = WLG_SECURE / "users"
REMOTE_AGENT_CONFIG = WLG_SECURE / "remote-agent.json"
REMOTE_AGENT_TOKEN = WLG_SECURE / "remote-device-token.dpapi"
REMOTE_AGENT_COMMAND_SECRET = WLG_SECURE / "remote-command-secret.dpapi"
REMOTE_AGENT_COMMAND_STATE = WLG_SECURE / "remote-command-state.json"
REMOTE_AGENT_LOG = WLG_SECURE / "remote-agent.log"

REMOTE_ADMIN_DATA = (
    Path(os.environ.get("APPDATA", str(Path.home())))
    / "WindowsLoginGuardRemoteAdmin"
)
REMOTE_ADMIN_CONFIG = REMOTE_ADMIN_DATA / "client.json"
REMOTE_ADMIN_TOKEN = REMOTE_ADMIN_DATA / "workstation-token.dpapi"
REMOTE_ADMIN_CERT = REMOTE_ADMIN_DATA / "management-server.crt"

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_LOG_TEXT_BYTES = 512 * 1024
MAX_AUDIT_RECORDS = 1000


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_utc(value: str) -> datetime:
    normalized = str(value).strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def sha256_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token(byte_count: int = 32) -> str:
    return secrets.token_urlsafe(byte_count)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_remote_command(command: dict[str, Any], secret: str) -> str:
    unsigned = {
        key: value
        for key, value in command.items()
        if key != "signature"
    }
    return hmac.new(
        secret.encode("utf-8"),
        canonical_json_bytes(unsigned),
        hashlib.sha256,
    ).hexdigest()


def verify_remote_command(
    command: dict[str, Any],
    secret: str,
) -> bool:
    provided = str(command.get("signature", "")).strip().lower()
    if len(provided) != 64:
        return False
    expected = sign_remote_command(command, secret)
    return hmac.compare_digest(provided, expected)


def constant_time_token_match(value: str, expected_hash: str) -> bool:
    return hmac.compare_digest(sha256_token(value), expected_hash)


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return default


def protect_machine_text(value: str) -> bytes:
    import win32crypt

    return win32crypt.CryptProtectData(
        value.encode("utf-8"),
        "Windows Login Guard Remote Management",
        None,
        None,
        None,
        0x4,
    )


def unprotect_machine_text(blob: bytes) -> str:
    import win32crypt

    _description, plaintext = win32crypt.CryptUnprotectData(
        blob, None, None, None, 0
    )
    return plaintext.decode("utf-8")


def protect_user_text(value: str) -> bytes:
    import win32crypt

    return win32crypt.CryptProtectData(
        value.encode("utf-8"),
        "Windows Login Guard Remote Administration",
        None,
        None,
        None,
        0,
    )


def unprotect_user_text(blob: bytes) -> str:
    import win32crypt

    _description, plaintext = win32crypt.CryptUnprotectData(
        blob, None, None, None, 0
    )
    return plaintext.decode("utf-8")


def encode_machine_secret(value: str) -> str:
    return base64.b64encode(protect_machine_text(value)).decode("ascii")


def decode_machine_secret(value: str) -> str:
    return unprotect_machine_text(base64.b64decode(value.encode("ascii")))


def ssl_context(ca_cert_path: str | None) -> ssl.SSLContext:
    context = (
        ssl.create_default_context(cafile=ca_cert_path)
        if ca_cert_path
        else ssl.create_default_context()
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def validate_server_url(url: str, allow_insecure_http: bool = False) -> str:
    normalized = str(url).strip().rstrip("/")
    if normalized.startswith("https://"):
        return normalized
    if allow_insecure_http and normalized.startswith("http://"):
        host = normalized.split("://", 1)[1].split("/", 1)[0]
        hostname = host.split(":", 1)[0].strip("[]").lower()
        if hostname in {"127.0.0.1", "localhost", "::1"}:
            return normalized
        raise ValueError(
            "Insecure HTTP is permitted only for a loopback test server"
        )
    raise ValueError("Remote management requires an HTTPS server URL")


def http_json(
    *,
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    bearer_token: str | None = None,
    workstation_token: str | None = None,
    ca_cert_path: str | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    body = None
    headers = {
        "Accept": "application/json",
        "User-Agent": f"WindowsLoginGuardRemote/{REMOTE_API_VERSION}",
    }
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_JSON_BYTES:
            raise ValueError("Remote request is too large")
        headers["Content-Type"] = "application/json"
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    if workstation_token:
        headers["X-WLG-Workstation-Token"] = workstation_token

    request = urllib.request.Request(
        url=url,
        data=body,
        headers=headers,
        method=method.upper(),
    )
    context = ssl_context(ca_cert_path) if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=context,
        ) as response:
            raw = response.read(MAX_JSON_BYTES + 1)
            if len(raw) > MAX_JSON_BYTES:
                raise ValueError("Remote response is too large")
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
            if not isinstance(parsed, dict):
                raise ValueError("Remote response must be a JSON object")
            return parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_JSON_BYTES)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = {}
        message = str(parsed.get("message") or parsed.get("error") or exc.reason)
        raise RuntimeError(f"Remote server returned HTTP {exc.code}: {message}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Remote server connection failed: {exc.reason}") from exc


def hostname() -> str:
    return socket.gethostname()


def safe_text(value: Any, maximum: int = 500) -> str:
    text = str(value or "").replace("\x00", "").strip()
    return text[:maximum]


def truncate_utf8(value: str, maximum_bytes: int) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return value
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore")
