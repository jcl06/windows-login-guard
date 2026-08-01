from __future__ import annotations

import base64
import ctypes
import hashlib
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from remote_common import (
    REMOTE_ADMIN_CONFIG,
    REMOTE_ADMIN_DATA,
    REMOTE_ADMIN_TOKEN,
    REMOTE_API_VERSION,
    atomic_write_json,
    http_json,
    read_json,
    unprotect_user_text,
)

POLL_SECONDS = 5
ERROR_RETRY_SECONDS = 30
STATE_PATH = REMOTE_ADMIN_DATA / "approval-notifier-state.json"
LOG_PATH = (
    Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    / "WindowsLoginGuardRemoteAdmin"
    / "approval-notifier.log"
)


def configure_logging() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=LOG_PATH,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )


def acquire_single_instance() -> bool:
    identity = hashlib.sha256(
        str(Path.home()).lower().encode("utf-8")
    ).hexdigest()[:16]
    name = f"Local\\WindowsLoginGuardApprovalNotifier-{identity}"
    handle = ctypes.windll.kernel32.CreateMutexW(
        None,
        False,
        name,
    )
    if not handle:
        return False
    return ctypes.windll.kernel32.GetLastError() != 183


def encoded(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def show_notification(
    *,
    title: str,
    message: str,
    open_script: Path,
) -> None:
    title_data = encoded(title)
    message_data = encoded(message)
    script_data = encoded(str(open_script))

    powershell = rf"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Decode([string]$Value) {{
    return [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($Value)
    )
}}

$title = Decode '{title_data}'
$message = Decode '{message_data}'
$openScript = Decode '{script_data}'

$notification = New-Object System.Windows.Forms.NotifyIcon
$notification.Icon = [System.Drawing.SystemIcons]::Shield
$notification.BalloonTipIcon = (
    [System.Windows.Forms.ToolTipIcon]::Info
)
$notification.BalloonTipTitle = $title
$notification.BalloonTipText = $message
$notification.Text = 'Windows Login Guard'
$notification.Visible = $true

$notification.add_BalloonTipClicked({{
    Start-Process `
        -FilePath powershell.exe `
        -ArgumentList @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', ('"' + $openScript + '"')
        )
}})

$notification.ShowBalloonTip(12000)
[System.Media.SystemSounds]::Exclamation.Play()
Start-Sleep -Seconds 13
$notification.Dispose()
"""
    encoded_script = base64.b64encode(
        powershell.encode("utf-16le")
    ).decode("ascii")

    subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            encoded_script,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def load_client() -> tuple[dict[str, Any], str] | None:
    config = read_json(REMOTE_ADMIN_CONFIG, {})
    if not isinstance(config, dict) or not REMOTE_ADMIN_TOKEN.is_file():
        return None
    server_url = str(config.get("server_url", "")).rstrip("/")
    if not server_url:
        return None
    token = unprotect_user_text(REMOTE_ADMIN_TOKEN.read_bytes())
    if not token:
        return None
    return config, token


def load_seen_ids() -> set[str]:
    state = read_json(STATE_PATH, {})
    if not isinstance(state, dict):
        return set()
    values = state.get("seen_pending_ids", [])
    if not isinstance(values, list):
        return set()
    return {
        str(value)
        for value in values
        if str(value).strip()
    }


def save_seen_ids(values: set[str]) -> None:
    atomic_write_json(
        STATE_PATH,
        {
            "seen_pending_ids": sorted(values),
            "updated_utc": time.time(),
        },
    )


def notification_message(
    requests: list[dict[str, Any]],
) -> str:
    if len(requests) == 1:
        request = requests[0]
        return (
            f"{request.get('username', 'A user')} requested approval on "
            f"{request.get('device_display_name', 'a protected PC')} "
            f"(session {request.get('session_id', 'unknown')}). "
            "Select this notification to open Remote Administration."
        )
    return (
        f"{len(requests)} new login approval requests are waiting. "
        "Select this notification to open Remote Administration."
    )


def run() -> int:
    configure_logging()
    if not acquire_single_instance():
        return 0

    logging.info("Approval notifier started")
    open_script = Path(__file__).with_name("open-remote-admin.ps1")
    seen_ids = load_seen_ids()

    while True:
        try:
            loaded = load_client()
            if loaded is None:
                time.sleep(ERROR_RETRY_SECONDS)
                continue

            config, workstation_token = loaded
            response = http_json(
                method="GET",
                url=(
                    f"{str(config['server_url']).rstrip('/')}"
                    "/api/v1/workstation/approval-notifications"
                    "?limit=250"
                ),
                workstation_token=workstation_token,
                ca_cert_path=str(
                    config.get("ca_cert_path", "")
                ) or None,
                timeout=10.0,
            )
            if int(response.get("api_version", -1)) != REMOTE_API_VERSION:
                raise RuntimeError(
                    "The management server API version is incompatible"
                )

            requests = [
                value
                for value in response.get("approval_requests", [])
                if isinstance(value, dict) and value.get("id")
            ]
            current_ids = {
                str(value["id"])
                for value in requests
            }
            new_ids = current_ids - seen_ids
            new_requests = [
                value
                for value in requests
                if str(value["id"]) in new_ids
            ]

            if new_requests:
                show_notification(
                    title="Windows Login Guard approval requested",
                    message=notification_message(new_requests),
                    open_script=open_script,
                )
                logging.info(
                    "Displayed notification for %d approval request(s)",
                    len(new_requests),
                )

            seen_ids = current_ids
            save_seen_ids(seen_ids)
            time.sleep(POLL_SECONDS)
        except Exception:
            logging.exception("Approval notification check failed")
            time.sleep(ERROR_RETRY_SECONDS)


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except KeyboardInterrupt:
        raise SystemExit(0)
