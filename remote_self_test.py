from __future__ import annotations

import logging
import os
import time
import tempfile
import threading
from pathlib import Path

import pyotp

import remote_server
from remote_common import (
    http_json,
    new_token,
    sha256_token,
    utc_now_iso,
    verify_remote_command,
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wlg-remote-self-test-") as directory:
        database = Path(directory) / "management.db"
        config = {
            "bind_address": "127.0.0.1",
            "port": 0,
            "tls_cert_path": "",
            "tls_key_path": "",
            "allow_insecure_http": True,
            "database_path": str(database),
            "admin_session_hours": 1,
            "offline_after_seconds": 45,
            "maximum_sync_age_seconds": 300,
        }
        remote_server.initialize_database(config)
        secret = pyotp.random_base32()
        workstation_enrollment = new_token()
        device_enrollment = new_token()
        with remote_server.db_connect(config) as db:
            db.execute(
                """
                INSERT INTO admins (
                    username, totp_secret_dpapi, enabled, created_utc
                ) VALUES (?, ?, 1, ?)
                """,
                (
                    "self-test-admin",
                    remote_server.encode_machine_secret(secret),
                    utc_now_iso(),
                ),
            )
            for kind, token in (
                ("workstation", workstation_enrollment),
                ("device", device_enrollment),
            ):
                db.execute(
                    """
                    INSERT INTO enrollment_tokens (
                        kind, token_hash, label, created_utc, expires_utc
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        kind,
                        sha256_token(token),
                        "self-test",
                        utc_now_iso(),
                        "2099-01-01T00:00:00+00:00",
                    ),
                )

        logger = logging.getLogger("WlgRemoteSelfTest")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        server = remote_server.build_server(config, logger)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True,
        )
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            health = http_json(method="GET", url=f"{base}/health")
            assert health.get("ok")
            workstation = http_json(
                method="POST",
                url=f"{base}/api/v1/workstations/register",
                payload={
                    "enrollment_token": workstation_enrollment,
                    "label": "Self Test Workstation",
                },
            )
            login = http_json(
                method="POST",
                url=f"{base}/api/v1/admin/login",
                payload={
                    "username": "self-test-admin",
                    "otp": pyotp.TOTP(secret).now(),
                },
                workstation_token=str(workstation["workstation_token"]),
            )
            device = http_json(
                method="POST",
                url=f"{base}/api/v1/devices/register",
                payload={
                    "enrollment_token": device_enrollment,
                    "hostname": "self-test-device",
                    "machine_identity": sha256_token("self-test-machine"),
                    "display_name": "Self Test Device",
                    "endpoint_version": "self-test",
                    "operating_system": "Windows self-test",
                },
            )
            challenge_id = new_token(18)
            sync_payload = {
                "hostname": "self-test-device",
                "display_name": "Self Test Device",
                "endpoint_version": "self-test",
                "operating_system": "Windows self-test",
                "dashboard": {
                    "overall_health": "healthy",
                    "counts": {"active_sessions": 1},
                },
                "sessions": [
                    {
                        "session_id": 1,
                        "username": "test",
                        "user_sid": "S-1-5-21-self-test",
                        "verification_state": "Waiting approval",
                        "verification_reason": "logon",
                        "challenge_id": challenge_id,
                        "challenge_created_utc": utc_now_iso(),
                        "remaining_seconds": 300,
                    }
                ],
                "diagnostics": {"health": []},
                "audit": [{"action": "self_test"}],
                "logs": "self-test log",
                "agent_status": "online",
                "last_error": "",
                "command_secret_ready": True,
            }
            first_sync = http_json(
                method="POST",
                url=f"{base}/api/v1/devices/sync",
                bearer_token=str(device["device_token"]),
                payload=sync_payload,
            )
            assert first_sync.get("ok")
            inventory = http_json(
                method="GET",
                url=f"{base}/api/v1/admin/devices",
                bearer_token=str(login["session_token"]),
            )
            assert len(inventory.get("devices", [])) == 1
            detail = http_json(
                method="GET",
                url=(
                    f"{base}/api/v1/admin/devices/"
                    f"{device['device_id']}"
                ),
                bearer_token=str(login["session_token"]),
            )
            assert detail["device"]["logs"] == "self-test log"
            assert detail["device"]["sessions"][0]["username"] == "test"
            requests = detail["device"]["approval_requests"]
            assert len(requests) == 1

            notifications = http_json(
                method="GET",
                url=(
                    f"{base}/api/v1/workstation/"
                    "approval-notifications?limit=250"
                ),
                workstation_token=str(
                    workstation["workstation_token"]
                ),
            )
            assert len(
                notifications.get("approval_requests", [])
            ) == 1
            assert (
                notifications["approval_requests"][0][
                    "device_display_name"
                ]
                == "Self Test Device"
            )

            request_id = str(requests[0]["id"])
            decision = http_json(
                method="POST",
                url=(
                    f"{base}/api/v1/admin/approval-requests/"
                    f"{request_id}/approve"
                ),
                bearer_token=str(login["session_token"]),
                payload={"duration": "session"},
            )
            assert decision.get("queued")
            command_sync = http_json(
                method="POST",
                url=f"{base}/api/v1/devices/sync",
                bearer_token=str(device["device_token"]),
                payload=sync_payload,
            )
            assert len(command_sync.get("commands", [])) == 1
            command = dict(command_sync["commands"][0])
            assert verify_remote_command(
                command,
                str(device["command_secret"]),
            )
            result = http_json(
                method="POST",
                url=f"{base}/api/v1/devices/command-results",
                bearer_token=str(device["device_token"]),
                payload={
                    "command_id": command["command_id"],
                    "request_id": command["request_id"],
                    "ok": True,
                    "action": command["type"],
                    "local_response": {"ok": True, "approved": True},
                },
            )
            assert result.get("status") == "approved"

            session_action = http_json(
                method="POST",
                url=(
                    f"{base}/api/v1/admin/devices/"
                    f"{device['device_id']}/sessions/1/lock"
                ),
                bearer_token=str(login["session_token"]),
                payload={
                    "user_sid": "S-1-5-21-self-test",
                    "username": "test",
                },
            )
            assert session_action.get("queued")
            action_sync = http_json(
                method="POST",
                url=f"{base}/api/v1/devices/sync",
                bearer_token=str(device["device_token"]),
                payload=sync_payload,
            )
            assert len(action_sync.get("commands", [])) == 1
            action_command = dict(action_sync["commands"][0])
            assert action_command["type"] == "lock_session"
            assert verify_remote_command(
                action_command,
                str(device["command_secret"]),
            )
            action_result = http_json(
                method="POST",
                url=f"{base}/api/v1/devices/command-results",
                bearer_token=str(device["device_token"]),
                payload={
                    "command_id": action_command["command_id"],
                    "request_id": action_command["request_id"],
                    "ok": True,
                    "action": action_command["type"],
                    "local_response": {"ok": True, "locked": True},
                },
            )
            assert action_result.get("status") == "completed"
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
            if thread.is_alive():
                raise RuntimeError(
                    "Remote-management self-test server did not stop"
                )

        # On Windows, this rename fails when any SQLite connection still
        # holds management.db open. Retry briefly for filesystem release.
        release_probe = database.with_suffix(".release-test")
        last_error: OSError | None = None
        for _attempt in range(20):
            try:
                os.replace(database, release_probe)
                os.replace(release_probe, database)
                last_error = None
                break
            except OSError as exc:
                last_error = exc
                time.sleep(0.1)

        if last_error is not None:
            raise RuntimeError(
                "SQLite database handle remained open after server shutdown"
            ) from last_error

    print("Windows Login Guard remote-management self-test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
