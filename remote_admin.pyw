from __future__ import annotations

import base64
import ctypes
import json
import os
import queue
import socket
import subprocess
import tkinter as tk
import winsound
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from remote_common import (
    REMOTE_API_VERSION,
    REMOTE_ADMIN_CONFIG,
    REMOTE_ADMIN_DATA,
    REMOTE_ADMIN_TOKEN,
    atomic_write_json,
    http_json,
    protect_user_text,
    read_json,
    safe_text,
    unprotect_user_text,
    validate_server_url,
)

APP_VERSION = Path(__file__).with_name("VERSION").read_text(
    encoding="utf-8"
).strip()
AUTO_REFRESH_MS = 15_000
APPROVAL_WATCH_MS = 5_000
UI_QUEUE_INTERVAL_MS = 75
MAX_AUDIT_RENDER_ROWS = 250
MAX_LOG_RENDER_CHARS = 150_000


def present_modal(window: tk.Toplevel, parent: tk.Tk) -> None:
    """Present a modal dialog even when the application root is withdrawn."""
    window.update_idletasks()

    width = max(window.winfo_width(), window.winfo_reqwidth())
    height = max(window.winfo_height(), window.winfo_reqheight())
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = max(0, (screen_width - width) // 2)
    y = max(0, (screen_height - height) // 3)
    window.geometry(f"+{x}+{y}")

    try:
        if parent.state() != "withdrawn":
            window.transient(parent)
    except tk.TclError:
        pass

    window.deiconify()
    window.lift()
    window.grab_set()

    try:
        window.attributes("-topmost", True)
        window.after(
            750,
            lambda: window.attributes("-topmost", False),
        )
    except tk.TclError:
        pass

    window.focus_force()


class FLASHWINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("hwnd", ctypes.c_void_p),
        ("dwFlags", ctypes.c_uint),
        ("uCount", ctypes.c_uint),
        ("dwTimeout", ctypes.c_uint),
    ]


def flash_window(hwnd: int) -> None:
    """Flash the Remote Administration taskbar button."""
    try:
        flash_info = FLASHWINFO(
            ctypes.sizeof(FLASHWINFO),
            hwnd,
            0x00000002 | 0x0000000C,
            5,
            0,
        )
        ctypes.windll.user32.FlashWindowEx(
            ctypes.byref(flash_info)
        )
    except Exception:
        pass


def show_windows_notification(title: str, message: str) -> None:
    """Show a Windows notification without an additional dependency."""
    title_data = base64.b64encode(
        title.encode("utf-8")
    ).decode("ascii")
    message_data = base64.b64encode(
        message.encode("utf-8")
    ).decode("ascii")

    script = rf"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$title = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('{title_data}')
)
$message = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('{message_data}')
)

$notification = New-Object System.Windows.Forms.NotifyIcon
$notification.Icon = [System.Drawing.SystemIcons]::Shield
$notification.BalloonTipIcon = (
    [System.Windows.Forms.ToolTipIcon]::Info
)
$notification.BalloonTipTitle = $title
$notification.BalloonTipText = $message
$notification.Text = 'Windows Login Guard'
$notification.Visible = $true
$notification.ShowBalloonTip(10000)
Start-Sleep -Seconds 11
$notification.Dispose()
"""

    encoded_script = base64.b64encode(
        script.encode("utf-16le")
    ).decode("ascii")

    try:
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
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0,
            ),
        )
    except OSError:
        pass

    try:
        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    except RuntimeError:
        pass


DURATION_LABELS = {
    "once": "Once",
    "until_lock": "Until lock",
    "session": "Until sign-out",
    "15_minutes": "15 minutes",
    "30_minutes": "30 minutes",
    "1_hour": "1 hour",
    "2_hours": "2 hours",
    "4_hours": "4 hours",
    "8_hours": "8 hours",
    "24_hours": "24 hours",
}
DEFAULT_APPROVAL_DURATIONS = tuple(DURATION_LABELS)


class ApprovalDecisionDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Tk,
        *,
        request: dict[str, Any],
        decision: str,
    ) -> None:
        super().__init__(parent)
        self.result: dict[str, str] | None = None
        self.request = request
        self.decision = decision
        approve = decision == "approve"
        self.title(
            "Approve Remote Login"
            if approve
            else "Deny Remote Login"
        )
        self.geometry("520x390" if approve else "520x330")
        self.resizable(False, False)

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        ttk.Label(
            frame,
            text=(
                "Approve protected session"
                if approve
                else "Deny protected session"
            ),
            font=("Segoe UI", 15, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 14))

        details = [
            ("Device", request.get("device_display_name", "")),
            ("User", request.get("username", "")),
            ("Session", request.get("session_id", "")),
            ("Reason", request.get("reason", "")),
            ("Expires", RemoteAdminApp._local_time(request.get("expires_utc"))),
        ]
        for row, (label, value) in enumerate(details, start=1):
            ttk.Label(frame, text=f"{label}:", font=("Segoe UI", 10, "bold")).grid(
                row=row, column=0, sticky="nw", padx=(0, 12), pady=4
            )
            ttk.Label(frame, text=str(value), wraplength=340).grid(
                row=row, column=1, sticky="w", pady=4
            )

        next_row = len(details) + 1
        self.duration_map: dict[str, str] = {}
        self.duration_var = tk.StringVar()
        if approve:
            durations = request.get("allowed_durations") or list(
                DEFAULT_APPROVAL_DURATIONS
            )
            duration_labels = [
                DURATION_LABELS.get(str(value), str(value))
                for value in durations
            ]
            self.duration_map = {
                DURATION_LABELS.get(str(value), str(value)): str(value)
                for value in durations
            }
            ttk.Label(
                frame,
                text="Access duration:",
                font=("Segoe UI", 10, "bold"),
            ).grid(row=next_row, column=0, sticky="w", padx=(0, 12), pady=(12, 5))
            combo = ttk.Combobox(
                frame,
                textvariable=self.duration_var,
                values=duration_labels,
                state="readonly",
                width=28,
            )
            combo.grid(row=next_row, column=1, sticky="w", pady=(12, 5))
            default = str(request.get("default_duration", "session"))
            default_label = DURATION_LABELS.get(default, default)
            if default_label in duration_labels:
                combo.set(default_label)
            elif duration_labels:
                combo.current(0)
            next_row += 1

        decision_text = (
            "Approval grants access using the administrator session "
            "authenticated when Remote Administration was opened. "
            "No additional OTP is required."
            if approve
            else (
                "Denial does not grant access. The authenticated "
                "administrator session and this confirmation are "
                "recorded in the audit log."
            )
        )
        ttk.Label(
            frame,
            text=decision_text,
            wraplength=455,
        ).grid(
            row=next_row,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(12, 5),
        )
        next_row += 1

        self.error_var = tk.StringVar()
        ttk.Label(
            frame,
            textvariable=self.error_var,
            foreground="#b3261e",
            wraplength=460,
        ).grid(row=next_row, column=0, columnspan=2, sticky="w", pady=(8, 0))
        next_row += 1

        actions = ttk.Frame(frame)
        actions.grid(row=next_row, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(actions, text="Cancel", command=self.destroy).pack(
            side="right", padx=(8, 0)
        )
        ttk.Button(
            actions,
            text="Approve" if approve else "Deny",
            command=self._submit,
        ).pack(side="right")

        present_modal(self, parent)

    def _submit(self) -> None:
        duration = ""
        if self.decision == "approve":
            duration = self.duration_map.get(
                self.duration_var.get(),
                "",
            )
            if not duration:
                self.error_var.set("Select an approval duration.")
                return
        self.result = {"duration": duration}
        self.destroy()


class RemoteApiClient:
    def __init__(
        self,
        *,
        server_url: str,
        workstation_token: str,
        ca_cert_path: str,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.workstation_token = workstation_token
        self.ca_cert_path = ca_cert_path or None
        self.session_token = ""
        self.username = ""
        self.session_expires_utc = ""

    def login(self, username: str, otp: str) -> dict[str, Any]:
        response = http_json(
            method="POST",
            url=f"{self.server_url}/api/v1/admin/login",
            payload={"username": username, "otp": otp},
            workstation_token=self.workstation_token,
            ca_cert_path=self.ca_cert_path,
        )
        if int(response.get("api_version", -1)) != REMOTE_API_VERSION:
            raise RuntimeError(
                "The management server API version is not compatible with this app"
            )
        self.session_token = str(response.get("session_token", ""))
        self.username = str(response.get("username", username))
        self.session_expires_utc = str(response.get("expires_utc", ""))
        return response

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.session_token:
            raise RuntimeError("Administrator authentication is required")
        response = http_json(
            method=method,
            url=f"{self.server_url}{path}",
            payload=payload,
            bearer_token=self.session_token,
            ca_cert_path=self.ca_cert_path,
        )
        if (
            "api_version" in response
            and int(response.get("api_version", -1)) != REMOTE_API_VERSION
        ):
            raise RuntimeError(
                "The management server API version is not compatible with this app"
            )
        return response

    def logout(self) -> None:
        if self.session_token:
            try:
                self.request("POST", "/api/v1/admin/logout", {})
            except Exception:
                pass
        self.session_token = ""


class EnrollmentDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk) -> None:
        super().__init__(parent)
        self.result: dict[str, Any] | None = None
        self.title("Register Remote Administration Workstation")
        self.geometry("650x410")
        self.resizable(False, False)

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        ttk.Label(
            frame,
            text="Register this administrator workstation",
            font=("Segoe UI", 15, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        ttk.Label(
            frame,
            text=(
                "Use a single-use admin-computer registration code created on the "
                "Windows Login Guard management server."
            ),
            wraplength=590,
            justify="left",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 18))

        self.server_var = tk.StringVar(value="https://management-server:8443")
        self.cert_var = tk.StringVar()
        self.token_var = tk.StringVar()
        self.label_var = tk.StringVar(
            value=f"{socket.gethostname()} - {os.environ.get('USERNAME', 'Administrator')}"
        )
        self.insecure_var = tk.BooleanVar(value=False)

        fields = [
            ("Server URL", self.server_var),
            ("Server certificate", self.cert_var),
            ("Registration code", self.token_var),
            ("Workstation label", self.label_var),
        ]
        for row, (label, variable) in enumerate(fields, start=2):
            ttk.Label(frame, text=label).grid(
                row=row, column=0, sticky="w", padx=(0, 12), pady=7
            )
            entry = ttk.Entry(frame, textvariable=variable, width=58)
            entry.grid(row=row, column=1, sticky="ew", pady=7)
            if label == "Server certificate":
                ttk.Button(
                    frame,
                    text="Browse",
                    command=self._browse_cert,
                ).grid(row=row, column=2, padx=(8, 0), pady=7)

        ttk.Checkbutton(
            frame,
            text="Allow insecure loopback HTTP for local testing only",
            variable=self.insecure_var,
        ).grid(row=6, column=0, columnspan=3, sticky="w", pady=(12, 6))

        self.status_var = tk.StringVar(value="")
        ttk.Label(
            frame,
            textvariable=self.status_var,
            foreground="#b3261e",
            wraplength=590,
        ).grid(row=7, column=0, columnspan=3, sticky="w", pady=(4, 8))

        actions = ttk.Frame(frame)
        actions.grid(row=8, column=0, columnspan=3, sticky="e", pady=(10, 0))
        ttk.Button(actions, text="Cancel", command=self.destroy).pack(
            side="right", padx=(8, 0)
        )
        ttk.Button(actions, text="Register", command=self._register).pack(
            side="right"
        )

        present_modal(self, parent)

    def _browse_cert(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Select management server certificate",
            filetypes=[
                ("PEM certificate files", "*.crt *.pem"),
                ("All files", "*.*"),
            ],
        )
        if selected:
            self.cert_var.set(selected)

    def _register(self) -> None:
        self.status_var.set("")
        try:
            server_url = validate_server_url(
                self.server_var.get(), self.insecure_var.get()
            )
            cert_path = self.cert_var.get().strip()
            if server_url.startswith("https://") and not cert_path:
                raise ValueError("Select the management server certificate")
            if cert_path and not Path(cert_path).is_file():
                raise ValueError("The selected certificate file does not exist")
            token = self.token_var.get().strip()
            label = safe_text(self.label_var.get(), 200)
            if not token or not label:
                raise ValueError("Registration code and admin-computer label are required")
            response = http_json(
                method="POST",
                url=f"{server_url}/api/v1/workstations/register",
                payload={"enrollment_token": token, "label": label},
                ca_cert_path=cert_path or None,
            )
            if not response.get("ok"):
                raise RuntimeError(
                    str(response.get("message") or response.get("error"))
                )
            if int(response.get("api_version", -1)) != REMOTE_API_VERSION:
                raise RuntimeError(
                    "The management server API version is not compatible with this app"
                )
            self.result = {
                "server_url": server_url,
                "ca_cert_path": str(Path(cert_path).resolve()) if cert_path else "",
                "workstation_id": str(response["workstation_id"]),
                "workstation_token": str(response["workstation_token"]),
                "workstation_label": label,
                "allow_insecure_http": self.insecure_var.get(),
            }
            self.destroy()
        except Exception as exc:
            self.status_var.set(str(exc))


class LoginDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Tk,
        server_url: str,
        default_username: str = "",
    ) -> None:
        super().__init__(parent)
        self.result: tuple[str, str] | None = None
        self.title("Remote Administrator Sign In")
        self.geometry("470x285")
        self.resizable(False, False)

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        ttk.Label(
            frame,
            text="Remote Administrator Sign In",
            font=("Segoe UI", 15, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5))
        ttk.Label(
            frame,
            text=server_url,
            foreground="#5f6368",
            wraplength=420,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 18))

        self.username_var = tk.StringVar(value=default_username)
        self.otp_var = tk.StringVar()
        ttk.Label(frame, text="Administrator").grid(
            row=2, column=0, sticky="w", padx=(0, 12), pady=8
        )
        username_entry = ttk.Entry(frame, textvariable=self.username_var)
        username_entry.grid(row=2, column=1, sticky="ew", pady=8)
        if default_username:
            username_entry.configure(state="readonly")
        ttk.Label(frame, text="OTP").grid(
            row=3, column=0, sticky="w", padx=(0, 12), pady=8
        )
        otp_entry = ttk.Entry(frame, textvariable=self.otp_var, show="•")
        otp_entry.grid(row=3, column=1, sticky="ew", pady=8)
        otp_entry.bind("<Return>", lambda _event: self._submit())

        actions = ttk.Frame(frame)
        actions.grid(row=4, column=0, columnspan=2, sticky="e", pady=(18, 0))
        ttk.Button(actions, text="Cancel", command=self.destroy).pack(
            side="right", padx=(8, 0)
        )
        ttk.Button(actions, text="Sign In", command=self._submit).pack(side="right")
        username_entry.focus_set()
        present_modal(self, parent)
        otp_entry.focus_set()

    def _submit(self) -> None:
        username = self.username_var.get().strip()
        otp = self.otp_var.get().strip().replace(" ", "")
        if not username or not otp:
            messagebox.showerror(
                "Missing information",
                "Enter the administrator username and current OTP.",
                parent=self,
            )
            return
        self.result = (username, otp)
        self.destroy()


class RemoteAdminApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title("Windows Login Guard Remote Administration")
        self.root.geometry("1320x820")
        self.root.minsize(1100, 700)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.config = self._load_or_enroll()
        self.client = RemoteApiClient(
            server_url=self.config["server_url"],
            workstation_token=unprotect_user_text(REMOTE_ADMIN_TOKEN.read_bytes()),
            ca_cert_path=self.config.get("ca_cert_path", ""),
        )
        self.devices: list[dict[str, Any]] = []
        self.selected_device_id = ""
        self.current_device: dict[str, Any] = {}
        self.auto_refresh_job: str | None = None
        self.approval_watch_job: str | None = None
        self.ui_queue_job: str | None = None
        self.ui_queue: queue.Queue[
            tuple[str, Future[dict[str, Any]], dict[str, Any]]
        ] = queue.Queue()
        self.executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="WlgRemoteAdmin",
        )
        self.inventory_refresh_in_progress = False
        self.detail_refresh_in_progress = False
        self.device_removal_in_progress = False
        self.approval_decision_in_progress = False
        self.session_action_in_progress = False
        self.approval_watch_in_progress = False
        self.pending_detail_device_id = ""
        self.known_pending_approval_ids: set[str] = set()
        self.approval_watch_initialized = False
        self.closing = False

        self._configure_style()
        self._login()
        self._build_ui()
        self.root.deiconify()
        self._schedule_ui_queue()
        self.refresh_devices()
        self._schedule_refresh()
        self._schedule_approval_watch(delay_ms=1_000)

    def _load_or_enroll(self) -> dict[str, Any]:
        config = read_json(REMOTE_ADMIN_CONFIG, {})
        if isinstance(config, dict) and REMOTE_ADMIN_TOKEN.exists():
            return config

        dialog = EnrollmentDialog(self.root)
        self.root.wait_window(dialog)
        if dialog.result is None:
            raise SystemExit(0)
        result = dialog.result
        REMOTE_ADMIN_DATA.mkdir(parents=True, exist_ok=True)
        REMOTE_ADMIN_TOKEN.write_bytes(
            protect_user_text(result.pop("workstation_token"))
        )
        certificate_source = str(result.get("ca_cert_path", ""))
        if certificate_source:
            certificate_target = REMOTE_ADMIN_DATA / "management-server.crt"
            certificate_target.write_bytes(Path(certificate_source).read_bytes())
            result["ca_cert_path"] = str(certificate_target)
        atomic_write_json(REMOTE_ADMIN_CONFIG, result)
        return result

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("PageTitle.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("CardValue.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Muted.TLabel", foreground="#5f6368")
        style.configure("Healthy.TLabel", foreground="#176b2c")
        style.configure("Warning.TLabel", foreground="#8a4b00")
        style.configure("Error.TLabel", foreground="#b3261e")

    def _login(self) -> None:
        while True:
            dialog = LoginDialog(
                self.root,
                self.config["server_url"],
                str(self.config.get("linked_username", "")),
            )
            self.root.wait_window(dialog)
            if dialog.result is None:
                raise SystemExit(0)
            username, otp = dialog.result
            try:
                self.client.login(username, otp)
                return
            except Exception as exc:
                messagebox.showerror(
                    "Sign in failed",
                    str(exc),
                    parent=self.root,
                )

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header,
            text="Windows Login Guard Remote Administration",
            style="Title.TLabel",
        ).grid(row=0, column=0, sticky="w")
        self.identity_label = ttk.Label(
            header,
            text=f"{self.client.username}  |  v{APP_VERSION}",
            style="Muted.TLabel",
        )
        self.identity_label.grid(row=0, column=1, sticky="e", padx=(12, 8))
        self.refresh_button = ttk.Button(
            header,
            text="Refresh",
            command=self.refresh_devices,
        )
        self.refresh_button.grid(row=0, column=2, sticky="e")

        body = ttk.Panedwindow(self.root, orient="horizontal")
        body.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 8))

        device_panel = ttk.Frame(body, width=300)
        detail_panel = ttk.Frame(body)
        body.add(device_panel, weight=1)
        body.add(detail_panel, weight=4)

        device_panel.rowconfigure(1, weight=1)
        device_panel.columnconfigure(0, weight=1)
        ttk.Label(
            device_panel,
            text="Devices",
            style="PageTitle.TLabel",
        ).grid(row=0, column=0, sticky="w", padx=8, pady=(8, 10))
        self.device_tree = ttk.Treeview(
            device_panel,
            show="tree",
            selectmode="browse",
        )
        self.device_tree.column("#0", width=275, anchor="w", stretch=True)
        self.device_tree.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=8,
            pady=(0, 8),
        )
        self.device_tree.bind(
            "<<TreeviewSelect>>",
            self._device_selected,
        )

        device_actions = ttk.Frame(device_panel)
        device_actions.grid(
            row=2,
            column=0,
            sticky="ew",
            padx=8,
            pady=(0, 8),
        )
        device_actions.columnconfigure(0, weight=1)
        self.remove_device_button = ttk.Button(
            device_actions,
            text="Remove Device",
            command=self._remove_selected_device,
            state="disabled",
        )
        self.remove_device_button.grid(
            row=0,
            column=0,
            sticky="ew",
        )

        detail_panel.rowconfigure(1, weight=1)
        detail_panel.columnconfigure(0, weight=1)
        self.device_title = ttk.Label(
            detail_panel,
            text="Select a device",
            style="PageTitle.TLabel",
        )
        self.device_title.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 10))

        self.tabs = ttk.Notebook(detail_panel)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.dashboard_tab = ttk.Frame(self.tabs)
        self.approvals_tab = ttk.Frame(self.tabs)
        self.sessions_tab = ttk.Frame(self.tabs)
        self.audit_tab = ttk.Frame(self.tabs)
        self.logs_tab = ttk.Frame(self.tabs)
        self.diagnostics_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.approvals_tab, text="Approvals")
        self.tabs.add(self.sessions_tab, text="Sessions")
        self.tabs.add(self.audit_tab, text="Audit")
        self.tabs.add(self.logs_tab, text="Logs")
        self.tabs.add(self.diagnostics_tab, text="Diagnostics")
        self.tabs.bind("<<NotebookTabChanged>>", self._tab_changed)

        self._build_dashboard()
        self._build_approvals()
        self._build_sessions()
        self._build_audit()
        self._build_logs()
        self._build_diagnostics()

        self.status_var = tk.StringVar(value="Ready")
        ttk.Separator(self.root, orient="horizontal").grid(
            row=2, column=0, sticky="ew"
        )
        self.status_label = ttk.Label(
            self.root,
            textvariable=self.status_var,
            anchor="w",
        )
        self.status_label.grid(
            row=3, column=0, sticky="ew", padx=14, pady=(5, 7)
        )

    def _build_dashboard(self) -> None:
        self.dashboard_tab.columnconfigure(0, weight=1)
        self.dashboard_tab.rowconfigure(2, weight=1)
        summary = ttk.Frame(self.dashboard_tab)
        summary.grid(row=0, column=0, sticky="ew", padx=14, pady=14)
        self.summary_labels: dict[str, ttk.Label] = {}
        cards = [
            ("connectivity", "Connectivity"),
            ("health", "System Health"),
            ("maintenance", "Maintenance"),
            ("enrolled", "Enrolled Accounts"),
            ("sessions", "Active Sessions"),
            ("waiting", "Waiting Verification"),
            ("approvals", "Pending Approvals"),
        ]
        for index, (key, title) in enumerate(cards):
            summary.columnconfigure(index, weight=1)
            frame = ttk.LabelFrame(summary, text=title)
            frame.grid(row=0, column=index, sticky="nsew", padx=(0, 8))
            label = ttk.Label(frame, text="—", style="CardValue.TLabel", anchor="center")
            label.pack(fill="both", expand=True, padx=10, pady=12)
            self.summary_labels[key] = label

        self.device_info = ttk.Label(
            self.dashboard_tab,
            text="",
            style="Muted.TLabel",
            wraplength=850,
            justify="left",
        )
        self.device_info.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 10))

        notifications_frame = ttk.LabelFrame(
            self.dashboard_tab, text="Notifications and Recent Activity"
        )
        notifications_frame.grid(
            row=2, column=0, sticky="nsew", padx=14, pady=(0, 14)
        )
        notifications_frame.columnconfigure(0, weight=1)
        notifications_frame.rowconfigure(0, weight=1)
        self.notifications_tree = ttk.Treeview(
            notifications_frame,
            columns=("severity", "title", "detail"),
            show="headings",
        )
        for column, text, width in [
            ("severity", "Severity", 90),
            ("title", "Event", 260),
            ("detail", "Details", 520),
        ]:
            self.notifications_tree.heading(column, text=text)
            self.notifications_tree.column(column, width=width, anchor="w")
        self.notifications_tree.grid(row=0, column=0, sticky="nsew")

    def _build_approvals(self) -> None:
        self.approvals_tab.columnconfigure(0, weight=1)
        self.approvals_tab.rowconfigure(0, weight=1)
        columns = (
            "username",
            "session_id",
            "reason",
            "requested",
            "expires",
            "status",
        )
        self.approvals_tree = ttk.Treeview(
            self.approvals_tab,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        definitions = [
            ("username", "User", 210),
            ("session_id", "Session", 75),
            ("reason", "Reason", 130),
            ("requested", "Requested", 185),
            ("expires", "Expires", 185),
            ("status", "Status", 170),
        ]
        for column, title, width in definitions:
            self.approvals_tree.heading(column, text=title)
            self.approvals_tree.column(column, width=width, anchor="w")
        self.approvals_tree.column("session_id", anchor="center")
        self.approvals_tree.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=12,
            pady=(12, 6),
        )
        self.approvals_tree.bind(
            "<<TreeviewSelect>>",
            self._approval_selected,
        )

        actions = ttk.Frame(self.approvals_tab)
        actions.grid(row=1, column=0, sticky="e", padx=12, pady=(0, 12))
        self.deny_approval_button = ttk.Button(
            actions,
            text="Deny",
            command=lambda: self._decide_selected_approval("deny"),
            state="disabled",
        )
        self.deny_approval_button.pack(side="right", padx=(8, 0))
        self.approve_approval_button = ttk.Button(
            actions,
            text="Approve",
            command=lambda: self._decide_selected_approval("approve"),
            state="disabled",
        )
        self.approve_approval_button.pack(side="right")

    def _build_sessions(self) -> None:
        self.sessions_tab.columnconfigure(0, weight=1)
        self.sessions_tab.rowconfigure(0, weight=1)
        columns = (
            "session_id",
            "username",
            "connection",
            "verification",
            "reason",
            "remaining",
            "failed",
            "recovery",
        )
        self.sessions_tree = ttk.Treeview(
            self.sessions_tab,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        headings = {
            "session_id": "Session",
            "username": "User",
            "connection": "Connection",
            "verification": "Verification",
            "reason": "Reason",
            "remaining": "Time Left",
            "failed": "Failed Attempts",
            "recovery": "F8 Recovery",
        }
        widths = {
            "session_id": 70,
            "username": 190,
            "connection": 115,
            "verification": 130,
            "reason": 150,
            "remaining": 90,
            "failed": 100,
            "recovery": 100,
        }
        for column in columns:
            self.sessions_tree.heading(column, text=headings[column])
            self.sessions_tree.column(
                column,
                width=widths[column],
                anchor="center",
            )
        self.sessions_tree.column("username", anchor="w")
        self.sessions_tree.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=12,
            pady=(12, 6),
        )
        self.sessions_tree.bind(
            "<<TreeviewSelect>>",
            self._session_selected,
        )

        actions = ttk.Frame(self.sessions_tab)
        actions.grid(
            row=1,
            column=0,
            sticky="e",
            padx=12,
            pady=(0, 12),
        )
        self.logoff_session_button = ttk.Button(
            actions,
            text="Log Off Session",
            command=lambda: self._run_selected_session_action("logoff"),
            state="disabled",
        )
        self.logoff_session_button.pack(side="right", padx=(8, 0))
        self.lock_session_button = ttk.Button(
            actions,
            text="Lock Session",
            command=lambda: self._run_selected_session_action("lock"),
            state="disabled",
        )
        self.lock_session_button.pack(side="right")

    def _build_audit(self) -> None:
        self.audit_tab.columnconfigure(0, weight=1)
        self.audit_tab.rowconfigure(0, weight=1)
        columns = ("timestamp", "action", "actor", "target", "details")
        self.audit_tree = ttk.Treeview(
            self.audit_tab, columns=columns, show="headings"
        )
        for column, text, width in [
            ("timestamp", "Timestamp (Local)", 190),
            ("action", "Action", 210),
            ("actor", "Actor", 150),
            ("target", "Target", 170),
            ("details", "Details", 420),
        ]:
            self.audit_tree.heading(column, text=text)
            self.audit_tree.column(column, width=width, anchor="w")
        self.audit_tree.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

    def _build_logs(self) -> None:
        self.logs_tab.columnconfigure(0, weight=1)
        self.logs_tab.rowconfigure(1, weight=1)
        top = ttk.Frame(self.logs_tab)
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        self.log_search_var = tk.StringVar()
        ttk.Label(top, text="Find").pack(side="left")
        ttk.Entry(top, textvariable=self.log_search_var, width=35).pack(
            side="left", padx=(8, 8)
        )
        ttk.Button(top, text="Find Next", command=self._find_log).pack(side="left")
        self.log_text = tk.Text(
            self.logs_tab,
            wrap="none",
            font=("Consolas", 9),
            state="disabled",
        )
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

    def _build_diagnostics(self) -> None:
        self.diagnostics_tab.columnconfigure(0, weight=1)
        self.diagnostics_tab.rowconfigure(0, weight=1)
        self.diagnostics_tree = ttk.Treeview(
            self.diagnostics_tab,
            columns=("component", "status", "detail"),
            show="headings",
        )
        for column, text, width in [
            ("component", "Component", 190),
            ("status", "Status", 110),
            ("detail", "Details", 650),
        ]:
            self.diagnostics_tree.heading(column, text=text)
            self.diagnostics_tree.column(column, width=width, anchor="w")
        self.diagnostics_tree.grid(
            row=0, column=0, sticky="nsew", padx=12, pady=12
        )

    @staticmethod
    def _local_time(value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return "—"
        try:
            normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        except ValueError:
            return raw

    @staticmethod
    def _duration(seconds: Any) -> str:
        try:
            value = max(0, int(seconds))
        except (TypeError, ValueError):
            return "—"
        minutes, secs = divmod(value, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"

    def _set_status(self, text: str, level: str = "information") -> None:
        self.status_var.set(text)
        colors = {
            "information": "#303030",
            "healthy": "#176b2c",
            "warning": "#8a4b00",
            "error": "#b3261e",
        }
        self.status_label.configure(foreground=colors.get(level, "#303030"))

    def _set_busy(self, busy: bool) -> None:
        self.refresh_button.configure(
            state="disabled"
            if (
                self.inventory_refresh_in_progress
                or self.detail_refresh_in_progress
            )
            else "normal"
        )
        self._update_remove_device_button(busy=busy)
        self._update_approval_buttons(busy=busy)

        # A background inventory/detail refresh does not invalidate the
        # selected session. The server revalidates session ID, user SID,
        # device status, and command-channel readiness when an action is
        # submitted, so refresh activity must not disable Lock or Log Off.
        self._update_session_action_buttons()

    def _selected_device_summary(self) -> dict[str, Any] | None:
        if not self.selected_device_id:
            return None
        for device in self.devices:
            if str(device.get("id", "")) == self.selected_device_id:
                return device
        return None

    def _update_remove_device_button(
        self,
        *,
        busy: bool | None = None,
    ) -> None:
        if busy is None:
            busy = (
                self.inventory_refresh_in_progress
                or self.detail_refresh_in_progress
                or self.device_removal_in_progress
                or self.approval_decision_in_progress
                or self.session_action_in_progress
            )
        enabled = (
            not busy
            and self._selected_device_summary() is not None
            and not self.closing
        )
        self.remove_device_button.configure(
            state="normal" if enabled else "disabled"
        )

    def _selected_approval_request(self) -> dict[str, Any] | None:
        if not hasattr(self, "approvals_tree"):
            return None
        selection = self.approvals_tree.selection()
        if not selection:
            return None
        request_id = str(selection[0])
        for request in self.current_device.get("approval_requests", []):
            if str(request.get("id", "")) == request_id:
                return dict(request)
        return None

    def _approval_selected(self, _event: tk.Event) -> None:
        self._update_approval_buttons()

    def _update_approval_buttons(
        self,
        *,
        busy: bool | None = None,
    ) -> None:
        if not hasattr(self, "approve_approval_button"):
            return
        if busy is None:
            busy = (
                self.inventory_refresh_in_progress
                or self.detail_refresh_in_progress
                or self.device_removal_in_progress
                or self.approval_decision_in_progress
                or self.session_action_in_progress
            )
        request = self._selected_approval_request()
        enabled = bool(
            not busy
            and request is not None
            and str(request.get("status", "")) == "pending"
            and bool(self.current_device.get("online"))
            and bool(self.current_device.get("remote_approval_ready"))
            and not self.closing
        )
        state = "normal" if enabled else "disabled"
        self.approve_approval_button.configure(state=state)
        self.deny_approval_button.configure(state=state)

    def _selected_session(self) -> dict[str, Any] | None:
        if not hasattr(self, "sessions_tree"):
            return None
        selection = self.sessions_tree.selection()
        if not selection:
            return None
        selected_id = str(selection[0])
        for session in self.current_device.get("sessions", []):
            if str(session.get("session_id", "")) == selected_id:
                return dict(session)
        return None

    def _session_selected(self, _event: tk.Event) -> None:
        self._update_session_action_buttons()

    def _update_session_action_buttons(
        self,
        *,
        busy: bool | None = None,
    ) -> None:
        if not hasattr(self, "lock_session_button"):
            return
        if busy is None:
            # Inventory and detail refreshes use cached session data and do
            # not block session controls. The management server performs
            # authoritative validation before accepting either command.
            busy = (
                self.device_removal_in_progress
                or self.approval_decision_in_progress
                or self.session_action_in_progress
            )

        session = self._selected_session()
        available = bool(
            not busy
            and session is not None
            and int(session.get("session_id", -1)) > 0
            and bool(session.get("user_sid"))
            and bool(self.current_device.get("online"))
            and bool(
                self.current_device.get(
                    "remote_session_control_ready",
                    self.current_device.get("remote_approval_ready"),
                )
            )
            and not self.closing
        )
        connection = str(
            session.get("connection_state", "")
            if session is not None
            else ""
        ).lower()
        lock_available = available and connection != "disconnected"

        self.lock_session_button.configure(
            state="normal" if lock_available else "disabled"
        )
        self.logoff_session_button.configure(
            state="normal" if available else "disabled"
        )

    def _run_selected_session_action(self, action: str) -> None:
        session = self._selected_session()
        if (
            session is None
            or self.session_action_in_progress
            or self.device_removal_in_progress
            or self.approval_decision_in_progress
            or action not in {"lock", "logoff"}
        ):
            return

        device_name = str(
            self.current_device.get("display_name")
            or self.current_device.get("hostname")
            or "protected PC"
        )
        username = str(session.get("username") or "Unknown user")
        session_id = int(session.get("session_id", -1))

        local_warning = ""
        if str(self.current_device.get("hostname", "")).casefold() == (
            socket.gethostname().casefold()
        ):
            local_warning = (
                "\n\nThis appears to be the current Admin PC. "
                "The action may lock or sign out this Windows session."
            )

        if action == "lock":
            title = "Lock remote Windows session"
            verb = "Lock"
            warning = (
                f"Lock session {session_id} for {username} on "
                f"{device_name}?\n\n"
                "Running applications remain open. The user must sign in "
                "again to continue."
            )
        else:
            title = "Log off remote Windows session"
            verb = "Log off"
            warning = (
                f"Log off session {session_id} for {username} on "
                f"{device_name}?\n\n"
                "This closes the user's applications. Unsaved work may be "
                "lost."
            )

        confirmed = messagebox.askyesno(
            title,
            warning + local_warning,
            icon="warning",
            parent=self.root,
        )
        if not confirmed:
            return

        self.session_action_in_progress = True
        self._set_busy(True)
        self._set_status(
            f"{verb} command is being queued for "
            f"{username} on {device_name}...",
            "warning",
        )
        self._submit_request(
            kind="session_action",
            path=(
                f"/api/v1/admin/devices/{self.selected_device_id}"
                f"/sessions/{session_id}/{action}"
            ),
            method="POST",
            payload={
                "user_sid": str(session.get("user_sid", "")),
                "username": username,
            },
            context={
                "action": action,
                "device_name": device_name,
                "username": username,
                "session_id": session_id,
            },
        )

    def _apply_session_action_result(
        self,
        future: Future[dict[str, Any]],
        context: dict[str, Any],
    ) -> None:
        self.session_action_in_progress = False
        self._set_busy(
            self.inventory_refresh_in_progress
            or self.detail_refresh_in_progress
            or self.device_removal_in_progress
            or self.approval_decision_in_progress
        )

        try:
            response = future.result()
        except Exception as exc:
            message = str(exc)
            if self._is_authentication_error(message):
                self._reauthenticate_and_refresh()
                return
            self._set_status(message, "error")
            messagebox.showerror(
                "Remote session action failed",
                message,
                parent=self.root,
            )
            self._update_session_action_buttons()
            return

        action = str(context.get("action", "action"))
        username = str(context.get("username", "user"))
        device_name = str(context.get("device_name", "protected PC"))
        label = "Lock" if action == "lock" else "Logoff"
        self._set_status(
            f"{label} command queued for {username} on {device_name}.",
            "healthy",
        )
        if response.get("queued"):
            self.root.after(1_000, self.refresh_selected_device)
        else:
            self.refresh_selected_device()

    def _submit_request(
        self,
        *,
        kind: str,
        path: str,
        context: dict[str, Any],
        method: str = "GET",
        payload: dict[str, Any] | None = None,
    ) -> None:
        future = self.executor.submit(
            self.client.request,
            method,
            path,
            payload,
        )
        future.add_done_callback(
            lambda completed: self.ui_queue.put(
                (kind, completed, context)
            )
        )

    def _schedule_ui_queue(self) -> None:
        if self.closing:
            return
        self.ui_queue_job = self.root.after(
            UI_QUEUE_INTERVAL_MS,
            self._drain_ui_queue,
        )

    def _drain_ui_queue(self) -> None:
        self.ui_queue_job = None
        if self.closing:
            return

        while True:
            try:
                kind, future, context = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "inventory":
                self._apply_inventory_result(future, context)
            elif kind == "detail":
                self._apply_detail_result(future, context)
            elif kind == "remove_device":
                self._apply_remove_device_result(future, context)
            elif kind == "approval_decision":
                self._apply_approval_decision_result(future, context)
            elif kind == "approval_watch":
                self._apply_approval_watch_result(future, context)
            elif kind == "session_action":
                self._apply_session_action_result(future, context)

        self._schedule_ui_queue()

    @staticmethod
    def _is_authentication_error(message: str) -> bool:
        lowered = message.lower()
        return (
            "http 401" in lowered
            or "authentication_required" in lowered
            or "administrator authentication is required" in lowered
        )

    def _reauthenticate_and_refresh(self) -> None:
        try:
            self._login()
        except SystemExit:
            self.close()
            return
        self.refresh_devices(silent=True)

    def _schedule_approval_watch(
        self,
        *,
        delay_ms: int = APPROVAL_WATCH_MS,
    ) -> None:
        if self.closing or self.approval_watch_job:
            return
        self.approval_watch_job = self.root.after(
            delay_ms,
            self._approval_watch_tick,
        )

    def _approval_watch_tick(self) -> None:
        self.approval_watch_job = None
        if self.closing:
            return
        if self.approval_watch_in_progress:
            self._schedule_approval_watch()
            return

        self.approval_watch_in_progress = True
        self._submit_request(
            kind="approval_watch",
            path=(
                "/api/v1/admin/approval-requests"
                "?status=pending&limit=250"
            ),
            context={},
        )

    def _device_name_for_notification(
        self,
        device_id: str,
    ) -> str:
        for device in self.devices:
            if str(device.get("id", "")) == device_id:
                return str(
                    device.get("display_name")
                    or device.get("hostname")
                    or "Protected PC"
                )
        return "Protected PC"

    def _apply_approval_watch_result(
        self,
        future: Future[dict[str, Any]],
        _context: dict[str, Any],
    ) -> None:
        self.approval_watch_in_progress = False

        try:
            response = future.result()
        except Exception as exc:
            message = str(exc)
            if not self._is_authentication_error(message):
                self._set_status(
                    f"Approval notification check failed: {message}",
                    "warning",
                )
            self._schedule_approval_watch()
            return

        requests = list(response.get("approval_requests", []))
        current_ids = {
            str(request.get("id", ""))
            for request in requests
            if request.get("id")
        }

        if self.approval_watch_initialized:
            new_ids = current_ids - self.known_pending_approval_ids
        else:
            new_ids = current_ids

        self.approval_watch_initialized = True
        self.known_pending_approval_ids = current_ids
        self._update_pending_approval_indicators(requests)

        new_requests = [
            request
            for request in requests
            if str(request.get("id", "")) in new_ids
        ]
        if new_requests:
            if self.selected_device_id in {
                str(request.get("device_id", ""))
                for request in new_requests
            }:
                self.refresh_selected_device()

        self._schedule_approval_watch()

    def _update_pending_approval_indicators(
        self,
        requests: list[dict[str, Any]],
    ) -> None:
        total = len(requests)
        counts_by_device: dict[str, int] = {}
        for request in requests:
            device_id = str(request.get("device_id", ""))
            counts_by_device[device_id] = (
                counts_by_device.get(device_id, 0) + 1
            )

        for device in self.devices:
            device_id = str(device.get("id", ""))
            device["pending_approval_count"] = counts_by_device.get(
                device_id,
                0,
            )

        base_title = "Windows Login Guard Remote Administration"
        if total:
            self.root.title(
                f"{base_title} — {total} pending approval"
                f"{'s' if total != 1 else ''}"
            )
        else:
            self.root.title(base_title)

        if hasattr(self, "approvals_tab"):
            selected_count = counts_by_device.get(
                self.selected_device_id,
                0,
            )
            label = "Approvals"
            if selected_count:
                label += f" ({selected_count})"
            self.tabs.tab(self.approvals_tab, text=label)

        if self.current_device:
            dashboard = dict(
                self.current_device.get("dashboard", {})
            )
            counts = dict(dashboard.get("counts", {}))
            counts["pending_approvals"] = counts_by_device.get(
                self.selected_device_id,
                0,
            )
            dashboard["counts"] = counts
            self.current_device["dashboard"] = dashboard
            if self.tabs.index(self.tabs.select()) == 0:
                self._render_dashboard(self.current_device)

    def _notify_pending_approvals(
        self,
        requests: list[dict[str, Any]],
    ) -> None:
        if len(requests) == 1:
            request = requests[0]
            device_name = self._device_name_for_notification(
                str(request.get("device_id", ""))
            )
            username = str(request.get("username") or "Unknown user")
            session_id = request.get("session_id", "")
            message = (
                f"{username} requested login approval on "
                f"{device_name} (session {session_id}). "
                "Open Remote Administration and select Approvals."
            )
        else:
            message = (
                f"{len(requests)} new login approval requests are "
                "waiting. Open Remote Administration and select "
                "Approvals."
            )

        show_windows_notification(
            "Windows Login Guard approval requested",
            message,
        )
        flash_window(self.root.winfo_id())
        self._set_status(message, "warning")

    def refresh_devices(self, silent: bool = False) -> None:
        if self.closing:
            return
        if self.inventory_refresh_in_progress:
            if not silent:
                self._set_status(
                    "A device refresh is already running.",
                    "information",
                )
            return

        self.inventory_refresh_in_progress = True
        self._set_busy(True)
        self._set_status("Refreshing device inventory...")
        self._submit_request(
            kind="inventory",
            path="/api/v1/admin/devices",
            context={"silent": silent},
        )

    def _apply_inventory_result(
        self,
        future: Future[dict[str, Any]],
        context: dict[str, Any],
    ) -> None:
        self.inventory_refresh_in_progress = False
        self._set_busy(
            self.detail_refresh_in_progress
            or self.device_removal_in_progress
            or self.approval_decision_in_progress
        )
        silent = bool(context.get("silent"))

        try:
            response = future.result()
        except Exception as exc:
            message = str(exc)
            if self._is_authentication_error(message):
                self._reauthenticate_and_refresh()
                return
            self._set_status(message, "error")
            if not silent:
                messagebox.showerror(
                    "Device refresh failed",
                    message,
                    parent=self.root,
                )
            return

        self.devices = list(response.get("devices", []))
        selected = self.selected_device_id

        existing_items = self.device_tree.get_children()
        if existing_items:
            self.device_tree.delete(*existing_items)

        display_name_counts: dict[str, int] = {}
        display_host_counts: dict[tuple[str, str], int] = {}
        for device in self.devices:
            name = str(
                device.get("display_name")
                or device.get("hostname")
                or device.get("id", "")
            )
            host = str(device.get("hostname") or "")
            name_key = name.casefold()
            host_key = host.casefold()
            display_name_counts[name_key] = (
                display_name_counts.get(name_key, 0) + 1
            )
            pair = (name_key, host_key)
            display_host_counts[pair] = (
                display_host_counts.get(pair, 0) + 1
            )

        for device in self.devices:
            item_id = str(device.get("id", ""))
            display_name = str(
                device.get("display_name")
                or device.get("hostname")
                or item_id
            )
            hostname = str(device.get("hostname") or "")
            name_key = display_name.casefold()
            pair = (name_key, hostname.casefold())

            if display_name_counts.get(name_key, 0) > 1:
                label = (
                    f"{display_name} ({hostname})"
                    if hostname
                    else display_name
                )
                if display_host_counts.get(pair, 0) > 1:
                    label = f"{label} [{item_id[:8]}]"
            else:
                label = display_name

            self.device_tree.insert(
                "",
                "end",
                iid=item_id,
                text=label,
            )

        if selected and self.device_tree.exists(selected):
            target = selected
        elif self.devices:
            target = str(self.devices[0].get("id", ""))
        else:
            target = ""

        if target:
            self.selected_device_id = target
            self.device_tree.selection_set(target)
            self.device_tree.focus(target)
            self.refresh_selected_device()
        else:
            self.selected_device_id = ""
            self.current_device = {}
            self._clear_device_view(
                "No protected devices are registered."
            )

        self._set_status(
            f"Loaded {len(self.devices)} device(s).",
            "healthy",
        )
        self._update_remove_device_button()

    def _device_selected(self, _event: tk.Event) -> None:
        selection = self.device_tree.selection()
        if not selection:
            return

        selected = str(selection[0])
        if selected == self.selected_device_id and self.current_device:
            return

        self.selected_device_id = selected
        self._update_remove_device_button()
        self.refresh_selected_device()

    def refresh_selected_device(self) -> None:
        if self.closing or not self.selected_device_id:
            return

        requested_device_id = self.selected_device_id
        if self.detail_refresh_in_progress:
            self.pending_detail_device_id = requested_device_id
            self._set_status(
                "Waiting for the current device refresh to finish...",
                "information",
            )
            return

        self.detail_refresh_in_progress = True
        self.pending_detail_device_id = ""
        self._set_busy(True)
        self._set_status("Loading selected device...")
        self._submit_request(
            kind="detail",
            path=f"/api/v1/admin/devices/{requested_device_id}",
            context={"device_id": requested_device_id},
        )

    def _apply_detail_result(
        self,
        future: Future[dict[str, Any]],
        context: dict[str, Any],
    ) -> None:
        requested_device_id = str(context.get("device_id", ""))
        self.detail_refresh_in_progress = False
        self._set_busy(
            self.inventory_refresh_in_progress
            or self.device_removal_in_progress
            or self.approval_decision_in_progress
        )

        try:
            response = future.result()
        except Exception as exc:
            message = str(exc)
            if self._is_authentication_error(message):
                self._reauthenticate_and_refresh()
                return
            self._set_status(message, "error")
            self._start_pending_detail_refresh(requested_device_id)
            return

        if requested_device_id == self.selected_device_id:
            device = dict(response.get("device", {}))
            self.current_device = device
            self._render_device_header(device)
            self._render_active_tab()

            state = (
                "revoked registration"
                if device.get("revoked")
                else (
                    "online data"
                    if device.get("online")
                    else "last-known offline data"
                )
            )
            self._set_status(
                "Showing "
                f"{state} for "
                f"{device.get('display_name', requested_device_id)}.",
                "healthy" if device.get("online") else "warning",
            )

        self._start_pending_detail_refresh(requested_device_id)

    def _decide_selected_approval(self, decision: str) -> None:
        request = self._selected_approval_request()
        if request is None or self.approval_decision_in_progress:
            return
        request["device_display_name"] = str(
            self.current_device.get("display_name", "")
        )
        if not request.get("allowed_durations"):
            request["allowed_durations"] = list(
                DEFAULT_APPROVAL_DURATIONS
            )
        if not request.get("default_duration"):
            request["default_duration"] = "session"
        dialog = ApprovalDecisionDialog(
            self.root,
            request=request,
            decision=decision,
        )
        self.root.wait_window(dialog)
        if dialog.result is None:
            return

        self.approval_decision_in_progress = True
        self._set_busy(True)
        label = "Approving" if decision == "approve" else "Denying"
        self._set_status(
            f"{label} access for {request.get('username', 'user')}...",
            "warning",
        )
        self._submit_request(
            kind="approval_decision",
            path=(
                f"/api/v1/admin/approval-requests/{request['id']}"
                f"/{decision}"
            ),
            method="POST",
            payload=dialog.result,
            context={
                "decision": decision,
                "request_id": str(request["id"]),
                "username": str(request.get("username", "user")),
            },
        )

    def _apply_approval_decision_result(
        self,
        future: Future[dict[str, Any]],
        context: dict[str, Any],
    ) -> None:
        self.approval_decision_in_progress = False
        self._set_busy(
            self.inventory_refresh_in_progress
            or self.detail_refresh_in_progress
            or self.device_removal_in_progress
        )
        try:
            response = future.result()
        except Exception as exc:
            message = str(exc)
            if self._is_authentication_error(message):
                self._reauthenticate_and_refresh()
                return
            self._set_status(message, "error")
            messagebox.showerror(
                "Remote approval failed",
                message,
                parent=self.root,
            )
            self._update_approval_buttons()
            return

        decision = str(context.get("decision", "decision"))
        username = str(context.get("username", "user"))
        self._set_status(
            f"Remote {decision} queued for {username}. Waiting for the protected PC...",
            "healthy",
        )
        if response.get("queued"):
            self.root.after(500, self.refresh_selected_device)
        else:
            self.refresh_selected_device()

    def _remove_selected_device(self) -> None:
        device = self._selected_device_summary()
        if device is None or self.device_removal_in_progress:
            return

        device_id = str(device.get("id", ""))
        display_name = str(
            device.get("display_name")
            or device.get("hostname")
            or device_id
        )
        hostname = str(device.get("hostname") or "Unknown")
        status = "Online" if device.get("online") else "Offline"
        last_seen = self._local_time(device.get("last_seen_utc"))

        online_warning = ""
        if device.get("online"):
            online_warning = (
                "\n\nThis device is currently online. Removing it will "
                "invalidate its Remote Agent registration. It must be "
                "registered again before it can report to this server."
            )

        confirmed = messagebox.askyesno(
            "Remove device registration",
            (
                f"Remove {display_name} from Remote Administration?\n\n"
                f"Hostname: {hostname}\n"
                f"Status: {status}\n"
                f"Last seen: {last_seen}\n"
                f"Device ID: {device_id}\n\n"
                "This permanently deletes the server-side registration "
                "and cached dashboard, session, audit, log, and diagnostic "
                "data. It does not uninstall Windows Login Guard from the "
                "protected PC."
                f"{online_warning}"
            ),
            icon="warning",
            parent=self.root,
        )
        if not confirmed:
            return

        self.device_removal_in_progress = True
        self._set_busy(True)
        self._set_status(
            f"Removing {display_name}...",
            "warning",
        )
        self._submit_request(
            kind="remove_device",
            path=f"/api/v1/admin/devices/{device_id}",
            method="DELETE",
            payload={},
            context={
                "device_id": device_id,
                "display_name": display_name,
            },
        )

    def _apply_remove_device_result(
        self,
        future: Future[dict[str, Any]],
        context: dict[str, Any],
    ) -> None:
        self.device_removal_in_progress = False
        self._set_busy(
            self.inventory_refresh_in_progress
            or self.detail_refresh_in_progress
        )

        try:
            future.result()
        except Exception as exc:
            message = str(exc)
            if self._is_authentication_error(message):
                self._reauthenticate_and_refresh()
                return
            self._set_status(message, "error")
            messagebox.showerror(
                "Device removal failed",
                message,
                parent=self.root,
            )
            self._update_remove_device_button()
            return

        removed_id = str(context.get("device_id", ""))
        display_name = str(
            context.get("display_name", "Device")
        )
        self.devices = [
            device
            for device in self.devices
            if str(device.get("id", "")) != removed_id
        ]
        self.selected_device_id = ""
        self.current_device = {}
        self.pending_detail_device_id = ""
        self._clear_device_view("Select a device")
        self._set_status(
            f"Removed {display_name}.",
            "healthy",
        )
        self.refresh_devices(silent=True)

    def _start_pending_detail_refresh(
        self,
        completed_device_id: str,
    ) -> None:
        pending = self.pending_detail_device_id
        self.pending_detail_device_id = ""

        if (
            pending
            and pending != completed_device_id
            and pending == self.selected_device_id
        ):
            self.root.after_idle(self.refresh_selected_device)

    def _tab_changed(self, _event: tk.Event) -> None:
        if not self.current_device or self.closing:
            return
        self.root.after_idle(self._render_active_tab)

    def _render_device_header(self, device: dict[str, Any]) -> None:
        display_name = str(
            device.get("display_name")
            or device.get("hostname")
            or "Device"
        )
        self.device_title.configure(text=display_name)

    def _render_active_tab(self) -> None:
        if not self.current_device:
            return

        selected_tab = self.tabs.index(self.tabs.select())
        renderers = {
            0: self._render_dashboard,
            1: self._render_approvals,
            2: self._render_sessions,
            3: self._render_audit,
            4: self._render_logs,
            5: self._render_diagnostics,
        }
        renderer = renderers.get(selected_tab)
        if renderer:
            renderer(self.current_device)

    def _render_dashboard(self, device: dict[str, Any]) -> None:
        dashboard = dict(device.get("dashboard", {}))
        counts = dict(dashboard.get("counts", {}))
        maintenance = dict(dashboard.get("maintenance", {}))

        self.summary_labels["connectivity"].configure(
            text=(
                "Revoked"
                if device.get("revoked")
                else (
                    "Online"
                    if device.get("online")
                    else "Offline"
                )
            )
        )
        self.summary_labels["health"].configure(
            text=str(
                dashboard.get("overall_health", "Unknown")
            ).title()
        )
        self.summary_labels["maintenance"].configure(
            text=(
                "Enabled"
                if maintenance.get("enabled")
                else "Disabled"
            )
        )
        self.summary_labels["enrolled"].configure(
            text=str(counts.get("enrolled_accounts", 0))
        )
        self.summary_labels["sessions"].configure(
            text=str(
                counts.get(
                    "active_sessions",
                    len(device.get("sessions", [])),
                )
            )
        )
        self.summary_labels["waiting"].configure(
            text=str(counts.get("waiting_for_verification", 0))
        )
        pending_approvals = sum(
            1
            for request in device.get("approval_requests", [])
            if str(request.get("status", "")) == "pending"
        )
        self.summary_labels["approvals"].configure(
            text=str(pending_approvals)
        )
        self.device_info.configure(
            text=(
                f"Host: {device.get('hostname', '—')}   |   "
                f"Endpoint: {device.get('endpoint_version', '—')}   |   "
                "Last seen: "
                f"{self._local_time(device.get('last_seen_utc'))}   |   "
                f"Agent: {device.get('agent_status', '—')}   |   "
                "Remote approval: "
                f"{'Ready' if device.get('remote_approval_ready') else 'Waiting for v1.9.0 agent handshake'}\n"
                f"Operating system: "
                f"{device.get('operating_system', '—')}"
            )
        )

        items = self.notifications_tree.get_children()
        if items:
            self.notifications_tree.delete(*items)

        notifications = list(dashboard.get("notifications", []))
        if not notifications:
            notifications = [
                {
                    "severity": "information",
                    "title": "No synchronized notifications",
                    "detail": (
                        device.get("last_error")
                        or "No active warnings were reported."
                    ),
                }
            ]

        for record in notifications[:100]:
            self.notifications_tree.insert(
                "",
                "end",
                values=(
                    str(
                        record.get(
                            "severity",
                            "information",
                        )
                    ).title(),
                    record.get("title", ""),
                    record.get("detail", ""),
                ),
            )

    def _render_approvals(self, device: dict[str, Any]) -> None:
        items = self.approvals_tree.get_children()
        if items:
            self.approvals_tree.delete(*items)

        requests = list(device.get("approval_requests", []))
        status_labels = {
            "pending": "Pending",
            "approved_pending_delivery": "Approval queued",
            "denied_pending_delivery": "Denial queued",
            "approved": "Approved",
            "denied": "Denied",
            "expired": "Expired",
            "cancelled": "Cancelled",
            "failed": "Failed",
        }
        for request in requests[:250]:
            request_id = str(request.get("id", ""))
            self.approvals_tree.insert(
                "",
                "end",
                iid=request_id,
                values=(
                    request.get("username", ""),
                    request.get("session_id", ""),
                    request.get("reason", ""),
                    self._local_time(request.get("requested_utc")),
                    self._local_time(request.get("expires_utc")),
                    status_labels.get(
                        str(request.get("status", "")),
                        str(request.get("status", "")).replace("_", " ").title(),
                    ),
                ),
            )

        pending_ids = [
            str(request.get("id", ""))
            for request in requests
            if str(request.get("status", "")) == "pending"
        ]
        if pending_ids and self.approvals_tree.exists(pending_ids[0]):
            self.approvals_tree.selection_set(pending_ids[0])
            self.approvals_tree.focus(pending_ids[0])
        self._update_approval_buttons()

    def _render_sessions(self, device: dict[str, Any]) -> None:
        selection = self.sessions_tree.selection()
        selected_id = str(selection[0]) if selection else ""

        items = self.sessions_tree.get_children()
        if items:
            self.sessions_tree.delete(*items)

        session_ids: list[str] = []
        for session in list(device.get("sessions", []))[:250]:
            session_id = str(session.get("session_id", ""))
            if not session_id:
                continue
            session_ids.append(session_id)
            self.sessions_tree.insert(
                "",
                "end",
                iid=session_id,
                values=(
                    session_id,
                    session.get("username", ""),
                    session.get("connection_state", ""),
                    session.get("verification_state", ""),
                    session.get("verification_reason", "") or "—",
                    (
                        self._duration(
                            session.get("remaining_seconds")
                        )
                        if session.get("verification_required")
                        else "—"
                    ),
                    session.get("failed_attempts", 0),
                    (
                        "Ready"
                        if session.get("recovery_available")
                        else "Locked"
                    ),
                ),
            )

        if selected_id and self.sessions_tree.exists(selected_id):
            self.sessions_tree.selection_set(selected_id)
            self.sessions_tree.focus(selected_id)
        self._update_session_action_buttons()

    def _render_audit(self, device: dict[str, Any]) -> None:
        items = self.audit_tree.get_children()
        if items:
            self.audit_tree.delete(*items)

        records = list(device.get("audit", []))
        for record in records[:MAX_AUDIT_RENDER_ROWS]:
            details = record.get("details", {})
            self.audit_tree.insert(
                "",
                "end",
                values=(
                    self._local_time(record.get("timestamp_utc")),
                    str(
                        record.get("action", "")
                    ).replace("_", " ").title(),
                    record.get("actor_username", ""),
                    record.get("target_username", ""),
                    (
                        json.dumps(details, sort_keys=True)
                        if details
                        else ""
                    ),
                ),
            )

        if len(records) > MAX_AUDIT_RENDER_ROWS:
            self._set_status(
                "Showing the newest "
                f"{MAX_AUDIT_RENDER_ROWS} of "
                f"{len(records)} audit records.",
                "information",
            )

    def _render_logs(self, device: dict[str, Any]) -> None:
        logs = str(device.get("logs", ""))
        if len(logs) > MAX_LOG_RENDER_CHARS:
            logs = (
                "[Showing the last "
                f"{MAX_LOG_RENDER_CHARS:,} characters]\n\n"
                + logs[-MAX_LOG_RENDER_CHARS:]
            )

        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", logs)
        self.log_text.configure(state="disabled")

    def _render_diagnostics(
        self,
        device: dict[str, Any],
    ) -> None:
        items = self.diagnostics_tree.get_children()
        if items:
            self.diagnostics_tree.delete(*items)

        diagnostics = dict(device.get("diagnostics", {}))
        health = list(diagnostics.get("health", []))
        if device.get("last_error"):
            health.insert(
                0,
                {
                    "component": "Remote Agent",
                    "status": "warning",
                    "detail": device.get("last_error"),
                },
            )

        for record in health[:250]:
            self.diagnostics_tree.insert(
                "",
                "end",
                values=(
                    record.get("component", ""),
                    str(
                        record.get("status", "unknown")
                    ).title(),
                    record.get("detail", ""),
                ),
            )

        paths = diagnostics.get("paths", {})
        if isinstance(paths, dict):
            for name, value in list(paths.items())[:100]:
                self.diagnostics_tree.insert(
                    "",
                    "end",
                    values=(
                        str(name).replace("_", " ").title(),
                        "Path",
                        value,
                    ),
                )

    def _clear_device_view(self, message: str) -> None:
        self.current_device = {}
        self.device_title.configure(text=message)
        if hasattr(self, "approvals_tree"):
            items = self.approvals_tree.get_children()
            if items:
                self.approvals_tree.delete(*items)
        self._update_remove_device_button()
        self._update_approval_buttons()
        self._update_session_action_buttons()
        for label in self.summary_labels.values():
            label.configure(text="—")
        self.device_info.configure(text="")
        for tree in (
            self.notifications_tree,
            self.sessions_tree,
            self.audit_tree,
            self.diagnostics_tree,
        ):
            for item in tree.get_children():
                tree.delete(item)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _find_log(self) -> None:
        query = self.log_search_var.get()
        if not query:
            return
        start = self.log_text.index("insert +1c")
        position = self.log_text.search(query, start, stopindex="end", nocase=True)
        if not position:
            position = self.log_text.search(query, "1.0", stopindex=start, nocase=True)
        if position:
            end = f"{position}+{len(query)}c"
            self.log_text.tag_remove("search", "1.0", "end")
            self.log_text.tag_add("search", position, end)
            self.log_text.tag_configure("search", background="yellow")
            self.log_text.mark_set("insert", end)
            self.log_text.see(position)

    def _schedule_refresh(self) -> None:
        if self.closing:
            return
        self.auto_refresh_job = self.root.after(
            AUTO_REFRESH_MS,
            self._auto_refresh,
        )

    def _auto_refresh(self) -> None:
        self.auto_refresh_job = None
        if self.closing:
            return

        if (
            not self.inventory_refresh_in_progress
            and not self.detail_refresh_in_progress
            and not self.device_removal_in_progress
            and not self.approval_decision_in_progress
            and not self.session_action_in_progress
        ):
            self.refresh_devices(silent=True)

        self._schedule_refresh()

    def close(self) -> None:
        if self.closing:
            return
        self.closing = True

        if self.auto_refresh_job:
            self.root.after_cancel(self.auto_refresh_job)
            self.auto_refresh_job = None
        if self.approval_watch_job:
            self.root.after_cancel(self.approval_watch_job)
            self.approval_watch_job = None
        if self.ui_queue_job:
            self.root.after_cancel(self.ui_queue_job)
            self.ui_queue_job = None

        self.client.session_token = ""
        self.executor.shutdown(
            wait=False,
            cancel_futures=True,
        )
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    try:
        RemoteAdminApp().run()
    except SystemExit:
        return
    except Exception as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Remote Administration failed",
            str(exc),
            parent=root,
        )
        root.destroy()


if __name__ == "__main__":
    main()
