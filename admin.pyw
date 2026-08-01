from __future__ import annotations

import ctypes
import socket
import subprocess
import time
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from common import HOST, MANAGEMENT_TOKEN_PATH, PORT_FILE, recv_json, send_json


SERVICE_NAME = "WindowsLoginGuard"
AUTO_REFRESH_MS = 5000


class AdminClient:
    def __init__(self, token: str) -> None:
        self.token = token

    def request(self, payload: dict, timeout: float = 6.0) -> dict:
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
                    return {
                        "ok": False,
                        "error": "invalid_response",
                        "message": "The service returned an invalid response.",
                    }
                return response
        except FileNotFoundError:
            return {
                "ok": False,
                "error": "service_offline",
                "message": "The service endpoint is not available.",
            }
        except (ConnectionRefusedError, ConnectionResetError):
            return {
                "ok": False,
                "error": "service_restarting",
                "message": "The service is restarting or unavailable.",
            }
        except socket.timeout:
            return {
                "ok": False,
                "error": "ipc_timeout",
                "message": "The service did not respond before the IPC timeout.",
            }
        except (OSError, ValueError) as exc:
            return {
                "ok": False,
                "error": "service_error",
                "message": str(exc),
            }


class AdminConsole:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.withdraw()
        if not ctypes.windll.shell32.IsUserAnAdmin():
            messagebox.showerror(
                "Administrator required",
                "Run Windows Login Guard Admin as administrator.",
                parent=self.root,
            )
            raise SystemExit(1)

        try:
            token = MANAGEMENT_TOKEN_PATH.read_text(
                encoding="ascii"
            ).strip()
        except OSError as exc:
            messagebox.showerror(
                "Management token unavailable",
                str(exc),
                parent=self.root,
            )
            raise SystemExit(1)

        self.client = AdminClient(token)
        self.local_version = self._read_local_version()
        self.service_version = "unknown"
        self.auto_refresh_job: str | None = None
        self.restart_in_progress = False

        self.accounts: list[dict] = []
        self.approvers: list[dict] = []
        self.maintenance: dict = {"enabled": False}
        self.config_schema: dict[str, dict] = {}
        self.config_values: dict[str, object] = {}
        self.config_bindings: dict[str, dict] = {}
        self.config_dirty = False

        self._configure_root()
        self._build_shell()
        self.root.deiconify()

        self.refresh_dashboard()
        self.refresh_accounts()
        self.refresh_config()
        self.refresh_audit()
        self.refresh_diagnostics()
        self._schedule_auto_refresh()

    @staticmethod
    def _read_local_version() -> str:
        try:
            return Path(__file__).with_name("VERSION").read_text(
                encoding="utf-8"
            ).strip()
        except OSError:
            return "unknown"

    def _configure_root(self) -> None:
        self.root.title("Windows Login Guard Administration")
        self.root.geometry("1160x780")
        self.root.minsize(1020, 680)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        style = ttk.Style(self.root)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("PageTitle.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Field.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Muted.TLabel", foreground="#5f6368")
        style.configure("Error.TLabel", foreground="#b3261e")
        style.configure("CardValue.TLabel", font=("Segoe UI", 15, "bold"))

    def _build_shell(self) -> None:
        header = ttk.Frame(self.root)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header,
            text="Windows Login Guard Administration",
            style="Title.TLabel",
        ).grid(row=0, column=0, sticky="w")
        self.version_label = ttk.Label(
            header,
            text=f"Admin Console {self.local_version}",
            style="Muted.TLabel",
        )
        self.version_label.grid(row=0, column=1, sticky="e")

        self.tabs = ttk.Notebook(self.root)
        self.tabs.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=14,
            pady=(0, 8),
        )

        self.dashboard_tab = ttk.Frame(self.tabs)
        self.accounts_tab = ttk.Frame(self.tabs)
        self.settings_tab = ttk.Frame(self.tabs)
        self.maintenance_tab = ttk.Frame(self.tabs)
        self.audit_tab = ttk.Frame(self.tabs)
        self.diagnostics_tab = ttk.Frame(self.tabs)

        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.accounts_tab, text="Enrolled Accounts")
        self.tabs.add(self.settings_tab, text="Configuration")
        self.tabs.add(
            self.maintenance_tab,
            text="Recovery & Maintenance",
        )
        self.tabs.add(self.audit_tab, text="Audit")
        self.tabs.add(self.diagnostics_tab, text="Diagnostics")

        self._build_dashboard_tab()
        self._build_accounts_tab()
        self._build_settings_tab()
        self._build_maintenance_tab()
        self._build_audit_tab()
        self._build_diagnostics_tab()

        status_frame = ttk.Separator(self.root, orient="horizontal")
        status_frame.grid(row=2, column=0, sticky="ew")
        self.status_text = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(
            self.root,
            textvariable=self.status_text,
            anchor="w",
        )
        self.status_label.grid(
            row=3,
            column=0,
            sticky="ew",
            padx=14,
            pady=(5, 7),
        )

    def set_status(self, message: str, level: str = "information") -> None:
        self.status_text.set(message)
        foreground = {
            "error": "#b3261e",
            "warning": "#8a4b00",
            "healthy": "#176b2c",
            "information": "#303030",
        }.get(level, "#303030")
        self.status_label.configure(foreground=foreground)
        self.root.update_idletasks()

    @staticmethod
    def _error_message(response: dict) -> str:
        return str(
            response.get("message")
            or response.get("error")
            or "Unknown service error"
        )

    def api(self, payload: dict, *, quiet: bool = False) -> dict:
        response = self.client.request(payload)
        if not response.get("ok") and not quiet:
            self.set_status(self._error_message(response), "error")
        return response

    def _schedule_auto_refresh(self) -> None:
        if self.auto_refresh_job is not None:
            self.root.after_cancel(self.auto_refresh_job)
        self.auto_refresh_job = self.root.after(
            AUTO_REFRESH_MS,
            self._auto_refresh,
        )

    def _auto_refresh(self) -> None:
        self.auto_refresh_job = None
        if not self.restart_in_progress:
            self.refresh_dashboard(quiet=True)
        self._schedule_auto_refresh()

    @staticmethod
    def _format_local_timestamp(value: object) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        try:
            normalized = (
                raw[:-1] + "+00:00"
                if raw.endswith("Z")
                else raw
            )
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            local_value = parsed.astimezone()
            return local_value.strftime(
                "%Y-%m-%d %H:%M:%S %Z"
            )
        except (TypeError, ValueError):
            return raw

    @staticmethod
    def _format_duration(seconds: int | None) -> str:
        if seconds is None:
            return "—"
        seconds = max(0, int(seconds))
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        if hours:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"

    @staticmethod
    def _friendly_choice(value: str) -> str:
        special = {
            "topmost": "Topmost window",
            "isolated_desktop": "Isolated desktop",
            "require_admin_approval": "Require administrator approval",
            "admin_session": "Administrator session",
            "until_lock": "Until workstation locks",
            "session": "Current session",
            "once": "One time",
            "logoff": "Sign out",
            "service_start": "Service start",
        }
        return special.get(value, value.replace("_", " ").title())

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    def _build_dashboard_tab(self) -> None:
        self.dashboard_tab.columnconfigure(0, weight=1)
        self.dashboard_tab.rowconfigure(3, weight=1)

        header = ttk.Frame(self.dashboard_tab)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header,
            text="System Overview",
            style="PageTitle.TLabel",
        ).grid(row=0, column=0, sticky="w")
        self.health_badge = tk.Label(
            header,
            text="Connecting",
            font=("Segoe UI", 10, "bold"),
            padx=10,
            pady=4,
            bg="#e8eaed",
            fg="#303030",
        )
        self.health_badge.grid(row=0, column=1, padx=(8, 8))
        ttk.Button(
            header,
            text="Refresh",
            command=self.refresh_dashboard,
        ).grid(row=0, column=2)

        notifications = ttk.LabelFrame(
            self.dashboard_tab,
            text="Notifications",
        )
        notifications.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=16,
            pady=(0, 10),
        )
        notifications.columnconfigure(0, weight=1)
        self.notification_text = tk.StringVar(value="Connecting to service...")
        ttk.Label(
            notifications,
            textvariable=self.notification_text,
            wraplength=1080,
            justify="left",
        ).grid(row=0, column=0, sticky="w", padx=12, pady=10)

        summary = ttk.Frame(self.dashboard_tab)
        summary.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 10))
        self.dashboard_values: dict[str, ttk.Label] = {}
        cards = [
            ("service", "Service"),
            ("maintenance", "Maintenance"),
            ("enrolled_accounts", "Enrolled Accounts"),
            ("active_sessions", "Active Sessions"),
            ("waiting_for_verification", "Waiting Verification"),
            ("recovery_available", "F8 Recovery Ready"),
        ]
        for column, (key, title) in enumerate(cards):
            summary.columnconfigure(column, weight=1)
            card = ttk.LabelFrame(summary, text=title)
            card.grid(
                row=0,
                column=column,
                sticky="nsew",
                padx=(0, 8),
            )
            value = ttk.Label(
                card,
                text="—",
                style="CardValue.TLabel",
                anchor="center",
            )
            value.pack(fill="both", expand=True, padx=10, pady=12)
            self.dashboard_values[key] = value

        content = ttk.Panedwindow(self.dashboard_tab, orient="horizontal")
        content.grid(
            row=3,
            column=0,
            sticky="nsew",
            padx=16,
            pady=(0, 12),
        )

        sessions_frame = ttk.LabelFrame(content, text="Live Sessions")
        activity_frame = ttk.LabelFrame(content, text="Recent Activity")
        content.add(sessions_frame, weight=4)
        content.add(activity_frame, weight=2)

        sessions_frame.columnconfigure(0, weight=1)
        sessions_frame.rowconfigure(0, weight=1)
        session_columns = (
            "session",
            "user",
            "connection",
            "status",
            "reason",
            "timer",
            "failed",
            "recovery",
        )
        self.sessions_tree = ttk.Treeview(
            sessions_frame,
            columns=session_columns,
            show="headings",
            height=13,
        )
        session_headings = {
            "session": "Session",
            "user": "User",
            "connection": "Connection",
            "status": "Verification",
            "reason": "Reason",
            "timer": "Timer",
            "failed": "Failed Attempts",
            "recovery": "Recovery",
        }
        session_widths = {
            "session": 65,
            "user": 150,
            "connection": 90,
            "status": 115,
            "reason": 120,
            "timer": 70,
            "failed": 95,
            "recovery": 85,
        }
        for column in session_columns:
            self.sessions_tree.heading(
                column,
                text=session_headings[column],
            )
            self.sessions_tree.column(
                column,
                width=session_widths[column],
                anchor="w" if column in {"user", "reason"} else "center",
            )
        session_scroll = ttk.Scrollbar(
            sessions_frame,
            orient="vertical",
            command=self.sessions_tree.yview,
        )
        self.sessions_tree.configure(yscrollcommand=session_scroll.set)
        self.sessions_tree.grid(row=0, column=0, sticky="nsew")
        session_scroll.grid(row=0, column=1, sticky="ns")

        activity_frame.columnconfigure(0, weight=1)
        activity_frame.rowconfigure(0, weight=1)
        self.activity_tree = ttk.Treeview(
            activity_frame,
            columns=("time", "action", "actor"),
            show="headings",
            height=13,
        )
        for column, heading, width in (
            ("time", "Time (Local)", 175),
            ("action", "Action", 155),
            ("actor", "Actor", 110),
        ):
            self.activity_tree.heading(column, text=heading)
            self.activity_tree.column(column, width=width, anchor="w")
        self.activity_tree.grid(row=0, column=0, sticky="nsew")

    def _set_dashboard_offline(self, response: dict) -> None:
        error = str(response.get("error", "service_error"))
        message = self._error_message(response)
        if self.restart_in_progress or error == "service_restarting":
            title = "Restarting"
            detail = "Service restart in progress. Reconnecting automatically."
            color = "#8a4b00"
            background = "#fff4ce"
        else:
            title = "Offline"
            detail = message
            color = "#b3261e"
            background = "#fde7e9"
        self.health_badge.configure(
            text=title,
            fg=color,
            bg=background,
        )
        self.notification_text.set(detail)
        self.dashboard_values["service"].configure(text=title)
        for key in (
            "maintenance",
            "enrolled_accounts",
            "active_sessions",
            "waiting_for_verification",
            "recovery_available",
        ):
            self.dashboard_values[key].configure(text="Unavailable")
        self.set_status(detail, "warning" if title == "Restarting" else "error")

    def refresh_dashboard(self, quiet: bool = False) -> None:
        response = self.api(
            {"action": "admin_dashboard"},
            quiet=True,
        )
        if not response.get("ok"):
            self._set_dashboard_offline(response)
            return

        service = dict(response.get("service", {}))
        self.service_version = str(service.get("version", "unknown"))
        version_mismatch = self.service_version != self.local_version
        if version_mismatch:
            self.health_badge.configure(
                text="Version mismatch",
                fg="#8a4b00",
                bg="#fff4ce",
            )
            self.notification_text.set(
                f"Admin Console {self.local_version}; service "
                f"{self.service_version}. Run the v{self.local_version} upgrade."
            )
            self.set_status(
                "Admin Console and service versions do not match.",
                "warning",
            )
        else:
            overall = str(response.get("overall_health", "healthy"))
            badge = {
                "healthy": ("Healthy", "#176b2c", "#dff6dd"),
                "warning": ("Warning", "#8a4b00", "#fff4ce"),
                "critical": ("Critical", "#b3261e", "#fde7e9"),
            }.get(overall, ("Unknown", "#303030", "#e8eaed"))
            self.health_badge.configure(
                text=badge[0],
                fg=badge[1],
                bg=badge[2],
            )
            notifications = list(response.get("notifications", []))
            self.notification_text.set(
                "   |   ".join(
                    str(item.get("title", ""))
                    for item in notifications[:4]
                )
                or "No active notifications."
            )
            if not quiet:
                self.set_status("Dashboard refreshed.", "healthy")

        uptime = self._format_duration(
            int(service.get("uptime_seconds", 0))
        )
        self.dashboard_values["service"].configure(
            text=f"{service.get('status', 'Unknown')}\n{uptime}"
        )
        maintenance = dict(response.get("maintenance", {}))
        self.dashboard_values["maintenance"].configure(
            text="Enabled" if maintenance.get("enabled", False) else "Disabled"
        )
        counts = dict(response.get("counts", {}))
        for key in (
            "enrolled_accounts",
            "active_sessions",
            "waiting_for_verification",
            "recovery_available",
        ):
            self.dashboard_values[key].configure(text=str(counts.get(key, 0)))

        for item in self.sessions_tree.get_children():
            self.sessions_tree.delete(item)
        for session in response.get("sessions", []):
            self.sessions_tree.insert(
                "",
                "end",
                values=(
                    session.get("session_id", ""),
                    session.get("username", "Unknown"),
                    session.get("connection_state", "Unknown"),
                    session.get("verification_state", "Unknown"),
                    self._friendly_choice(
                        str(session.get("verification_reason", ""))
                    ) if session.get("verification_reason") else "—",
                    self._format_duration(session.get("remaining_seconds")),
                    session.get("failed_attempts", 0),
                    "Ready"
                    if session.get("recovery_available", False)
                    else "Locked",
                ),
            )

        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)
        for record in response.get("recent_activity", []):
            self.activity_tree.insert(
                "",
                "end",
                values=(
                    self._format_local_timestamp(
                        record.get("timestamp_utc", "")
                    ),
                    str(record.get("action", "")).replace("_", " ").title(),
                    record.get("actor_username", ""),
                ),
            )

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def _build_settings_tab(self) -> None:
        self.settings_tab.columnconfigure(0, weight=1)
        self.settings_tab.rowconfigure(1, weight=1)

        header = ttk.Frame(self.settings_tab)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header,
            text="Configuration",
            style="PageTitle.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Values and available selections are loaded from the service schema.",
            style="Muted.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(3, 0))

        self.settings_notebook = ttk.Notebook(self.settings_tab)
        self.settings_notebook.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=16,
            pady=(0, 10),
        )

        actions = ttk.Frame(self.settings_tab)
        actions.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
        self.config_state_text = tk.StringVar(value="Loading configuration...")
        ttk.Label(
            actions,
            textvariable=self.config_state_text,
            style="Muted.TLabel",
        ).pack(side="left", fill="x", expand=True)
        ttk.Button(
            actions,
            text="Reload",
            command=self.refresh_config,
        ).pack(side="right", padx=(8, 0))
        self.apply_config_button = ttk.Button(
            actions,
            text="Apply",
            command=self.apply_config,
        )
        self.apply_config_button.pack(side="right")
        self.apply_config_button.state(["disabled"])

    def _clear_config_form(self) -> None:
        for tab_id in self.settings_notebook.tabs():
            self.settings_notebook.forget(tab_id)
        self.config_bindings.clear()

    def refresh_config(self) -> None:
        response = self.api({"action": "admin_get_config"})
        if not response.get("ok"):
            self.config_state_text.set(self._error_message(response))
            return
        self.service_version = str(
            response.get("service_version", self.service_version)
        )
        self.config_schema = dict(response.get("schema", {}))
        self.config_values = dict(response.get("values", {}))
        self.config_dirty = False
        self._render_config_form()
        self.config_state_text.set("Configuration loaded from the service.")
        self.apply_config_button.state(["disabled"])

    def _render_config_form(self) -> None:
        self._clear_config_form()
        sections: dict[str, list[tuple[str, dict]]] = {}
        for key, rule in self.config_schema.items():
            sections.setdefault(
                str(rule.get("section", "Other")),
                [],
            ).append((key, rule))

        for section_name, fields in sections.items():
            tab = ttk.Frame(self.settings_notebook)
            self.settings_notebook.add(tab, text=section_name)
            tab.columnconfigure(0, weight=1)
            tab.columnconfigure(1, weight=1)

            for index, (key, rule) in enumerate(fields):
                column = index % 2
                row = index // 2
                panel = ttk.LabelFrame(
                    tab,
                    text=str(rule.get("label", key)),
                )
                panel.grid(
                    row=row,
                    column=column,
                    sticky="nsew",
                    padx=(12 if column == 0 else 6, 12),
                    pady=(12 if row == 0 else 4, 4),
                )
                panel.columnconfigure(0, weight=1)

                description = str(rule.get("description", ""))
                ttk.Label(
                    panel,
                    text=description,
                    wraplength=470,
                    justify="left",
                    style="Muted.TLabel",
                ).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 6))

                rule_type = str(rule.get("type", ""))
                raw_value = self.config_values.get(key)
                display_to_raw: dict[str, str] = {}

                if rule_type == "boolean":
                    variable: tk.Variable = tk.BooleanVar(value=bool(raw_value))
                    control = ttk.Checkbutton(
                        panel,
                        text="Enabled",
                        variable=variable,
                    )
                elif rule_type == "enum":
                    choices = [str(item) for item in rule.get("choices", [])]
                    display_to_raw = {
                        self._friendly_choice(item): item for item in choices
                    }
                    raw_to_display = {
                        raw: display for display, raw in display_to_raw.items()
                    }
                    variable = tk.StringVar(
                        value=raw_to_display.get(
                            str(raw_value),
                            self._friendly_choice(str(raw_value)),
                        )
                    )
                    control = ttk.Combobox(
                        panel,
                        textvariable=variable,
                        values=list(display_to_raw),
                        state="readonly",
                        width=34,
                    )
                elif rule_type == "integer":
                    variable = tk.StringVar(value=str(raw_value))
                    control = ttk.Entry(
                        panel,
                        textvariable=variable,
                        width=16,
                    )
                    minimum = int(rule["minimum"])
                    maximum = int(rule["maximum"])
                    ttk.Label(
                        panel,
                        text=f"Allowed range: {minimum}–{maximum}",
                        style="Muted.TLabel",
                    ).grid(row=2, column=0, sticky="w", padx=10, pady=(4, 0))
                else:
                    continue

                control.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 4))
                error_label = ttk.Label(panel, text="", style="Error.TLabel")
                error_label.grid(row=3, column=0, sticky="w", padx=10, pady=(3, 8))

                self.config_bindings[key] = {
                    "rule": rule,
                    "variable": variable,
                    "display_to_raw": display_to_raw,
                    "error_label": error_label,
                }
                variable.trace_add(
                    "write",
                    lambda *_args, field_key=key: self._config_changed(field_key),
                )
                if rule_type == "integer":
                    control.bind(
                        "<FocusOut>",
                        lambda _event, field_key=key: self._validate_config_field(
                            field_key
                        ),
                    )

    def _config_changed(self, _key: str) -> None:
        self.config_dirty = True
        self.root.after_idle(self._update_config_action_state)

    def _binding_value(self, key: str) -> object:
        binding = self.config_bindings[key]
        rule = binding["rule"]
        value = binding["variable"].get()
        rule_type = str(rule["type"])
        if rule_type == "boolean":
            return bool(value)
        if rule_type == "integer":
            text = str(value).strip()
            if not text or not text.lstrip("-").isdigit():
                raise ValueError("Enter a whole number.")
            number = int(text)
            minimum = int(rule["minimum"])
            maximum = int(rule["maximum"])
            if number < minimum or number > maximum:
                raise ValueError(
                    f"Value must be between {minimum} and {maximum}."
                )
            return number
        if rule_type == "enum":
            raw = binding["display_to_raw"].get(str(value))
            if raw is None:
                raise ValueError("Select one of the available options.")
            return raw
        raise ValueError("Unsupported configuration field type.")

    def _validate_config_field(self, key: str) -> bool:
        binding = self.config_bindings[key]
        try:
            self._binding_value(key)
        except ValueError as exc:
            binding["error_label"].configure(text=str(exc))
            return False
        binding["error_label"].configure(text="")
        return True

    def _collect_config(self) -> tuple[dict[str, object], list[str]]:
        values: dict[str, object] = {}
        errors: list[str] = []
        for key in self.config_bindings:
            try:
                values[key] = self._binding_value(key)
                self.config_bindings[key]["error_label"].configure(text="")
            except ValueError as exc:
                label = str(self.config_schema[key].get("label", key))
                errors.append(f"{label}: {exc}")
                self.config_bindings[key]["error_label"].configure(text=str(exc))

        if not errors:
            attempts = int(values["max_otp_attempts"])
            threshold = int(values["recovery_otp_failure_threshold"])
            if threshold > attempts:
                message = (
                    "The F8 recovery threshold cannot exceed the maximum "
                    "OTP-attempt limit."
                )
                errors.append(message)
                self.config_bindings[
                    "recovery_otp_failure_threshold"
                ]["error_label"].configure(text=message)
        return values, errors

    def _update_config_action_state(self) -> None:
        if not self.config_bindings:
            self.apply_config_button.state(["disabled"])
            return
        values, errors = self._collect_config()
        changed = any(
            self.config_values.get(key) != value
            for key, value in values.items()
        ) if not errors else False
        if errors:
            self.config_state_text.set("Correct the highlighted values.")
            self.apply_config_button.state(["disabled"])
        elif changed:
            self.config_state_text.set("Unsaved configuration changes.")
            self.apply_config_button.state(["!disabled"])
        else:
            self.config_state_text.set("No unsaved changes.")
            self.apply_config_button.state(["disabled"])

    def apply_config(self) -> None:
        values, errors = self._collect_config()
        if errors:
            self.set_status(errors[0], "error")
            self._update_config_action_state()
            return
        updates = {
            key: value
            for key, value in values.items()
            if self.config_values.get(key) != value
        }
        if not updates:
            self.set_status("No configuration changes to apply.")
            return

        credential = self.ask_admin_credential(
            "Authorize configuration update"
        )
        if credential is None:
            return
        approver_sid, code = credential

        self.set_status("Validating and saving configuration...")
        response = self.api(
            {
                "action": "admin_update_config",
                "approver_sid": approver_sid,
                "code": code,
                "updates": updates,
            },
            quiet=True,
        )
        if not response.get("ok"):
            message = self._error_message(response)
            self.set_status(message, "error")
            messagebox.showerror(
                "Configuration update failed",
                message,
                parent=self.root,
            )
            return

        self.config_values = dict(response.get("values", values))
        self.set_status("Configuration saved. Restarting service...")
        self.restart_in_progress = True
        self._set_dashboard_offline(
            {
                "ok": False,
                "error": "service_restarting",
                "message": "Restarting service and reconnecting...",
            }
        )
        restarted, restart_error = self._restart_service()
        if not restarted:
            self.restart_in_progress = False
            self.set_status(
                f"Configuration saved, but service restart failed: {restart_error}",
                "error",
            )
            messagebox.showwarning(
                "Restart failed",
                "The configuration was saved, but the service could not be "
                f"restarted automatically.\n\n{restart_error}",
                parent=self.root,
            )
            return

        self.set_status("Service restarted. Reconnecting...")
        connected = self._wait_for_service(30)
        self.restart_in_progress = False
        if not connected:
            self.set_status(
                "Service restart completed, but the Admin Console could not reconnect.",
                "error",
            )
            return

        self.refresh_config()
        self.refresh_dashboard(quiet=True)
        self.refresh_diagnostics()
        self.refresh_audit()
        self.set_status("Configuration applied successfully.", "healthy")

    def _restart_service(self) -> tuple[bool, str]:
        command = (
            f"Restart-Service -Name '{SERVICE_NAME}' -Force -ErrorAction Stop; "
            f"(Get-Service -Name '{SERVICE_NAME}').WaitForStatus(" 
            "'Running', [TimeSpan]::FromSeconds(30))"
        )
        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    command,
                ],
                capture_output=True,
                text=True,
                timeout=45,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
        if result.returncode != 0:
            return False, (
                result.stderr.strip()
                or result.stdout.strip()
                or f"PowerShell exited with code {result.returncode}."
            )
        return True, ""

    def _wait_for_service(self, timeout_seconds: int) -> bool:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            self.root.update()
            response = self.client.request(
                {"action": "admin_dashboard"},
                timeout=2.0,
            )
            if response.get("ok"):
                return True
            time.sleep(0.5)
        return False

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------
    def _build_accounts_tab(self) -> None:
        self.accounts_tab.columnconfigure(0, weight=1)
        self.accounts_tab.rowconfigure(1, weight=1)
        header = ttk.Frame(self.accounts_tab)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header,
            text="Enrolled Accounts",
            style="PageTitle.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(
            header,
            text="Refresh",
            command=self.refresh_accounts,
        ).grid(row=0, column=1)

        columns = ("username", "role", "status", "recovery", "generated")
        self.accounts_tree = ttk.Treeview(
            self.accounts_tab,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        labels = {
            "username": "Account",
            "role": "Role",
            "status": "Status",
            "recovery": "Recovery Codes",
            "generated": "Last Generated",
        }
        widths = {
            "username": 280,
            "role": 130,
            "status": 120,
            "recovery": 130,
            "generated": 210,
        }
        for column in columns:
            self.accounts_tree.heading(column, text=labels[column])
            self.accounts_tree.column(column, width=widths[column], anchor="w")
        self.accounts_tree.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=16,
            pady=(0, 10),
        )

        actions = ttk.Frame(self.accounts_tab)
        actions.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
        ttk.Button(
            actions,
            text="Regenerate Recovery Codes",
            command=self.regenerate_recovery,
        ).pack(side="left", padx=(0, 8))
        ttk.Button(
            actions,
            text="Reset OTP Enrollment",
            command=self.reset_otp,
        ).pack(side="left")

    def refresh_accounts(self) -> None:
        response = self.api({"action": "admin_list_accounts"})
        if not response.get("ok"):
            return
        self.accounts = list(response.get("accounts", []))
        self.approvers = list(response.get("approvers", []))
        self.maintenance = dict(response.get("maintenance", {"enabled": False}))
        self._render_maintenance()
        for item in self.accounts_tree.get_children():
            self.accounts_tree.delete(item)
        for account in self.accounts:
            self.accounts_tree.insert(
                "",
                "end",
                iid=str(account["sid"]),
                values=(
                    account["username"],
                    "Administrator" if account["is_administrator"] else "User",
                    "Enrolled" if account["enrolled"] else "Not enrolled",
                    account["recovery_codes_remaining"],
                    account["recovery_codes_generated_at_utc"] or "Unknown",
                ),
            )

    def selected_account(self) -> dict | None:
        selection = self.accounts_tree.selection()
        if not selection:
            messagebox.showwarning(
                "Select an account",
                "Select an enrolled account first.",
                parent=self.root,
            )
            return None
        sid = selection[0]
        return next((item for item in self.accounts if item["sid"] == sid), None)

    def ask_admin_credential(self, title: str) -> tuple[str, str] | None:
        if not self.approvers:
            self.refresh_accounts()
        if not self.approvers:
            messagebox.showerror(
                "No enrolled administrator",
                "No enrolled administrator can authorize this action.",
                parent=self.root,
            )
            return None

        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.columnconfigure(0, weight=1)

        ttk.Label(dialog, text="Approving administrator:").grid(
            row=0, column=0, padx=14, pady=(14, 5), sticky="w"
        )
        labels = [item["label"] for item in self.approvers]
        selected = tk.StringVar(value=labels[0])
        combo = ttk.Combobox(
            dialog,
            textvariable=selected,
            values=labels,
            state="readonly",
            width=42,
        )
        combo.grid(row=1, column=0, padx=14, pady=5)

        ttk.Label(dialog, text="Administrator OTP or recovery code:").grid(
            row=2, column=0, padx=14, pady=(10, 5), sticky="w"
        )
        code_entry = ttk.Entry(dialog, width=28, justify="center", show="•")
        code_entry.grid(row=3, column=0, padx=14, pady=5)

        result: dict[str, str] = {}

        def submit() -> None:
            code = code_entry.get().strip()
            if not code:
                return
            label = selected.get()
            sid = next(
                item["id"] for item in self.approvers if item["label"] == label
            )
            result["sid"] = sid
            result["code"] = code
            dialog.destroy()

        buttons = ttk.Frame(dialog)
        buttons.grid(row=4, column=0, pady=14)
        ttk.Button(buttons, text="Authorize", command=submit).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(
            side="left"
        )
        code_entry.bind("<Return>", lambda _event: submit())
        code_entry.focus_set()
        self.root.wait_window(dialog)
        if not result:
            return None
        return result["sid"], result["code"]

    def regenerate_recovery(self) -> None:
        account = self.selected_account()
        if account is None:
            return
        if not messagebox.askyesno(
            "Regenerate recovery codes",
            "Existing recovery codes will become invalid. Continue?",
            parent=self.root,
        ):
            return
        credential = self.ask_admin_credential(
            "Authorize recovery-code regeneration"
        )
        if credential is None:
            return
        approver_sid, code = credential
        response = self.api(
            {
                "action": "admin_regenerate_recovery",
                "target_sid": account["sid"],
                "approver_sid": approver_sid,
                "code": code,
            }
        )
        if not response.get("generated"):
            messagebox.showerror(
                "Regeneration failed",
                self._error_message(response),
                parent=self.root,
            )
            return
        self.show_recovery_codes(
            account["username"],
            list(response.get("recovery_codes", [])),
        )
        self.refresh_accounts()
        self.refresh_audit()
        self.refresh_dashboard(quiet=True)

    def reset_otp(self) -> None:
        account = self.selected_account()
        if account is None:
            return
        if not messagebox.askyesno(
            "Reset OTP enrollment",
            "This removes the authenticator secret and recovery codes. Continue?",
            parent=self.root,
        ):
            return
        credential = self.ask_admin_credential("Authorize OTP reset")
        if credential is None:
            return
        approver_sid, code = credential
        response = self.api(
            {
                "action": "admin_reset_otp",
                "target_sid": account["sid"],
                "approver_sid": approver_sid,
                "code": code,
            }
        )
        if not response.get("reset"):
            messagebox.showerror(
                "Reset failed",
                self._error_message(response),
                parent=self.root,
            )
            return
        self.set_status(
            f"OTP enrollment reset for {account['username']}.",
            "healthy",
        )
        self.refresh_accounts()
        self.refresh_audit()
        self.refresh_dashboard(quiet=True)

    def show_recovery_codes(self, username: str, codes: list[str]) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Recovery Codes — {username}")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(
            dialog,
            text="Save these one-time recovery codes now.",
            font=("Segoe UI", 12, "bold"),
        ).pack(padx=18, pady=(16, 8))
        text = tk.Text(dialog, width=36, height=10, font=("Consolas", 12))
        text.insert("1.0", "\n".join(codes))
        text.config(state="disabled")
        text.pack(padx=18, pady=8)

        buttons = ttk.Frame(dialog)
        buttons.pack(pady=(4, 16))

        def copy_codes() -> None:
            dialog.clipboard_clear()
            dialog.clipboard_append("\n".join(codes))
            dialog.update()

        def save_codes() -> None:
            path = filedialog.asksaveasfilename(
                parent=dialog,
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                initialfile=f"{username}-recovery-codes.txt",
            )
            if path:
                Path(path).write_text("\n".join(codes) + "\n", encoding="utf-8")

        ttk.Button(buttons, text="Copy", command=copy_codes).pack(
            side="left", padx=5
        )
        ttk.Button(buttons, text="Save As...", command=save_codes).pack(
            side="left", padx=5
        )
        ttk.Button(buttons, text="Continue", command=dialog.destroy).pack(
            side="left", padx=5
        )

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------
    def _build_maintenance_tab(self) -> None:
        panel = ttk.Frame(self.maintenance_tab)
        panel.pack(fill="both", expand=True, padx=24, pady=24)
        ttk.Label(
            panel,
            text="Break-glass Maintenance",
            style="PageTitle.TLabel",
        ).pack(anchor="w", pady=(0, 12))
        self.maintenance_status = tk.StringVar(value="Loading status...")
        ttk.Label(
            panel,
            textvariable=self.maintenance_status,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", pady=(0, 14))
        ttk.Label(
            panel,
            text=(
                "Enabling or disabling maintenance mode requires an enrolled "
                "administrator code and the machine maintenance recovery key. "
                "All changes are audited."
            ),
            wraplength=900,
            justify="left",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 18))
        buttons = ttk.Frame(panel)
        buttons.pack(anchor="w")
        ttk.Button(
            buttons,
            text="Refresh Status",
            command=self.refresh_accounts,
        ).pack(side="left", padx=(0, 8))
        self.enable_maintenance_button = ttk.Button(
            buttons,
            text="Enable Maintenance Mode",
            command=self.enable_maintenance,
        )
        self.enable_maintenance_button.pack(side="left", padx=(0, 8))
        self.disable_maintenance_button = ttk.Button(
            buttons,
            text="Restore OTP Enforcement",
            command=self.disable_maintenance,
        )
        self.disable_maintenance_button.pack(side="left")

        ttk.Separator(panel, orient="horizontal").pack(
            fill="x",
            pady=22,
        )
        ttk.Label(
            panel,
            text="Maintenance Recovery Key",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 6))
        ttk.Label(
            panel,
            text=(
                "The key was displayed once during installation. Windows "
                "Login Guard stores only its SHA-256 hash, so the existing "
                "key cannot be viewed or recovered. If it was not saved or "
                "has been lost, rotate it here. The previous key becomes "
                "invalid immediately."
            ),
            wraplength=900,
            justify="left",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 10))
        ttk.Button(
            panel,
            text="Rotate Maintenance Recovery Key",
            command=self.rotate_maintenance_key,
        ).pack(anchor="w")

    def _render_maintenance(self) -> None:
        enabled = bool(self.maintenance.get("enabled", False))
        if enabled:
            self.maintenance_status.set(
                "MAINTENANCE MODE IS ENABLED\n\n"
                f"Enabled at: {self.maintenance.get('enabled_at_utc', 'Unknown')}\n"
                f"Enabled by: {self.maintenance.get('enabled_by', 'Unknown')}\n"
                f"Reason: {self.maintenance.get('reason', 'Not recorded')}"
            )
            self.enable_maintenance_button.state(["disabled"])
            self.disable_maintenance_button.state(["!disabled"])
        else:
            self.maintenance_status.set(
                "Maintenance mode is disabled. OTP enforcement is active."
            )
            self.enable_maintenance_button.state(["!disabled"])
            self.disable_maintenance_button.state(["disabled"])

    def ask_recovery_key(self) -> str | None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Maintenance recovery key")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        ttk.Label(
            dialog,
            text="Enter the offline maintenance recovery key:",
        ).pack(padx=18, pady=(18, 6))
        ttk.Label(
            dialog,
            text=(
                "This key was shown once during installation. If it was "
                "not saved, cancel this dialog and use Rotate Maintenance "
                "Recovery Key on the Recovery & Maintenance tab."
            ),
            wraplength=430,
            justify="left",
            style="Muted.TLabel",
        ).pack(padx=18, pady=(0, 8))
        entry = ttk.Entry(dialog, width=48, justify="center")
        entry.pack(padx=18, pady=8)
        result: dict[str, str] = {}

        def submit() -> None:
            value = entry.get().strip()
            if value:
                result["key"] = value
                dialog.destroy()

        buttons = ttk.Frame(dialog)
        buttons.pack(pady=(8, 18))
        ttk.Button(buttons, text="Continue", command=submit).pack(
            side="left",
            padx=(0, 8),
        )
        ttk.Button(
            buttons,
            text="Cancel",
            command=dialog.destroy,
        ).pack(side="left")
        entry.bind("<Return>", lambda _event: submit())
        entry.focus_set()
        self.root.wait_window(dialog)
        return result.get("key")

    def show_maintenance_recovery_key(self, recovery_key: str) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("New Maintenance Recovery Key")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        ttk.Label(
            dialog,
            text="Save this maintenance recovery key now.",
            font=("Segoe UI", 12, "bold"),
        ).pack(padx=18, pady=(16, 6))
        ttk.Label(
            dialog,
            text=(
                "It is displayed only once. Only its SHA-256 hash is stored "
                "on this computer. The previous key is no longer valid."
            ),
            wraplength=470,
            justify="left",
        ).pack(padx=18, pady=(0, 10))

        text = tk.Text(
            dialog,
            width=48,
            height=2,
            font=("Consolas", 12),
            wrap="none",
        )
        text.insert("1.0", recovery_key)
        text.config(state="disabled")
        text.pack(padx=18, pady=8)

        buttons = ttk.Frame(dialog)
        buttons.pack(pady=(6, 16))

        def copy_key() -> None:
            dialog.clipboard_clear()
            dialog.clipboard_append(recovery_key)
            dialog.update()

        def save_key() -> None:
            path = filedialog.asksaveasfilename(
                parent=dialog,
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                initialfile="windows-login-guard-maintenance-key.txt",
            )
            if path:
                Path(path).write_text(
                    recovery_key + "\n",
                    encoding="utf-8",
                )

        ttk.Button(buttons, text="Copy", command=copy_key).pack(
            side="left",
            padx=5,
        )
        ttk.Button(buttons, text="Save As...", command=save_key).pack(
            side="left",
            padx=5,
        )
        ttk.Button(buttons, text="I Saved It", command=dialog.destroy).pack(
            side="left",
            padx=5,
        )

    def rotate_maintenance_key(self) -> None:
        if not messagebox.askyesno(
            "Rotate maintenance recovery key",
            (
                "The current maintenance recovery key will stop working "
                "immediately. Continue?"
            ),
            parent=self.root,
        ):
            return
        credential = self.ask_admin_credential(
            "Authorize maintenance-key rotation"
        )
        if credential is None:
            return
        approver_sid, code = credential
        response = self.api(
            {
                "action": "admin_rotate_maintenance_key",
                "approver_sid": approver_sid,
                "code": code,
            }
        )
        if not response.get("rotated"):
            messagebox.showerror(
                "Unable to rotate key",
                self._error_message(response),
                parent=self.root,
            )
            return
        recovery_key = str(
            response.get("maintenance_recovery_key", "")
        )
        if not recovery_key:
            messagebox.showerror(
                "Key rotation failed",
                "The service did not return the new recovery key.",
                parent=self.root,
            )
            return
        self.show_maintenance_recovery_key(recovery_key)
        self.set_status(
            "Maintenance recovery key rotated. Save the new key offline.",
            "warning",
        )
        self.refresh_audit()
        self.refresh_dashboard(quiet=True)
        self.refresh_diagnostics()

    def enable_maintenance(self) -> None:
        if self.maintenance.get("enabled", False):
            return
        if not messagebox.askyesno(
            "Enable maintenance mode",
            "OTP enforcement will be disabled until explicitly restored. Continue?",
            parent=self.root,
        ):
            return
        reason = simpledialog.askstring(
            "Maintenance reason",
            "Enter the reason for enabling maintenance mode:",
            parent=self.root,
        )
        if reason is None or not reason.strip():
            return
        credential = self.ask_admin_credential("Authorize maintenance mode")
        if credential is None:
            return
        recovery_key = self.ask_recovery_key()
        if not recovery_key:
            return
        approver_sid, code = credential
        response = self.api(
            {
                "action": "admin_enable_maintenance",
                "approver_sid": approver_sid,
                "code": code,
                "recovery_key": recovery_key,
                "reason": reason.strip(),
            }
        )
        if not response.get("maintenance_enabled"):
            messagebox.showerror(
                "Unable to enable maintenance",
                self._error_message(response),
                parent=self.root,
            )
            return
        self.set_status("Maintenance mode enabled.", "warning")
        self.refresh_accounts()
        self.refresh_audit()
        self.refresh_dashboard(quiet=True)

    def disable_maintenance(self) -> None:
        if not self.maintenance.get("enabled", False):
            return
        credential = self.ask_admin_credential(
            "Authorize OTP enforcement restoration"
        )
        if credential is None:
            return
        recovery_key = self.ask_recovery_key()
        if not recovery_key:
            return
        approver_sid, code = credential
        response = self.api(
            {
                "action": "admin_disable_maintenance",
                "approver_sid": approver_sid,
                "code": code,
                "recovery_key": recovery_key,
            }
        )
        if not response.get("maintenance_disabled"):
            messagebox.showerror(
                "Unable to restore enforcement",
                self._error_message(response),
                parent=self.root,
            )
            return
        self.set_status("OTP enforcement restored.", "healthy")
        self.refresh_accounts()
        self.refresh_audit()
        self.refresh_dashboard(quiet=True)

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def _build_audit_tab(self) -> None:
        self.audit_tab.columnconfigure(0, weight=1)
        self.audit_tab.rowconfigure(1, weight=1)
        header = ttk.Frame(self.audit_tab)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Audit", style="PageTitle.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(
            header,
            text="Refresh",
            command=self.refresh_audit,
        ).grid(row=0, column=1)

        columns = ("timestamp", "actor", "action", "target", "details")
        self.audit_tree = ttk.Treeview(
            self.audit_tab,
            columns=columns,
            show="headings",
        )
        for column, label, width in (
            ("timestamp", "Timestamp (Local)", 225),
            ("actor", "Actor", 170),
            ("action", "Action", 220),
            ("target", "Target", 190),
            ("details", "Details", 300),
        ):
            self.audit_tree.heading(column, text=label)
            self.audit_tree.column(column, width=width, anchor="w")
        self.audit_tree.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=16,
            pady=(0, 14),
        )

    def refresh_audit(self) -> None:
        response = self.api(
            {"action": "admin_audit", "limit": 300},
            quiet=True,
        )
        if not response.get("ok"):
            return
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)
        for record in response.get("records", []):
            details = record.get("details", {})
            detail_text = ", ".join(
                f"{key}={value}" for key, value in details.items()
            ) if isinstance(details, dict) else str(details)
            self.audit_tree.insert(
                "",
                "end",
                values=(
                    self._format_local_timestamp(
                        record.get("timestamp_utc", "")
                    ),
                    record.get("actor_username", ""),
                    str(record.get("action", "")).replace("_", " ").title(),
                    record.get("target_username", ""),
                    detail_text,
                ),
            )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def _build_diagnostics_tab(self) -> None:
        self.diagnostics_tab.columnconfigure(0, weight=1)
        self.diagnostics_tab.rowconfigure(2, weight=1)
        header = ttk.Frame(self.diagnostics_tab)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header,
            text="Diagnostics",
            style="PageTitle.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(
            header,
            text="Refresh",
            command=self.refresh_diagnostics,
        ).grid(row=0, column=1)

        self.service_details = tk.StringVar(value="Loading service information...")
        ttk.Label(
            self.diagnostics_tab,
            textvariable=self.service_details,
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 10))

        self.diagnostics_tree = ttk.Treeview(
            self.diagnostics_tab,
            columns=("component", "status", "detail"),
            show="headings",
        )
        for column, label, width in (
            ("component", "Component", 220),
            ("status", "Status", 120),
            ("detail", "Details", 720),
        ):
            self.diagnostics_tree.heading(column, text=label)
            self.diagnostics_tree.column(column, width=width, anchor="w")
        self.diagnostics_tree.grid(
            row=2,
            column=0,
            sticky="nsew",
            padx=16,
            pady=(0, 14),
        )

    def refresh_diagnostics(self) -> None:
        response = self.api(
            {"action": "admin_diagnostics"},
            quiet=True,
        )
        if not response.get("ok"):
            self.service_details.set(
                "Diagnostics unavailable: " + self._error_message(response)
            )
            return
        service = dict(response.get("service", {}))
        self.service_details.set(
            f"Version: {service.get('version', 'Unknown')}    "
            f"Status: {service.get('status', 'Unknown')}    "
            f"Startup: {service.get('startup', 'Unknown')}    "
            f"PID: {service.get('pid', 'Unknown')}    "
            f"Uptime: {self._format_duration(service.get('uptime_seconds', 0))}"
        )
        for item in self.diagnostics_tree.get_children():
            self.diagnostics_tree.delete(item)
        for check in response.get("health", []):
            self.diagnostics_tree.insert(
                "",
                "end",
                values=(
                    check.get("label", ""),
                    str(check.get("status", "unknown")).title(),
                    check.get("detail", ""),
                ),
            )
        for key, path in dict(response.get("paths", {})).items():
            self.diagnostics_tree.insert(
                "",
                "end",
                values=(self._friendly_choice(key), "Path", path),
            )

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    AdminConsole().run()
