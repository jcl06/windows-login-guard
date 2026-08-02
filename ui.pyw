from __future__ import annotations

import argparse
import ctypes
import hashlib
from ctypes import wintypes
import io
from pathlib import Path
import secrets
import socket
import string
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import qrcode
import win32con
import win32event
import win32process
from PIL import ImageTk

from common import HOST, PORT_FILE, recv_json, send_json

ERROR_ALREADY_EXISTS = 183
UOI_NAME = 2
DESKTOP_READOBJECTS = 0x0001
DESKTOP_CREATEWINDOW = 0x0002
DESKTOP_ENUMERATE = 0x0040
DESKTOP_WRITEOBJECTS = 0x0080
DESKTOP_SWITCHDESKTOP = 0x0100
DESKTOP_REQUIRED_ACCESS = (
    DESKTOP_READOBJECTS
    | DESKTOP_CREATEWINDOW
    | DESKTOP_ENUMERATE
    | DESKTOP_WRITEOBJECTS
    | DESKTOP_SWITCHDESKTOP
)
HWND_TOPMOST = -1
SW_RESTORE = 9
SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_SHOWWINDOW = 0x0040
WAIT_OBJECT_0 = 0
EVENT_MODIFY_STATE = 0x0002
EXIT_VERIFIED = 0
EXIT_LOCKED = 10
EXIT_ISOLATION_ERROR = 20

DURATION_LABELS = {
    "once": "This challenge only",
    "until_lock": "Until the next lock",
    "session": "Until sign-out",
    "15_minutes": "15 minutes",
    "30_minutes": "30 minutes",
    "1_hour": "1 hour",
    "2_hours": "2 hours",
    "4_hours": "4 hours",
    "8_hours": "8 hours",
    "24_hours": "24 hours",
}


class OverlayDropdown(tk.Frame):
    """Compact selector with an overlay option panel inside the same window."""

    def __init__(
        self,
        master,
        *,
        values: list[str],
        width: int,
        max_rows: int = 6,
        toggle_callback=None,
    ) -> None:
        super().__init__(master)

        self.values = [str(value) for value in values]
        self.width_chars = max(12, int(width))
        self.max_rows = max(1, int(max_rows))
        self.toggle_callback = toggle_callback
        self.selection_callback = None
        self.expanded = False
        self.selected_index = -1
        self.overlay = None

        self.display_var = tk.StringVar(value="Select an option")
        self.button = tk.Button(
            self,
            textvariable=self.display_var,
            anchor="w",
            width=self.width_chars,
            padx=8,
            pady=5,
            relief="sunken",
            borderwidth=1,
            font=("Segoe UI", 10),
            command=self.toggle,
        )
        self.button.pack(side="left", fill="x", expand=True)

        self.arrow_button = tk.Button(
            self,
            text="▼",
            width=3,
            padx=0,
            pady=5,
            relief="raised",
            borderwidth=1,
            font=("Segoe UI", 9),
            command=self.toggle,
        )
        self.arrow_button.pack(side="right")

        self.button.bind("<Down>", self._open_from_keyboard)
        self.button.bind("<space>", self._open_from_keyboard)
        self.arrow_button.bind("<Down>", self._open_from_keyboard)

    def contains_widget(self, widget) -> bool:
        current = widget
        while current is not None:
            if current is self or current is self.overlay:
                return True
            current = getattr(current, "master", None)
        return False

    def get(self) -> str:
        if self.selected_index < 0:
            return ""
        return self.values[self.selected_index]

    def current(self, index: int) -> None:
        if not self.values:
            return
        bounded = max(0, min(int(index), len(self.values) - 1))
        self._set_selected_index(bounded)

    def set(self, value: str) -> None:
        try:
            index = self.values.index(str(value))
        except ValueError:
            return
        self._set_selected_index(index)

    def bind_selection(self, callback) -> None:
        self.selection_callback = callback

    def toggle(self) -> None:
        if self.expanded:
            self.collapse()
        else:
            self.expand()

    def expand(self) -> None:
        if self.expanded or not self.values:
            return

        if self.selected_index < 0:
            self._set_selected_index(0)

        self.update_idletasks()
        root = self.winfo_toplevel()

        x = self.winfo_rootx() - root.winfo_rootx()
        y = (
            self.winfo_rooty()
            - root.winfo_rooty()
            + self.winfo_height()
        )
        width = max(self.winfo_width(), 220)

        visible_rows = max(
            1,
            min(len(self.values), self.max_rows),
        )
        row_height = 24
        panel_height = visible_rows * row_height + 4

        self.overlay = tk.Frame(
            root,
            borderwidth=1,
            relief="solid",
            background="SystemWindow",
        )

        self.listbox = tk.Listbox(
            self.overlay,
            height=visible_rows,
            exportselection=False,
            selectmode=tk.SINGLE,
            activestyle="dotbox",
            font=("Segoe UI", 10),
            borderwidth=0,
            highlightthickness=0,
        )
        self.scrollbar = tk.Scrollbar(
            self.overlay,
            orient=tk.VERTICAL,
            command=self.listbox.yview,
        )
        self.listbox.configure(
            yscrollcommand=self.scrollbar.set
        )

        self.listbox.grid(row=0, column=0, sticky="nsew")
        if len(self.values) > visible_rows:
            self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.overlay.grid_columnconfigure(0, weight=1)
        self.overlay.grid_rowconfigure(0, weight=1)

        for value in self.values:
            self.listbox.insert(tk.END, value)

        self.listbox.selection_set(self.selected_index)
        self.listbox.activate(self.selected_index)
        self.listbox.see(self.selected_index)

        self.listbox.bind(
            "<<ListboxSelect>>",
            self._select_from_list,
            add="+",
        )
        self.listbox.bind("<Return>", self._accept_keyboard_selection)
        self.listbox.bind("<Escape>", lambda _event: self.collapse())

        # Keep the dropdown inside the visible Login Guard shell.
        root.update_idletasks()
        max_y = max(0, root.winfo_height() - panel_height - 4)
        y = min(y, max_y)

        self.overlay.place(
            x=x,
            y=y,
            width=width,
            height=panel_height,
        )
        self.overlay.lift()

        self.expanded = True
        self.arrow_button.config(text="▲")

        if self.toggle_callback is not None:
            self.toggle_callback(self, True)

        self.listbox.focus_set()

    def collapse(self, *, notify: bool = True) -> None:
        if not self.expanded:
            return

        self.expanded = False
        self.arrow_button.config(text="▼")

        if self.overlay is not None:
            try:
                self.overlay.destroy()
            except tk.TclError:
                pass
            self.overlay = None

        if notify and self.toggle_callback is not None:
            self.toggle_callback(self, False)

    def _set_selected_index(self, index: int) -> None:
        self.selected_index = index
        self.display_var.set(self.values[index])

    def _select_from_list(self, event=None) -> None:
        selected = self.listbox.curselection()
        if not selected:
            return

        self._set_selected_index(int(selected[0]))
        self.collapse()

        if self.selection_callback is not None:
            self.selection_callback(event)

    def _accept_keyboard_selection(self, event=None):
        self._select_from_list(event)
        return "break"

    def _open_from_keyboard(self, _event=None):
        self.expand()
        return "break"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--startup-check", action="store_true")
    parser.add_argument("--session-id", type=int)
    parser.add_argument("--token")
    parser.add_argument("--isolated-child", action="store_true")
    parser.add_argument("--desktop-name", default="default")
    parser.add_argument("--ready-event", default="")
    args = parser.parse_args()
    if not args.startup_check:
        if args.session_id is None:
            parser.error("--session-id is required")
        if not args.token:
            parser.error("--token is required")
    return args


def current_session_id() -> int:
    process_id = ctypes.windll.kernel32.GetCurrentProcessId()
    session_id = ctypes.c_ulong()
    ok = ctypes.windll.kernel32.ProcessIdToSessionId(
        process_id, ctypes.byref(session_id)
    )
    if not ok:
        raise ctypes.WinError()
    return int(session_id.value)


def acquire_single_instance(session_id: int, token: str):
    # Hash the complete role-qualified token. v0.9.1 truncated the token
    # before the "-helper"/"-isolated" suffix, so both processes acquired the
    # same mutex and the isolated child exited immediately with code 0.
    token_tag = hashlib.sha256(token.encode("utf-8")).hexdigest()[:20]
    name = f"Local\\WindowsLoginGuardUI-{session_id}-{token_tag}"
    handle = ctypes.windll.kernel32.CreateMutexW(None, False, name)
    if not handle:
        raise ctypes.WinError()
    if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        ctypes.windll.kernel32.CloseHandle(handle)
        return None
    return handle


USER32 = ctypes.WinDLL("user32", use_last_error=True)

USER32.CreateDesktopW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
]
USER32.CreateDesktopW.restype = wintypes.HANDLE

USER32.OpenDesktopW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
USER32.OpenDesktopW.restype = wintypes.HANDLE

USER32.OpenInputDesktop.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
USER32.OpenInputDesktop.restype = wintypes.HANDLE

USER32.SwitchDesktop.argtypes = [wintypes.HANDLE]
USER32.SwitchDesktop.restype = wintypes.BOOL

USER32.CloseDesktop.argtypes = [wintypes.HANDLE]
USER32.CloseDesktop.restype = wintypes.BOOL

USER32.GetUserObjectInformationW.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
USER32.GetUserObjectInformationW.restype = wintypes.BOOL


def desktop_name_from_handle(desktop_handle) -> str:
    if not desktop_handle:
        return ""
    required = wintypes.DWORD(0)
    USER32.GetUserObjectInformationW(
        desktop_handle,
        UOI_NAME,
        None,
        0,
        ctypes.byref(required),
    )
    if required.value <= 0:
        return ""
    chars = max(1, required.value // ctypes.sizeof(ctypes.c_wchar))
    buffer = ctypes.create_unicode_buffer(chars)
    ok = USER32.GetUserObjectInformationW(
        desktop_handle,
        UOI_NAME,
        buffer,
        ctypes.sizeof(buffer),
        ctypes.byref(required),
    )
    return buffer.value if ok else ""


def input_desktop_name() -> str:
    desktop = USER32.OpenInputDesktop(
        0,
        False,
        DESKTOP_READOBJECTS,
    )
    if not desktop:
        return ""
    try:
        return desktop_name_from_handle(desktop)
    finally:
        USER32.CloseDesktop(desktop)


def desktop_available(expected_name: str) -> bool:
    return (
        input_desktop_name().strip().lower()
        == expected_name.strip().lower()
    )


def user_shell_available() -> bool:
    # During post-update sign-in experiences Windows can expose the default
    # desktop before the ordinary Explorer shell is ready. Starting the
    # isolated approval desktop at that point hides the Windows-owned setup
    # experience and leaves the user looking at a blank screen.
    return bool(USER32.GetShellWindow())


class IsolatedDesktopController:
    """Creates a desktop, launches one Login Guard child, and watches it."""

    def __init__(
        self,
        *,
        session_id: int,
        token: str,
        ui_script: str,
        pythonw_exe: str,
        start_timeout_seconds: int,
    ) -> None:
        self.session_id = session_id
        self.token = token
        self.ui_script = ui_script
        self.pythonw_exe = pythonw_exe
        self.start_timeout_seconds = max(3, int(start_timeout_seconds))
        self.desktop_name = (
            f"WindowsLoginGuard-{session_id}-{secrets.token_hex(6)}"
        )
        self.ready_event_name = (
            f"Local\\WindowsLoginGuardDesktopReady-"
            f"{session_id}-{secrets.token_hex(8)}"
        )
        self.done = threading.Event()
        self.exit_code = EXIT_ISOLATION_ERROR
        self.error = ""
        self.thread = threading.Thread(
            target=self._run,
            name=f"WLG-Isolated-{session_id}",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        desktop_handle = None
        default_handle = None
        process_handle = None
        thread_handle = None
        ready_event_handle = None

        try:
            ready_event_handle = win32event.CreateEvent(
                None,
                True,
                False,
                self.ready_event_name,
            )
            default_handle = USER32.OpenDesktopW(
                "Default",
                0,
                False,
                DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP,
            )
            if not default_handle:
                raise ctypes.WinError(ctypes.get_last_error())

            desktop_handle = USER32.CreateDesktopW(
                self.desktop_name,
                None,
                None,
                0,
                DESKTOP_REQUIRED_ACCESS,
                None,
            )
            if not desktop_handle:
                raise ctypes.WinError(ctypes.get_last_error())

            startup = win32process.STARTUPINFO()
            startup.lpDesktop = rf"winsta0\{self.desktop_name}"
            command_line = subprocess.list2cmdline(
                [
                    self.pythonw_exe,
                    self.ui_script,
                    "--session-id",
                    str(self.session_id),
                    "--token",
                    self.token,
                    "--isolated-child",
                    "--desktop-name",
                    self.desktop_name,
                    "--ready-event",
                    self.ready_event_name,
                ]
            )
            (
                process_handle,
                thread_handle,
                _process_id,
                _thread_id,
            ) = win32process.CreateProcess(
                self.pythonw_exe,
                command_line,
                None,
                None,
                False,
                win32con.CREATE_UNICODE_ENVIRONMENT,
                None,
                str(Path(self.ui_script).resolve().parent),
                startup,
            )
            if thread_handle is not None:
                thread_handle.Close()
                thread_handle = None

            wait_result = win32event.WaitForMultipleObjects(
                [ready_event_handle, process_handle],
                False,
                self.start_timeout_seconds * 1000,
            )
            if wait_result == WAIT_OBJECT_0 + 1:
                child_exit = int(
                    win32process.GetExitCodeProcess(process_handle)
                )
                raise RuntimeError(
                    "Isolated UI child exited before creating its window "
                    f"(exit code {child_exit})."
                )
            if wait_result != WAIT_OBJECT_0:
                raise TimeoutError(
                    "Isolated UI child did not signal window readiness "
                    f"within {self.start_timeout_seconds} seconds."
                )

            if not USER32.SwitchDesktop(desktop_handle):
                raise ctypes.WinError(ctypes.get_last_error())

            win32event.WaitForSingleObject(
                process_handle,
                win32event.INFINITE,
            )
            self.exit_code = int(
                win32process.GetExitCodeProcess(process_handle)
            )
        except Exception as exc:
            self.error = str(exc)
            self.exit_code = EXIT_ISOLATION_ERROR
            if process_handle is not None:
                try:
                    ctypes.windll.kernel32.TerminateProcess(
                        int(process_handle),
                        EXIT_ISOLATION_ERROR,
                    )
                except Exception:
                    pass
        finally:
            try:
                if (
                    default_handle
                    and input_desktop_name().strip().lower()
                    == self.desktop_name.lower()
                ):
                    USER32.SwitchDesktop(default_handle)
            except Exception:
                pass

            for handle in (
                thread_handle,
                process_handle,
                ready_event_handle,
            ):
                if handle is not None:
                    try:
                        handle.Close()
                    except Exception:
                        pass

            for handle in (desktop_handle, default_handle):
                if handle:
                    try:
                        USER32.CloseDesktop(handle)
                    except Exception:
                        pass

            self.done.set()


class GuardWindow:
    def __init__(
        self,
        session_id: int,
        token: str,
        *,
        isolated_child: bool = False,
        desktop_name: str = "default",
        ready_event_name: str = "",
    ) -> None:
        actual_session = current_session_id()
        if actual_session != session_id:
            raise RuntimeError("UI session does not match service launch session")

        self.session_id = session_id
        self.token = token
        self.isolated_child = isolated_child
        self.desktop_name = desktop_name
        self.ready_event_name = ready_event_name
        self.exit_code = EXIT_VERIFIED
        self.isolated_controller: IsolatedDesktopController | None = None
        role_token = token + ("-isolated" if isolated_child else "-helper")
        self.mutex_handle = acquire_single_instance(session_id, role_token)
        if self.mutex_handle is None:
            raise SystemExit(0)

        self.visible = False
        self.current_mode = ""
        self.current_stage = ""
        self.current_key: tuple = ()
        self.current_response: dict = {}
        self.qr_photo = None
        self.local_recovery_codes: list[str] | None = None
        self.approver_map: dict[str, str] = {}
        self.duration_map: dict[str, str] = {}
        self.handled_client_actions: set[str] = set()
        self.auto_submit_job: str | None = None
        self.submit_in_progress = False
        self.preferred_focus_widget: tk.Widget | None = None
        self.focus_retry_jobs: list[str] = []
        self.user_interacted = False
        self.use_topmost_fallback = False
        self.isolated_ready_signaled = False
        self.active_dropdown: OverlayDropdown | None = None
        self.break_glass_active = False
        self.recovery_activity_job: str | None = None

        self.root = tk.Tk()
        self.root.title("Windows Login Guard")
        self.root.attributes("-topmost", True)
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)

        if self.isolated_child:
            self.root.configure(background="#101010")
            self.root.attributes("-fullscreen", True)
            self.root.overrideredirect(True)
            self.shell = tk.Frame(
                self.root,
                background="SystemButtonFace",
                borderwidth=1,
                relief="solid",
            )
            self.shell.place(
                relx=0.5,
                rely=0.5,
                anchor="center",
                width=500,
                height=310,
            )
        else:
            self.root.resizable(False, False)
            self.shell = self.root

        self._set_window_size(500, 310)

        self.header = tk.Label(
            self.shell,
            text="Windows Login Guard",
            font=("Segoe UI", 19, "bold"),
        )
        self.header.pack(pady=(20, 5))

        self.status = tk.Label(
            self.shell,
            text="Connecting to the verification service…",
            font=("Segoe UI", 10),
            wraplength=610,
            justify="center",
        )
        self.status.pack(pady=(0, 8))

        self.content = tk.Frame(self.shell)
        self.content.pack(fill="both", expand=True, padx=26, pady=8)

        self.error = tk.Label(
            self.shell,
            text="",
            font=("Segoe UI", 9),
            wraplength=610,
            justify="center",
        )
        self.error.pack(pady=(4, 14))

        self.root.bind_all(
            "<ButtonPress>",
            self._on_user_interaction,
            add="+",
        )
        self.root.bind_all(
            "<<ComboboxSelected>>",
            self._on_user_interaction,
            add="+",
        )
        self.root.bind_all(
            "<F8>",
            self._open_break_glass_from_key,
            add="+",
        )
        if self.isolated_child:
            self.visible = True
            self.status.config(
                text="Preparing the isolated verification desktop…"
            )
            self.root.deiconify()
            self.root.update_idletasks()
            self.root.update()
            # Do not signal the parent yet. The child must first obtain a
            # complete status response and render the actual verification or
            # approval prompt. Signalling here allowed the parent to switch to
            # an empty isolated desktop while the child was still connecting.
        else:
            self.root.withdraw()

        self.root.after(100, self.poll)

    def _signal_isolated_child_ready(self) -> None:
        if self.isolated_ready_signaled or not self.ready_event_name:
            return
        handle = None
        try:
            handle = win32event.OpenEvent(
                EVENT_MODIFY_STATE,
                False,
                self.ready_event_name,
            )
            win32event.SetEvent(handle)
            self.isolated_ready_signaled = True
        except Exception:
            # A later poll can retry. The parent still has its startup timeout.
            pass
        finally:
            if handle is not None:
                try:
                    handle.Close()
                except Exception:
                    pass

    def service_request(self, payload: dict) -> dict:
        if not PORT_FILE.exists():
            raise ConnectionError("Verification service is not ready")
        port = int(PORT_FILE.read_text(encoding="ascii").strip())
        request = {
            "session_id": self.session_id,
            "token": self.token,
            **payload,
        }
        with socket.create_connection((HOST, port), timeout=4) as sock:
            send_json(sock, request)
            return recv_json(sock)

    def show(self) -> None:
        newly_visible = not self.visible
        if newly_visible:
            self.visible = True
            self.user_interacted = False
            self.root.deiconify()
            always_on_top = bool(
                self.current_response.get("ui_always_on_top", True)
            )
            self.root.attributes("-topmost", always_on_top)
            self.root.lift()
            self._schedule_window_activation()

    def hide(self) -> None:
        if not self.visible:
            return
        self.visible = False
        self._cancel_focus_retries()
        self.root.withdraw()
        self.error.config(text="")

    def _on_user_interaction(self, event=None) -> None:
        self.user_interacted = True
        self._cancel_focus_retries()

        dropdown = self.active_dropdown
        if (
            dropdown is not None
            and event is not None
            and not dropdown.contains_widget(event.widget)
        ):
            dropdown.collapse()

    def _cancel_focus_retries(self) -> None:
        for job in self.focus_retry_jobs:
            try:
                self.root.after_cancel(job)
            except tk.TclError:
                pass
        self.focus_retry_jobs.clear()

    def _schedule_window_activation(self) -> None:
        self._cancel_focus_retries()

        # Activate once after Tk has mapped the window and then retry briefly.
        # The retries handle the short interval after Windows unlock where
        # Explorer or another shell component may still own foreground focus.
        delays = [0]
        retry_count = int(
            self.current_response.get("ui_focus_retry_count", 3)
        )
        retry_ms = int(
            self.current_response.get("ui_focus_retry_ms", 250)
        )
        delays.extend(retry_ms * index for index in range(1, retry_count + 1))

        for delay in delays:
            job = self.root.after(delay, self._activate_and_focus)
            self.focus_retry_jobs.append(job)

    def _activate_and_focus(self) -> None:
        if not self.visible:
            return

        always_on_top = bool(
            self.current_response.get("ui_always_on_top", True)
        )
        force_foreground = bool(
            self.current_response.get("ui_force_foreground", True)
        )

        try:
            self.root.deiconify()
            self.root.lift()
            self.root.attributes("-topmost", always_on_top)
            self.root.update_idletasks()
        except tk.TclError:
            return

        hwnd = int(self.root.winfo_id())
        user32 = ctypes.windll.user32

        try:
            user32.ShowWindow(hwnd, SW_RESTORE)
            if always_on_top:
                user32.SetWindowPos(
                    hwnd,
                    HWND_TOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
                )
            user32.BringWindowToTop(hwnd)
            if force_foreground:
                user32.SetForegroundWindow(hwnd)
                user32.SetActiveWindow(hwnd)
        except Exception:
            # Tk focus still provides a useful fallback if Windows declines
            # foreground activation under its anti-focus-stealing policy.
            pass

        if self.user_interacted:
            return

        widget = self.preferred_focus_widget
        if widget is not None:
            try:
                if widget.winfo_exists() and widget.winfo_viewable():
                    # Do not preserve incidental focus assigned to the root,
                    # shell, or a button while the window is being mapped.
                    # Mouse/keyboard interaction cancels these retries through
                    # self.user_interacted.
                    widget.focus_set()
                    if force_foreground:
                        widget.focus_force()
                    if isinstance(widget, tk.Entry):
                        widget.icursor(tk.END)
            except tk.TclError:
                pass

    def _set_preferred_focus(self, widget: tk.Widget) -> None:
        self.preferred_focus_widget = widget

    def clear_content(self) -> None:
        self._cancel_auto_submit()
        self._cancel_focus_retries()
        if self.active_dropdown is not None:
            self.active_dropdown.collapse(notify=False)
        self.active_dropdown = None
        self.preferred_focus_widget = None
        for child in self.content.winfo_children():
            child.destroy()
        self.error.config(text="")
        self.qr_photo = None

    def _set_window_size(self, width: int, height: int) -> None:
        self.root.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        width = min(int(width), max(420, screen_width - 20))
        height = min(int(height), max(260, screen_height - 40))

        if self.isolated_child:
            self.shell.place_configure(width=width, height=height)
            return

        x = max(0, (screen_width - width) // 2)
        y = max(10, (screen_height - height) // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _dropdown_toggled(
        self,
        dropdown: OverlayDropdown,
        expanded: bool,
    ) -> None:
        if expanded:
            if (
                self.active_dropdown is not None
                and self.active_dropdown is not dropdown
            ):
                self.active_dropdown.collapse(notify=False)
            self.active_dropdown = dropdown
            return

        if self.active_dropdown is dropdown:
            self.active_dropdown = None

    def _apply_window_size(self, mode: str, stage: str = "") -> None:
        compact = bool(
            self.current_response.get("ui_compact_verify_window", True)
        )
        if mode == "verify":
            self._set_window_size(520, 380 if compact else 700)
        elif mode == "break_glass":
            self._set_window_size(640, 500)
        elif mode == "enroll" and stage == "scan":
            self._set_window_size(660, 720)
        elif mode == "enroll":
            self._set_window_size(640, 430)
        elif mode == "approval_wait":
            approval_mode = str(
                self.current_response.get("admin_approval_mode", "inline")
            )
            height = 550 if approval_mode in {"inline", "either"} else 390
            if self.current_response.get("remote_approval_available", False):
                height += 105
            self._set_window_size(680, height)
        elif mode == "approval_console":
            self._set_window_size(680, 550)
        elif mode == "deny":
            self._set_window_size(580, 350)
        elif mode == "client_action":
            self._set_window_size(500, 250)
        else:
            self._set_window_size(500, 310)

    def _cancel_auto_submit(self) -> None:
        if self.auto_submit_job is None:
            return
        try:
            self.root.after_cancel(self.auto_submit_job)
        except tk.TclError:
            pass
        self.auto_submit_job = None

    def _bind_otp_entry(self, entry: tk.Entry, callback) -> None:
        entry.bind("<Return>", lambda _event: callback())
        entry.bind(
            "<KeyRelease>",
            lambda _event: self._schedule_auto_submit(entry, callback),
        )

    def _schedule_auto_submit(self, entry: tk.Entry, callback) -> None:
        self._cancel_auto_submit()
        if not bool(self.current_response.get("ui_auto_submit_otp", True)):
            return
        value = entry.get().strip()
        if not (len(value) == 6 and value.isdigit()):
            return
        delay = int(self.current_response.get("ui_auto_submit_delay_ms", 200))
        self.auto_submit_job = self.root.after(
            delay,
            lambda expected=value: self._auto_submit_if_unchanged(
                entry, callback, expected
            ),
        )

    def _auto_submit_if_unchanged(
        self,
        entry: tk.Entry,
        callback,
        expected: str,
    ) -> None:
        self.auto_submit_job = None
        if self.submit_in_progress:
            return
        if entry.get().strip() != expected:
            return
        callback()

    def _request_submission(self, payload: dict) -> dict | None:
        if self.submit_in_progress:
            return None
        self._cancel_auto_submit()
        self.submit_in_progress = True
        try:
            return self.service_request(payload)
        except Exception as exc:
            self.error.config(text=f"Service error: {exc}")
            return None
        finally:
            self.submit_in_progress = False

    def poll(self) -> None:
        if (
            not self.isolated_child
            and self.isolated_controller is not None
        ):
            if self.isolated_controller.done.is_set():
                self._finish_isolated_controller()
            self.root.after(250, self.poll)
            return

        expected_desktop = (
            self.desktop_name if self.isolated_child else "default"
        )
        desktop_ready = desktop_available(expected_desktop)
        interactive = (
            desktop_ready
            if self.isolated_child
            else desktop_ready and user_shell_available()
        )
        try:
            response = self.service_request(
                {
                    "action": "status",
                    "desktop_available": interactive,
                    "interaction_context": (
                        "isolated"
                        if self.isolated_child
                        else (
                            "isolated_fallback"
                            if self.use_topmost_fallback
                            else "default"
                        )
                    ),
                }
            )
            if response.get("error") == "invalid_session_token":
                self.root.destroy()
                return

            self.current_response = response
            if self._handle_client_action(response):
                self.root.after(1000, self.poll)
                return
            if self.local_recovery_codes is not None:
                self.show()
                self._render_recovery_codes()
            elif (
                self.break_glass_active
                and interactive
                and response.get("required", False)
            ):
                self.show()
                remaining = response.get(
                    "recovery_remaining_seconds"
                )
                if remaining is None:
                    timer_text = ""
                else:
                    timer_text = (
                        f" Recovery remains available for "
                        f"{max(1, int(remaining) // 60)} minute(s)."
                    )
                self.status.config(
                    text=(
                        "The normal OTP countdown is paused while recovery "
                        "is active." + timer_text
                    )
                )
            elif response.get("required", False) and (
                interactive or self.isolated_child
            ):
                if (
                    not self.isolated_child
                    and not self.use_topmost_fallback
                    and response.get("interaction_mode")
                    == "isolated_desktop"
                ):
                    self.hide()
                    self._start_isolated_controller()
                else:
                    self.show()
                    self._render_response(response)
                    if self.isolated_child:
                        # Build and map the complete prompt before the parent
                        # switches the input desktop. This prevents the blank
                        # isolated screen seen by out-of-scope accounts waiting
                        # for administrator approval.
                        self.root.update_idletasks()
                        self.root.update()
                        self._signal_isolated_child_ready()
            else:
                if self.isolated_child:
                    self.exit_code = EXIT_VERIFIED
                    self.root.destroy()
                    return
                self.break_glass_active = False
                self.hide()
                self.current_mode = ""
                self.current_stage = ""
                self.current_key = ()
                self.use_topmost_fallback = False
        except Exception as exc:
            if self.visible:
                self.status.config(text=f"Waiting for service: {exc}")

        self.root.after(1000, self.poll)

    def _start_isolated_controller(self) -> None:
        if self.isolated_controller is not None:
            return
        try:
            self.service_request(
                {
                    "action": "ui_event",
                    "event_name": "isolated_desktop_starting",
                    "message": "Creating and rendering the isolated UI child.",
                }
            )
        except Exception:
            # The child will still attempt to start. Service/UI connectivity is
            # checked again by the child before the desktop is switched.
            pass
        ui_script = str(Path(__file__).resolve())
        pythonw_exe = str(Path(sys.executable).resolve())
        configured_timeout = int(
            self.current_response.get(
                "isolated_desktop_start_timeout_seconds",
                12,
            )
        )
        controller_timeout = max(3, configured_timeout - 3)
        self.isolated_controller = IsolatedDesktopController(
            session_id=self.session_id,
            token=self.token,
            ui_script=ui_script,
            pythonw_exe=pythonw_exe,
            start_timeout_seconds=controller_timeout,
        )
        self.isolated_controller.start()

    def _finish_isolated_controller(self) -> None:
        controller = self.isolated_controller
        self.isolated_controller = None
        self.current_mode = ""
        self.current_stage = ""
        self.current_key = ()

        if controller is None:
            return
        if controller.exit_code in {EXIT_VERIFIED, EXIT_LOCKED}:
            self.use_topmost_fallback = False
            return

        message = (
            controller.error
            or f"isolated child exit code {controller.exit_code}"
        )
        try:
            self.service_request(
                {
                    "action": "ui_event",
                    "event_name": "isolated_desktop_failed",
                    "message": message,
                }
            )
        except Exception:
            pass

        fallback = str(
            self.current_response.get(
                "isolated_desktop_fallback",
                "topmost",
            )
        )
        if fallback == "topmost":
            self.use_topmost_fallback = True
            self.status.config(
                text=(
                    "Isolated desktop could not start. "
                    "Using the configured topmost fallback."
                )
            )
            return

        try:
            ctypes.windll.user32.LockWorkStation()
        except Exception:
            pass

    def _handle_client_action(self, response: dict) -> bool:
        value = response.get("client_action")
        if not isinstance(value, dict):
            return False
        request_id = str(value.get("request_id", ""))
        action_type = str(value.get("type", ""))
        if not request_id:
            return False
        if request_id in self.handled_client_actions:
            # Keep the window hidden while Windows completes the requested lock
            # or the service applies its configured fallback.
            return True

        self.handled_client_actions.add(request_id)
        self.hide()
        success = False
        error = ""
        try:
            if action_type != "lock":
                raise RuntimeError(f"Unsupported client action: {action_type}")
            success = bool(ctypes.windll.user32.LockWorkStation())
            if not success:
                raise ctypes.WinError()
        except Exception as exc:
            error = str(exc)

        try:
            self.service_request(
                {
                    "action": "client_action_result",
                    "request_id": request_id,
                    "success": success,
                    "error": error,
                }
            )
        except Exception:
            # The service retains a timeout and applies its configured fallback
            # if it does not observe the workstation lock.
            pass

        if not success:
            self.show()
            self.status.config(
                text="Windows could not be locked. Login Guard is applying the configured fallback action."
            )
        elif self.isolated_child:
            self.exit_code = EXIT_LOCKED
            self.root.destroy()
        return success

    def _failure_action_text(self, response: dict) -> str:
        action = str(response.get("failure_action", "logoff"))
        if action == "lock":
            return "workstation lock"
        if action == "allow":
            return "gate dismissal"
        return "Windows logoff"

    def _render_response(self, response: dict) -> None:
        mode = str(response.get("mode", ""))
        stage = str(response.get("enrollment_stage", ""))
        request_ids = tuple(
            int(item.get("session_id", -1))
            for item in response.get("requests", [])
        )
        approver_ids = tuple(
            str(item.get("id", ""))
            for item in response.get("approvers", [])
        )
        render_key = (
            mode,
            stage,
            request_ids,
            approver_ids,
            response.get("admin_approval_mode", ""),
            bool(response.get("remote_approval_available", False)),
            bool(response.get("remote_approval_requested", False)),
            bool(
                response.get("remote_approval_return_to_verify", False)
            ),
            response.get("provisioning_uri", ""),
        )
        if render_key != self.current_key:
            self.current_key = render_key
            self.current_mode = mode
            self.current_stage = stage
            self.user_interacted = False
            self._apply_window_size(mode, stage)
            self.clear_content()
            if mode == "verify":
                self._build_verify()
            elif mode == "enroll":
                if stage == "scan":
                    self._build_enrollment_scan(response)
                else:
                    self._build_enrollment_authorize(response)
            elif mode == "approval_wait":
                self._build_approval_wait(response)
            elif mode == "approval_console":
                self._build_approval_console(response)
            elif mode == "deny":
                self._build_deny()
            elif mode == "client_action":
                self._label("Applying Login Guard policy…", size=16, bold=True)

            self._schedule_window_activation()

        remaining = response.get("remaining_seconds")
        if mode == "verify" and remaining is not None:
            self.status.config(
                text=(
                    f"OTP required. Automatic {self._failure_action_text(response)} "
                    f"in {int(remaining)} seconds."
                )
            )
        elif mode == "approval_wait" and remaining is not None:
            self.status.config(
                text=(
                    "Waiting for an enrolled administrator. Automatic "
                    f"{self._failure_action_text(response)} in "
                    f"{int(remaining)} seconds."
                )
            )
        elif mode == "approval_console":
            request_times = [
                int(item.get("remaining_seconds", 0))
                for item in response.get("requests", [])
            ]
            soonest = min(request_times) if request_times else 0
            self.status.config(
                text=(
                    "Pending Login Guard approval requests require your decision. "
                    f"The earliest request expires in {soonest} seconds."
                )
            )
        elif mode == "deny" and remaining is not None:
            self.status.config(
                text=(
                    "This account is denied by policy. Automatic "
                    f"{self._failure_action_text(response)} in "
                    f"{int(remaining)} seconds."
                )
            )
        elif mode == "enroll":
            self.status.config(
                text=(
                    "This account is not enrolled yet. It will not be logged out "
                    "until enrollment is completed and its OTP has been tested."
                )
            )
            if stage == "scan":
                enrollment_remaining = response.get("enrollment_remaining_seconds")
                if enrollment_remaining is not None:
                    self._update_enrollment_timer(int(enrollment_remaining))

    def _label(self, text: str, *, size: int = 10, bold: bool = False) -> tk.Label:
        font = ("Segoe UI", size, "bold" if bold else "normal")
        label = tk.Label(
            self.content,
            text=text,
            font=font,
            wraplength=590,
            justify="center",
        )
        label.pack(pady=7)
        return label

    def _dropdown(
        self,
        *,
        values: list[str],
        width: int,
        max_rows: int = 6,
    ) -> OverlayDropdown:
        dropdown = OverlayDropdown(
            self.content,
            values=values,
            width=width,
            max_rows=max_rows,
            toggle_callback=self._dropdown_toggled,
        )
        dropdown.bind_selection(self._on_user_interaction)
        dropdown.pack(fill="x", padx=20, pady=7)
        return dropdown

    def _entry(self, *, width: int = 24, show: str | None = None) -> tk.Entry:
        entry = tk.Entry(
            self.content,
            font=("Consolas", 16),
            justify="center",
            width=width,
            show=show or "",
        )
        entry.pack(pady=8)
        self._set_preferred_focus(entry)
        return entry

    def _button(self, text: str, command) -> tk.Button:
        button = tk.Button(
            self.content,
            text=text,
            command=command,
            font=("Segoe UI", 11),
            width=24,
        )
        button.pack(pady=9)
        return button

    def _build_verify(self) -> None:
        self._label(
            f"Verify {self.current_response.get('username', 'this account')}",
            size=16,
            bold=True,
        )
        self._label(
            "Enter this account's 6-digit authenticator code or a one-time recovery code."
        )
        self.code_entry = self._entry(width=20)
        self._bind_otp_entry(self.code_entry, self.verify_user)
        self._button("Verify", self.verify_user)

        if self.current_response.get("remote_approval_available", False):
            self._label(
                "Or request approval from a registered administrator."
            )
            self._button(
                "Request Approval",
                self.request_remote_approval,
            )

    def request_remote_approval(self) -> None:
        response = self._request_submission(
            {"action": "request_remote_approval"}
        )
        if response is None:
            return
        if response.get("remote_approval_requested"):
            self.current_key = ()
            self.current_mode = ""
            self.status.config(
                text=(
                    "Remote approval requested. Waiting for a registered "
                    "administrator."
                )
            )
            return
        self._show_error(response)

    def verify_user(self) -> None:
        code = self.code_entry.get().strip()
        if not code:
            return
        response = self._request_submission(
            {"action": "verify_user", "code": code}
        )
        if response is None:
            return
        if response.get("verified"):
            if self.isolated_child:
                self.exit_code = EXIT_VERIFIED
                self.root.destroy()
            else:
                self.hide()
            return
        self._show_error(response)
        self.code_entry.delete(0, tk.END)

    def _open_break_glass_from_key(self, _event=None) -> None:
        if self.break_glass_active:
            return
        if str(self.current_response.get("mode", "")) != "verify":
            return
        if not self.current_response.get("recovery_available", False):
            return
        self.open_break_glass()

    def open_break_glass(self) -> None:
        if self.break_glass_active:
            return
        if str(self.current_response.get("mode", "")) != "verify":
            return

        begin = self._request_submission({"action": "recovery_begin"})
        if begin is None:
            return
        if not begin.get("recovery_active"):
            self._show_error(begin)
            return

        self.break_glass_active = True
        self.current_mode = "break_glass"
        self.current_stage = ""
        self.current_key = ("break_glass",)
        self._apply_window_size("break_glass")
        self.clear_content()
        self.status.config(
            text=(
                "Break-glass recovery requires the offline maintenance "
                "recovery key."
            )
        )
        self._build_break_glass()
        self._schedule_window_activation()

    def _build_break_glass(self) -> None:
        self._label("Account recovery", size=16, bold=True)
        self._label(
            "Normal recovery is hidden until three OTP attempts fail. "
            "Enter the offline machine recovery key to unlock only this "
            "Windows session."
        )
        self._label("Maintenance recovery key:", bold=True)
        self.break_glass_key_entry = self._entry(width=50)

        self._label("Recovery reason:", bold=True)
        self.break_glass_reason_entry = tk.Entry(
            self.content,
            font=("Segoe UI", 11),
            justify="left",
            width=52,
        )
        self.break_glass_reason_entry.pack(pady=8)

        self._label(
            "The key is displayed while entered. The normal OTP timeout is "
            "paused, and active typing extends the recovery window.",
            size=9,
        )

        buttons = tk.Frame(self.content)
        buttons.pack(pady=10)
        tk.Button(
            buttons,
            text="Unlock This Session",
            command=self.submit_break_glass,
            font=("Segoe UI", 11),
            width=20,
        ).pack(side="left", padx=6)
        tk.Button(
            buttons,
            text="Back",
            command=self.cancel_break_glass,
            font=("Segoe UI", 11),
            width=16,
        ).pack(side="left", padx=6)

        self.break_glass_key_entry.bind(
            "<Return>", lambda _event: self.submit_break_glass()
        )
        self.break_glass_key_entry.bind(
            "<KeyRelease>",
            self._on_recovery_input,
        )
        self.break_glass_reason_entry.bind(
            "<Return>", lambda _event: self.submit_break_glass()
        )
        self.break_glass_reason_entry.bind(
            "<KeyRelease>",
            self._schedule_recovery_activity,
        )
        self._set_preferred_focus(self.break_glass_key_entry)

    def _on_recovery_input(self, _event=None) -> None:
        entry = self.break_glass_key_entry
        raw = "".join(
            character
            for character in entry.get().upper()
            if character in string.hexdigits.upper()
        )[:40]
        formatted = "-".join(
            raw[index:index + 8]
            for index in range(0, len(raw), 8)
        )
        if entry.get() != formatted:
            position = len(formatted)
            entry.delete(0, tk.END)
            entry.insert(0, formatted)
            entry.icursor(position)
        self._schedule_recovery_activity()

    def _schedule_recovery_activity(self, _event=None) -> None:
        if self.recovery_activity_job is not None:
            try:
                self.root.after_cancel(self.recovery_activity_job)
            except tk.TclError:
                pass
        self.recovery_activity_job = self.root.after(
            350,
            self._send_recovery_activity,
        )

    def _send_recovery_activity(self) -> None:
        self.recovery_activity_job = None
        if not self.break_glass_active:
            return
        try:
            self.service_request({"action": "recovery_activity"})
        except Exception:
            pass

    def submit_break_glass(self) -> None:
        recovery_key = self.break_glass_key_entry.get().strip()
        reason = self.break_glass_reason_entry.get().strip()
        if not recovery_key:
            self.error.config(text="maintenance recovery key required")
            return
        if not reason:
            self.error.config(text="recovery reason required")
            return

        response = self._request_submission(
            {
                "action": "recovery_unlock_session",
                "recovery_key": recovery_key,
                "reason": reason,
            }
        )
        if response is None:
            return
        if response.get("verified"):
            self.break_glass_active = False
            if self.isolated_child:
                self.exit_code = EXIT_VERIFIED
                self.root.destroy()
            else:
                self.hide()
            return

        self._show_error(response)
        if response.get("error") == "recovery_temporarily_locked":
            retry = int(response.get("retry_after_seconds", 30))
            self.error.config(
                text=f"recovery temporarily locked; retry in {retry} seconds"
            )
        self.break_glass_key_entry.delete(0, tk.END)
        self._set_preferred_focus(self.break_glass_key_entry)

    def cancel_break_glass(self) -> None:
        response = self._request_submission({"action": "recovery_cancel"})
        if response is None:
            return

        self.break_glass_active = False
        if self.recovery_activity_job is not None:
            try:
                self.root.after_cancel(self.recovery_activity_job)
            except tk.TclError:
                pass
            self.recovery_activity_job = None

        # recovery_cancel returns only timer state, not a complete render
        # payload. Fetch a fresh status response before rebuilding the OTP UI.
        try:
            status = self.service_request(
                {
                    "action": "status",
                    "desktop_available": desktop_available(
                        self.desktop_name
                        if self.isolated_child
                        else "default"
                    ),
                    "interaction_context": (
                        "isolated"
                        if self.isolated_child
                        else (
                            "isolated_fallback"
                            if self.use_topmost_fallback
                            else "default"
                        )
                    ),
                }
            )
        except Exception as exc:
            self.error.config(text=f"Service error: {exc}")
            return

        self.current_response = status
        self.current_key = ()
        self.current_mode = ""
        self.current_stage = ""
        self.user_interacted = False
        self._apply_window_size(
            str(status.get("mode", "verify")),
            str(status.get("enrollment_stage", "")),
        )
        self._render_response(status)
        self._schedule_window_activation()

    def _build_enrollment_authorize(self, response: dict) -> None:
        self._label("Enroll this Windows account", size=16, bold=True)
        self._label(
            "Enrollment creates a separate authenticator secret for this Windows account."
        )

        if response.get("initial_enrollment_allowed"):
            self._label(
                "This is the trusted installer account. Begin initial enrollment without an existing OTP."
            )
            self._button("Begin initial enrollment", self.begin_initial_enrollment)
            return

        approvers = list(response.get("approvers", []))
        if not approvers:
            self._label(
                "No enrolled administrator or bootstrap authenticator is available. "
                "This account remains logged in, but enrollment cannot continue.",
                bold=True,
            )
            return

        self._label("Authorize enrollment with an enrolled administrator OTP:")
        labels: list[str] = []
        self.approver_map = {}
        for item in approvers:
            label = str(item.get("label", item.get("id", "")))
            labels.append(label)
            self.approver_map[label] = str(item.get("id", ""))
        self.approver_combo = self._dropdown(
            values=labels,
            width=48,
            max_rows=5,
        )
        if labels:
            self.approver_combo.current(0)
        self.auth_code_entry = self._entry(width=20)
        self._bind_otp_entry(
            self.auth_code_entry, self.authorize_enrollment
        )
        self._button("Authorize enrollment", self.authorize_enrollment)

    def begin_initial_enrollment(self) -> None:
        response = self.service_request(
            {
                "action": "authorize_enrollment",
                "approver_id": "__initial__",
                "code": "",
            }
        )
        if response.get("authorized"):
            self.current_stage = ""
            self.current_mode = ""
            self.current_key = ()
            return
        self._show_error(response)

    def authorize_enrollment(self) -> None:
        label = self.approver_combo.get()
        approver_id = self.approver_map.get(label, "")
        code = self.auth_code_entry.get().strip()
        if not approver_id or not code:
            return
        response = self._request_submission(
            {
                "action": "authorize_enrollment",
                "approver_id": approver_id,
                "code": code,
            }
        )
        if response is None:
            return
        if response.get("authorized"):
            self.current_stage = ""
            self.current_mode = ""
            self.current_key = ()
            return
        self._show_error(response)
        self.auth_code_entry.delete(0, tk.END)

    def _build_enrollment_scan(self, response: dict) -> None:
        self._label("Scan your account-specific QR code", size=16, bold=True)
        self._label(
            "Scan this QR with Microsoft Authenticator, Google Authenticator, Aegis, or another TOTP app."
        )

        uri = str(response.get("provisioning_uri", ""))
        qr_image = qrcode.make(uri).resize((240, 240))
        self.qr_photo = ImageTk.PhotoImage(qr_image)
        qr_label = tk.Label(self.content, image=self.qr_photo)
        qr_label.pack(pady=8)

        self._label("Manual setup key:", bold=True)
        manual = tk.Entry(
            self.content,
            font=("Consolas", 11),
            justify="center",
            width=44,
        )
        manual.insert(0, str(response.get("manual_key", "")))
        manual.config(state="readonly")
        manual.pack(pady=5)

        self.enrollment_timer = self._label("", size=9)
        self._label("Enter the new 6-digit OTP to activate this account:")
        self.new_otp_entry = self._entry(width=20)
        self._bind_otp_entry(
            self.new_otp_entry, self.complete_enrollment
        )
        self._button("Verify and activate", self.complete_enrollment)

    def _update_enrollment_timer(self, seconds: int) -> None:
        if hasattr(self, "enrollment_timer"):
            self.enrollment_timer.config(
                text=f"Enrollment authorization expires in {seconds} seconds."
            )

    def complete_enrollment(self) -> None:
        code = self.new_otp_entry.get().strip()
        if not code:
            return
        response = self._request_submission(
            {"action": "complete_enrollment", "code": code}
        )
        if response is None:
            return
        if response.get("enrolled"):
            self.local_recovery_codes = list(response.get("recovery_codes", []))
            self.current_mode = "recovery"
            self.current_stage = ""
            self._render_recovery_codes()
            return
        self._show_error(response)
        self.new_otp_entry.delete(0, tk.END)

    def _render_recovery_codes(self) -> None:
        if self.current_mode == "recovery-rendered":
            return
        self.current_mode = "recovery-rendered"
        self._set_window_size(560, 560)
        self.clear_content()
        self.status.config(
            text="Enrollment succeeded. Save these recovery codes before continuing."
        )
        self._label("One-time recovery codes", size=16, bold=True)
        self._label(
            "Each code works once. Store them outside this PC. They cannot be displayed again."
        )
        text = tk.Text(
            self.content,
            width=32,
            height=10,
            font=("Consolas", 13),
            wrap="none",
        )
        text.insert("1.0", "\n".join(self.local_recovery_codes or []))
        text.config(state="disabled")
        text.pack(pady=10)

        actions = tk.Frame(self.content)
        actions.pack(pady=7)
        tk.Button(
            actions,
            text="Copy",
            width=14,
            command=self.copy_recovery_codes,
        ).pack(side="left", padx=5)
        tk.Button(
            actions,
            text="Save As...",
            width=14,
            command=self.save_recovery_codes,
        ).pack(side="left", padx=5)
        self._button("Continue", self.finish_recovery_display)

    def copy_recovery_codes(self) -> None:
        value = "\n".join(self.local_recovery_codes or [])
        if not value:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update()
        self.status.config(text="Recovery codes copied to the clipboard.")

    def save_recovery_codes(self) -> None:
        value = "\n".join(self.local_recovery_codes or [])
        if not value:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save Windows Login Guard recovery codes",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="windows-login-guard-recovery-codes.txt",
        )
        if not path:
            return
        try:
            Path(path).write_text(value + "\n", encoding="utf-8")
            self.status.config(text=f"Recovery codes saved to {path}")
        except OSError as exc:
            messagebox.showerror(
                "Save failed", str(exc), parent=self.root
            )

    def finish_recovery_display(self) -> None:
        self.local_recovery_codes = None
        self.current_mode = ""
        self.current_stage = ""
        self.current_key = ()
        if self.isolated_child:
            self.exit_code = EXIT_VERIFIED
            self.root.destroy()
            return
        self.hide()

    def _build_approval_wait(self, response: dict) -> None:
        self._label("Administrator approval required", size=16, bold=True)
        self._label(
            f"Approve access for {response.get('username', 'this account')}."
        )
        remote_available = bool(
            response.get("remote_approval_available", False)
        )
        remote_requested = bool(
            response.get("remote_approval_requested", False)
        )
        if remote_available and remote_requested:
            self._label(
                "Remote approval has been requested. Keep this PC connected "
                "while a registered administrator reviews the request."
            )
            if response.get("remote_approval_return_to_verify", False):
                self._button(
                    "Use my OTP instead",
                    self.cancel_remote_approval,
                )
            else:
                self._button(
                    "Cancel remote request",
                    self.cancel_remote_approval,
                )
        elif remote_available:
            self._label(
                "A registered remote administrator can also approve this "
                "session."
            )
            self._button(
                "Request Approval",
                self.request_remote_approval,
            )

        approval_mode = str(
            response.get("admin_approval_mode", "inline")
        )
        if approval_mode in {"inline", "either"}:
            self._label(
                "An enrolled administrator can approve directly on this screen. "
                "Select the administrator, choose a duration, and have that "
                "administrator enter their own OTP."
            )

            approvers = list(response.get("approvers", []))
            approver_labels = [
                str(item.get("label", item.get("id", "Unknown")))
                for item in approvers
            ]
            self.inline_approver_map = {
                str(item.get("label", item.get("id", "Unknown"))): str(
                    item.get("id", "")
                )
                for item in approvers
            }

            self._label("Approving administrator:", bold=True)
            self.inline_approver_combo = self._dropdown(
                values=approver_labels,
                width=44,
                max_rows=4,
            )
            if approver_labels:
                self.inline_approver_combo.current(0)

            durations = list(response.get("allowed_durations", []))
            duration_labels = [
                DURATION_LABELS.get(item, item) for item in durations
            ]
            self.inline_duration_map = {
                DURATION_LABELS.get(item, item): item for item in durations
            }
            self._label("Approval duration:", bold=True)
            self.inline_duration_combo = self._dropdown(
                values=duration_labels,
                width=32,
                max_rows=5,
            )
            default = str(response.get("default_duration", ""))
            default_label = DURATION_LABELS.get(default, default)
            if default_label in duration_labels:
                self.inline_duration_combo.set(default_label)
            elif duration_labels:
                self.inline_duration_combo.current(0)

            self._label(
                "Administrator OTP or one-time recovery code:",
                bold=True,
            )
            self.inline_approval_code_entry = self._entry(width=20)
            self._bind_otp_entry(
                self.inline_approval_code_entry,
                self.approve_current_session,
            )
            self._button(
                "Approve access",
                self.approve_current_session,
            )

            if approval_mode == "either":
                self._label(
                    "Switching to an administrator session remains available "
                    "as an alternative."
                )
            return

        self._label(
            "Switch to an enrolled administrator account and approve the "
            "pending request from its Login Guard window."
        )

    def cancel_remote_approval(self) -> None:
        response = self._request_submission(
            {"action": "cancel_remote_approval"}
        )
        if response is None:
            return
        if response.get("remote_approval_cancelled"):
            self.current_key = ()
            self.current_mode = ""
            if response.get("returned_to_verify", False):
                message = "Remote approval cancelled. Enter your OTP."
            else:
                message = (
                    "Remote approval request cancelled. Local administrator "
                    "approval remains available."
                )
            self.status.config(text=message)
            return
        self._show_error(response)

    def approve_current_session(self) -> None:
        approver_label = self.inline_approver_combo.get()
        approver_id = self.inline_approver_map.get(approver_label, "")
        duration = self.inline_duration_map.get(
            self.inline_duration_combo.get(), ""
        )
        code = self.inline_approval_code_entry.get().strip()
        if not approver_id or not duration or not code:
            return

        response = self._request_submission(
            {
                "action": "approve_current_session",
                "approver_id": approver_id,
                "duration": duration,
                "code": code,
            }
        )
        if response is None:
            return
        if response.get("approved"):
            self.current_mode = ""
            self.current_stage = ""
            if self.isolated_child:
                self.exit_code = EXIT_VERIFIED
                self.root.destroy()
            else:
                self.hide()
            return

        self._show_error(response)
        self.inline_approval_code_entry.delete(0, tk.END)

    def _build_approval_console(self, response: dict) -> None:
        self._label("Pending access approvals", size=16, bold=True)
        self._label(
            "Select a user, choose the access duration, and enter this administrator account's OTP."
        )

        requests = list(response.get("requests", []))
        request_labels: list[str] = []
        self.request_map: dict[str, int] = {}
        for item in requests:
            label = (
                f"{item.get('username', 'Unknown')} — "
                f"{int(item.get('remaining_seconds', 0))}s remaining"
            )
            request_labels.append(label)
            self.request_map[label] = int(item.get("session_id", -1))

        self._label("Pending request:", bold=True)
        self.request_combo = self._dropdown(
            values=request_labels,
            width=54,
            max_rows=5,
        )
        if request_labels:
            self.request_combo.current(0)

        durations = list(response.get("allowed_durations", []))
        duration_labels = [DURATION_LABELS.get(item, item) for item in durations]
        self.duration_map = {
            DURATION_LABELS.get(item, item): item for item in durations
        }
        self._label("Approval duration:", bold=True)
        self.duration_combo = self._dropdown(
            values=duration_labels,
            width=32,
            max_rows=5,
        )
        default = str(response.get("default_duration", ""))
        default_label = DURATION_LABELS.get(default, default)
        if default_label in duration_labels:
            self.duration_combo.set(default_label)
        elif duration_labels:
            self.duration_combo.current(0)

        self._label("Your administrator OTP or recovery code:", bold=True)
        self.approval_code_entry = self._entry(width=20)
        self._bind_otp_entry(
            self.approval_code_entry, self.approve_session
        )
        self._button("Approve access", self.approve_session)

    def approve_session(self) -> None:
        request_label = self.request_combo.get()
        target_session_id = self.request_map.get(request_label, -1)
        duration = self.duration_map.get(self.duration_combo.get(), "")
        code = self.approval_code_entry.get().strip()
        if target_session_id <= 0 or not duration or not code:
            return
        response = self._request_submission(
            {
                "action": "approve_session",
                "target_session_id": target_session_id,
                "duration": duration,
                "code": code,
            }
        )
        if response is None:
            return
        if response.get("approved"):
            self.current_mode = ""
            self.current_stage = ""
            if self.isolated_child:
                self.exit_code = EXIT_VERIFIED
                self.root.destroy()
            else:
                self.hide()
            return
        self._show_error(response)
        self.approval_code_entry.delete(0, tk.END)

    def _build_deny(self) -> None:
        self._label("Access denied by Login Guard policy", size=16, bold=True)
        self._label(
            "This account is outside the configured protection scope and administrator approval is not available."
        )
        action = self._failure_action_text(self.current_response)
        self._label(f"Login Guard will apply {action} when the countdown expires.")

    def _show_error(self, response: dict) -> None:
        error = str(response.get("error", "request_failed")).replace("_", " ")
        remaining = response.get("remaining_attempts")
        if remaining is not None:
            error += f" ({remaining} attempts remain)"
        self.error.config(text=error)

    def run(self) -> int:
        try:
            self.root.mainloop()
            return self.exit_code
        finally:
            if self.mutex_handle:
                ctypes.windll.kernel32.CloseHandle(self.mutex_handle)


if __name__ == "__main__":
    args = parse_args()

    if args.startup_check:
        check_window = GuardWindow(
            current_session_id(),
            "startup-check-" + secrets.token_urlsafe(24),
        )
        try:
            test_payloads = [
                {
                    "ok": True,
                    "required": True,
                    "mode": "verify",
                    "reason": "startup_check",
                    "remaining_seconds": 45,
                    "remaining_attempts": 5,
                    "recovery_available": False,
                    "requests": [],
                    "approvers": [],
                },
                {
                    "ok": True,
                    "required": True,
                    "mode": "verify",
                    "reason": "startup_check",
                    "remaining_seconds": 45,
                    "remaining_attempts": 2,
                    "recovery_available": True,
                    "requests": [],
                    "approvers": [],
                },
                {
                    "ok": True,
                    "required": True,
                    "mode": "enroll",
                    "enrollment_stage": "authorize",
                    "initial_enrollment_allowed": True,
                    "requests": [],
                    "approvers": [],
                },
            ]
            for payload in test_payloads:
                check_window.current_key = ()
                check_window._render_response(payload)
                check_window.root.update_idletasks()
            print(
                "Windows Login Guard UI startup and rendering validated"
            )
        finally:
            try:
                check_window.root.destroy()
            finally:
                if check_window.mutex_handle:
                    ctypes.windll.kernel32.CloseHandle(
                        check_window.mutex_handle
                    )
                    check_window.mutex_handle = None
        raise SystemExit(0)

    window = GuardWindow(
        args.session_id,
        args.token,
        isolated_child=args.isolated_child,
        desktop_name=args.desktop_name,
        ready_event_name=args.ready_event,
    )
    raise SystemExit(window.run())
