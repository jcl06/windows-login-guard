from __future__ import annotations

import logging
import os
import sys
import traceback
from pathlib import Path


def log_path() -> Path:
    root = Path(
        os.environ.get(
            "LOCALAPPDATA",
            str(Path.home() / "AppData" / "Local"),
        )
    ) / "WindowsLoginGuardRemoteAdmin"
    root.mkdir(parents=True, exist_ok=True)
    return root / "remote-admin.log"


def show_error(message: str, path: Path) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Windows Login Guard Remote Administration",
            f"{message}\n\nDiagnostic log:\n{path}",
            parent=root,
        )
        root.destroy()
    except Exception:
        pass


def main() -> int:
    path = log_path()
    logging.basicConfig(
        filename=path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )
    logging.info(
        "Starting Remote Administration with Python %s",
        sys.executable,
    )

    try:
        logging.info("Importing Remote Administration UI")
        from remote_admin import RemoteAdminApp

        logging.info("Constructing Remote Administration UI")
        application = RemoteAdminApp()
        logging.info("Entering Remote Administration event loop")
        application.run()
        logging.info("Remote Administration closed normally")
        return 0
    except SystemExit:
        logging.info("Remote Administration was cancelled")
        return 0
    except BaseException as exc:
        logging.exception("Remote Administration startup failed")
        show_error(
            f"Remote Administration could not start:\n{exc}",
            path,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
