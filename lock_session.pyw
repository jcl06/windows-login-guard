from __future__ import annotations

import ctypes


def main() -> int:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    lock_workstation = user32.LockWorkStation
    lock_workstation.argtypes = []
    lock_workstation.restype = ctypes.c_bool

    ctypes.set_last_error(0)
    if lock_workstation():
        return 0
    return int(ctypes.get_last_error() or 1)


if __name__ == "__main__":
    raise SystemExit(main())
