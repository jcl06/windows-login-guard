from __future__ import annotations

import pyotp
import win32api
import win32con
import win32security

from common import unprotect_machine_secret, user_secret_path


def current_user_sid() -> str:
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    try:
        token_user = win32security.GetTokenInformation(
            token, win32security.TokenUser
        )
        sid_object = token_user[0] if isinstance(token_user, tuple) else token_user
        return win32security.ConvertSidToStringSid(sid_object)
    finally:
        token.Close()


def main() -> int:
    sid = current_user_sid()
    secret_path = user_secret_path(sid)
    if not secret_path.exists():
        print("This Windows account is not enrolled. Use the Login Guard window.")
        return 1
    secret = unprotect_machine_secret(secret_path.read_bytes())
    code = input("Enter this account's current 6-digit OTP: ").strip()
    if pyotp.TOTP(secret).verify(code, valid_window=1):
        print("OTP verified.")
        return 0
    print("Invalid OTP.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
