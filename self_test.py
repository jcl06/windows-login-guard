from __future__ import annotations

import io
import secrets

import pyotp
import qrcode
import win32serviceutil
import win32ts

from common import protect_machine_secret, unprotect_machine_secret


def main() -> int:
    probe = "wlg-dpapi-" + secrets.token_hex(16)
    protected = protect_machine_secret(probe)

    if not isinstance(protected, bytes) or not protected:
        raise RuntimeError("DPAPI encryption did not return a non-empty bytes object")

    recovered = unprotect_machine_secret(protected)
    if recovered != probe:
        raise RuntimeError("DPAPI round-trip validation failed")

    # Confirm TOTP generation and validation work before enrollment.
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    if not totp.verify(totp.now(), valid_window=0):
        raise RuntimeError("TOTP self-test failed")

    uri = totp.provisioning_uri(
        name="Self Test", issuer_name="Windows Login Guard"
    )
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    if len(buffer.getvalue()) < 100:
        raise RuntimeError("In-memory QR self-test failed")

    print("Pre-enrollment self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
