from __future__ import annotations


def main() -> int:
    print(
        "Per-user enrollment is performed in the Windows Login Guard window. "
        "Start or restart the service, then sign in or unlock the target account."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
