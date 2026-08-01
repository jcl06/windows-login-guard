#!/usr/bin/env python3
"""Scan a Windows Login Guard source tree for likely sensitive artifacts."""

from __future__ import annotations

import argparse
import os
import re
import socket
import sys
from pathlib import Path

TEXT_SUFFIXES = {
    ".cmd",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".pyw",
    ".svg",
    ".txt",
    ".xml",
    ".yml",
    ".yaml",
}

BLOCKED_SUFFIXES = {
    ".cer",
    ".crt",
    ".db",
    ".dpapi",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}

BLOCKED_NAMES = {
    "approval-notifier-state.json",
    "launch-config.json",
    "management.db",
    "management-config.json",
    "pending-remote-registration.json",
    "registration.json",
    "remote-admin.json",
    "remote-agent.json",
    "server-config.json",
    "workstation-token.dpapi",
}

CONTENT_PATTERNS = {
    "private key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "Windows user-profile path": re.compile(
        r"(?i)\b[A-Z]:\\Users\\[^\\\r\n\"']+"
    ),
    "private IPv4 address": re.compile(
        r"\b(?:"
        r"10(?:\.\d{1,3}){3}|"
        r"192\.168(?:\.\d{1,3}){2}|"
        r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
        r")\b"
    ),
    "generated Windows computer name": re.compile(
        r"\b(?:DESKTOP|LAPTOP)-[A-Z0-9]{5,}\b"
    ),
    "email address": re.compile(
        r"(?i)\b[A-Z0-9._%+-]+@"
        r"(?!example\.(?:com|org|net)\b)"
        r"[A-Z0-9.-]+\.[A-Z]{2,}\b"
    ),
}


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        yield path


def environment_deny_values() -> set[str]:
    values = {
        os.environ.get("COMPUTERNAME", ""),
        os.environ.get("USERNAME", ""),
        os.environ.get("USERPROFILE", ""),
        socket.gethostname(),
    }
    return {
        value.strip()
        for value in values
        if value and len(value.strip()) >= 4
    }


def readable_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def scan(root: Path, explicit_values: list[str]) -> list[str]:
    findings: list[str] = []
    deny_values = environment_deny_values()
    deny_values.update(
        value.strip()
        for value in explicit_values
        if value and len(value.strip()) >= 4
    )

    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        name = path.name.lower()

        if suffix in BLOCKED_SUFFIXES:
            findings.append(
                f"{relative}: restricted runtime file type {suffix}"
            )
        if name in BLOCKED_NAMES:
            findings.append(
                f"{relative}: restricted runtime filename"
            )

        text = readable_text(path)
        if text is None:
            continue

        for label, pattern in CONTENT_PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    f"{relative}:{line}: possible {label}: "
                    f"{match.group(0)!r}"
                )

        for value in sorted(deny_values, key=len, reverse=True):
            for match in re.finditer(re.escape(value), text, re.IGNORECASE):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    f"{relative}:{line}: contains denied local value "
                    f"{value!r}"
                )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a source/release tree for likely deployment-specific "
            "or secret runtime artifacts."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--deny-value",
        action="append",
        default=[],
        help=(
            "Additional case-insensitive value that must not appear. "
            "May be supplied multiple times."
        ),
    )
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        parser.error(f"not a directory: {root}")

    findings = scan(root, args.deny_value)
    if findings:
        print("Release-safety scan failed:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1

    print(f"Release-safety scan passed: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
