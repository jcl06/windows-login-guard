from __future__ import annotations

import argparse
import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def build_certificate(names: list[str], days: int) -> tuple[bytes, bytes]:
    normalized: list[str] = []
    for name in names:
        value = str(name).strip()
        if value and value not in normalized:
            normalized.append(value)
    if not normalized:
        raise ValueError("At least one DNS name or IP address is required")

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject_name = normalized[0]
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]
    )
    san_entries: list[x509.GeneralName] = []
    for value in normalized:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            san_entries.append(x509.DNSName(value))

    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    return certificate_pem, private_key_pem


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a self-signed TLS certificate for WLG remote management"
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--name", action="append", default=[])
    parser.add_argument("--days", type=int, default=1825)
    args = parser.parse_args()
    if not 30 <= args.days <= 3650:
        raise ValueError("--days must be between 30 and 3650")

    names = list(args.name)
    if not names:
        names = [socket.getfqdn(), socket.gethostname(), "localhost", "127.0.0.1"]
    cert_pem, key_pem = build_certificate(names, args.days)
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cert_path = output_dir / "server.crt"
    key_path = output_dir / "server.key"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    if os.name == "nt":
        os.chmod(key_path, 0o600)
    print(f"Certificate: {cert_path}")
    print(f"Private key: {key_path}")
    print("Certificate names:")
    for name in names:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
