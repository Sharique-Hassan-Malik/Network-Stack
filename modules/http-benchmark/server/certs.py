"""
Generate a self-signed TLS certificate and private key for local benchmarking.

Both HTTP/2 (h2 via ALPN) and HTTP/3 (QUIC) require TLS. The generated files
are placed in server/certs/ and reused across runs.
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

CERT_PATH = Path(__file__).parent / "certs" / "cert.pem"
KEY_PATH  = Path(__file__).parent / "certs" / "key.pem"


def generate() -> tuple[Path, Path]:
    """Generate cert and key if they don't already exist. Returns (cert_path, key_path)."""
    CERT_PATH.parent.mkdir(parents=True, exist_ok=True)

    if CERT_PATH.exists() and KEY_PATH.exists():
        return CERT_PATH, KEY_PATH

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "HTTP Perf Analyzer"),
        x509.NameAttribute(NameOID.COMMON_NAME,              "localhost"),
    ])

    now  = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"Generated TLS certificate → {CERT_PATH}")
    return CERT_PATH, KEY_PATH


if __name__ == "__main__":
    generate()
