"""Genera la PKI local de CryptoNotes sin contraseñas incrustadas en código."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certificados"


def _password(environment_name: str, label: str) -> bytes:
    value = os.environ.get(environment_name)
    if value is None:
        value = getpass.getpass(f"Contraseña para {label} (mínimo 12 caracteres): ")
        confirmation = getpass.getpass("Repite la contraseña: ")
        if value != confirmation:
            raise ValueError("Las contraseñas no coinciden")
    if len(value) < 12:
        raise ValueError(f"La contraseña de {label} es demasiado corta")
    return value.encode("utf-8")


def _name(common_name: str, unit: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoNotes"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _write_private_key(path: Path, key: rsa.RSAPrivateKey, password: bytes) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        )
    )
    os.chmod(path, 0o600)


def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    os.chmod(path, 0o644)


def generate_pki(force: bool = False) -> None:
    CERT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = {
        "root_key": CERT_DIR / "root_ca.key",
        "root_cert": CERT_DIR / "root_ca.crt",
        "sub_key": CERT_DIR / "sub_ca.key",
        "sub_cert": CERT_DIR / "sub_ca.crt",
        "server_key": CERT_DIR / "server.key",
        "server_cert": CERT_DIR / "server.crt",
    }
    existing = [path for path in paths.values() if path.exists()]
    if len(existing) == len(paths) and not force:
        print("La PKI ya existe. Usa --force solo si quieres reemplazarla.")
        return
    if existing and not force:
        raise RuntimeError(
            "La PKI está incompleta. Revísala o ejecuta con --force para regenerarla."
        )

    root_password = _password("CRYPTONOTES_ROOT_CA_PASSWORD", "la CA raíz")
    intermediate_password = _password(
        "CRYPTONOTES_SUB_CA_PASSWORD", "la CA intermedia"
    )
    server_password = _password(
        "CRYPTONOTES_SERVER_KEY_PASSWORD", "el servidor"
    )

    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    root_subject = _name("CryptoNotes Root CA", "Autoridad raíz")
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    intermediate_subject = _name("CryptoNotes Intermediate CA", "Autoridad intermedia")
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_subject)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_subject = _name("localhost", "Servidor")
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(intermediate_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediate_key.public_key()
            ),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA256())
    )

    _write_private_key(paths["root_key"], root_key, root_password)
    _write_certificate(paths["root_cert"], root_cert)
    _write_private_key(paths["sub_key"], intermediate_key, intermediate_password)
    _write_certificate(paths["sub_cert"], intermediate_cert)
    _write_private_key(paths["server_key"], server_key, server_password)
    _write_certificate(paths["server_cert"], server_cert)
    print(f"PKI generada en {CERT_DIR}")
    print("Las claves privadas están cifradas y no deben añadirse al repositorio.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera la PKI local de CryptoNotes")
    parser.add_argument(
        "--force", action="store_true", help="reemplaza una PKI existente"
    )
    args = parser.parse_args()
    generate_pki(force=args.force)


if __name__ == "__main__":
    main()
