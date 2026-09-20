"""Primitivas compartidas por el cliente y el servidor de CryptoNotes.

Este módulo concentra formatos y parámetros criptográficos para evitar que
cliente, servidor y pruebas implementen versiones incompatibles del protocolo.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


PROTOCOL_VERSION = 1
AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
SALT_BYTES = 16

# Aproximadamente 32 MiB de memoria por derivación. Los parámetros se guardan
# junto a los datos para que la elección sea auditable y migrable.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32

MAX_NOTE_TITLE = 120
MAX_NOTE_CONTENT = 10_000


class SecurityError(ValueError):
    """Indica que una comprobación criptográfica o de formato ha fallado."""


def utc_now_iso() -> str:
    """Devuelve una fecha UTC estable y fácil de serializar."""

    return datetime.now(timezone.utc).isoformat()


def canonical_json(data: Mapping[str, Any]) -> bytes:
    """Serializa un diccionario de forma determinista para cifrar o firmar."""

    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_hex(value: Any, field: str, expected_length: int | None = None) -> bytes:
    """Decodifica hexadecimal aplicando validación estricta."""

    if not isinstance(value, str):
        raise SecurityError(f"{field} debe ser texto hexadecimal")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise SecurityError(f"{field} no contiene hexadecimal válido") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise SecurityError(f"{field} tiene una longitud incorrecta")
    return decoded


def transport_aad(direction: str, client_id: str, endpoint: str, sequence: int) -> bytes:
    """Construye los datos autenticados del protocolo de transporte.

    La dirección, el cliente, el endpoint y el contador quedan ligados al
    ciphertext. Así se impide trasladar un mensaje a otra operación o sesión.
    """

    if direction not in {"client", "server"}:
        raise ValueError("Dirección de protocolo inválida")
    if not isinstance(sequence, int) or sequence < 0:
        raise ValueError("Secuencia de protocolo inválida")
    return canonical_json(
        {
            "version": PROTOCOL_VERSION,
            "direction": direction,
            "client_id": client_id,
            "endpoint": endpoint,
            "sequence": sequence,
        }
    )


def envelope_signing_bytes(aad: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Codifica sin ambigüedad el sobre que firma el servidor."""

    return len(aad).to_bytes(4, "big") + aad + nonce + ciphertext


def _derive_scrypt_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise SecurityError("La contraseña no puede estar vacía")
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def create_vault(password: str) -> tuple[bytes, dict[str, Any]]:
    """Crea una clave aleatoria para las notas y la protege con la contraseña."""

    vault_key = AESGCM.generate_key(bit_length=256)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(GCM_NONCE_BYTES)
    wrapping_key = _derive_scrypt_key(password, salt)
    aad = b"cryptonotes:vault:v1"
    wrapped_key = AESGCM(wrapping_key).encrypt(nonce, vault_key, aad)
    metadata = {
        "version": 1,
        "kdf": {
            "name": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "length": SCRYPT_LENGTH,
        },
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "wrapped_key": wrapped_key.hex(),
    }
    return vault_key, metadata


def unwrap_vault_key(password: str, metadata: Mapping[str, Any]) -> bytes:
    """Recupera la clave de notas; una contraseña o metadata incorrectas fallan."""

    expected_kdf = {
        "name": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "length": SCRYPT_LENGTH,
    }
    if metadata.get("version") != 1 or metadata.get("kdf") != expected_kdf:
        raise SecurityError("Formato o parámetros de la bóveda no soportados")
    salt = decode_hex(metadata.get("salt"), "salt", SALT_BYTES)
    nonce = decode_hex(metadata.get("nonce"), "nonce", GCM_NONCE_BYTES)
    wrapped_key = decode_hex(metadata.get("wrapped_key"), "wrapped_key")
    wrapping_key = _derive_scrypt_key(password, salt)
    try:
        vault_key = AESGCM(wrapping_key).decrypt(
            nonce, wrapped_key, b"cryptonotes:vault:v1"
        )
    except Exception as exc:
        raise SecurityError("No se pudo abrir la bóveda") from exc
    if len(vault_key) != AES_KEY_BYTES:
        raise SecurityError("La clave de la bóveda tiene una longitud inválida")
    return vault_key


def note_aad(username: str, note_id: str) -> bytes:
    """Liga criptográficamente una nota a su propietario e identificador."""

    return canonical_json(
        {
            "version": 1,
            "type": "secure-note",
            "username": username,
            "note_id": note_id,
        }
    )


def encrypt_note(
    vault_key: bytes,
    username: str,
    title: str,
    content: str,
    note_id: str | None = None,
) -> dict[str, str]:
    """Cifra título y contenido para que el servidor solo almacene ciphertext."""

    title = title.strip()
    if not title:
        raise ValueError("La nota necesita un título")
    if len(title) > MAX_NOTE_TITLE:
        raise ValueError(f"El título no puede superar {MAX_NOTE_TITLE} caracteres")
    if len(content) > MAX_NOTE_CONTENT:
        raise ValueError(
            f"El contenido no puede superar {MAX_NOTE_CONTENT} caracteres"
        )
    if note_id is None:
        note_id = str(uuid.uuid4())
    else:
        try:
            uuid.UUID(note_id)
        except (ValueError, TypeError) as exc:
            raise ValueError("Identificador de nota inválido") from exc

    nonce = os.urandom(GCM_NONCE_BYTES)
    plaintext = canonical_json({"title": title, "content": content})
    ciphertext = AESGCM(vault_key).encrypt(
        nonce, plaintext, note_aad(username, note_id)
    )
    return {
        "id": note_id,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }


def decrypt_note(
    vault_key: bytes, username: str, record: Mapping[str, Any]
) -> dict[str, str]:
    """Verifica y descifra una nota; nunca devuelve datos no autenticados."""

    note_id = record.get("id")
    if not isinstance(note_id, str):
        raise SecurityError("La nota no contiene un identificador válido")
    try:
        uuid.UUID(note_id)
    except ValueError as exc:
        raise SecurityError("Identificador de nota inválido") from exc
    nonce = decode_hex(record.get("nonce"), "nonce", GCM_NONCE_BYTES)
    ciphertext = decode_hex(record.get("ciphertext"), "ciphertext")
    try:
        plaintext = AESGCM(vault_key).decrypt(
            nonce, ciphertext, note_aad(username, note_id)
        )
        decoded = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise SecurityError("La nota está dañada o no es auténtica") from exc
    if not isinstance(decoded, dict):
        raise SecurityError("Contenido de nota inválido")
    title = decoded.get("title")
    content = decoded.get("content")
    if not isinstance(title, str) or not isinstance(content, str):
        raise SecurityError("Contenido de nota inválido")
    return {
        "id": note_id,
        "title": title,
        "content": content,
        "updated_at": str(record.get("updated_at", "")),
    }
