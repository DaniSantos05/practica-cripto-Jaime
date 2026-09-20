"""Persistencia segura de usuarios, bóvedas cifradas y registros de auditoría."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core.crypto_utils import (
    GCM_NONCE_BYTES,
    SALT_BYTES,
    SCRYPT_LENGTH,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    decode_hex,
    utc_now_iso,
)


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MAX_NOTES_PER_USER = 200
MAX_ENCRYPTED_NOTE_BYTES = 24_000


class ManejadorDatosServidor:
    """Gestiona JSON local sin almacenar títulos ni contenidos en claro."""

    def __init__(self, base_path: str | os.PathLike[str]):
        self.directorio_datos = Path(base_path) / "datos"
        self.archivo_usuarios = self.directorio_datos / "usuarios.json"
        self.archivo_logs = self.directorio_datos / "logs.json"
        self._lock = threading.RLock()

        self.directorio_datos.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._asegurar_archivo(self.archivo_usuarios, {})
        self._asegurar_archivo(self.archivo_logs, [])

        # Reduce la diferencia temporal entre un usuario inexistente y una
        # contraseña incorrecta haciendo que ambos casos ejecuten scrypt.
        self._dummy_salt = os.urandom(SALT_BYTES)
        self._dummy_hash = self._derivar_password(
            "contraseña-ficticia-que-nunca-es-valida", self._dummy_salt
        )

    def _asegurar_archivo(self, path: Path, initial_value: Any) -> None:
        if not path.exists():
            self._guardar_json(path, initial_value)
        else:
            os.chmod(path, 0o600)

    def _cargar_json(self, path: Path, expected_type: type) -> Any:
        with self._lock:
            try:
                with path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
            except (FileNotFoundError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"No se pudo leer {path.name}") from exc
            if not isinstance(data, expected_type):
                raise RuntimeError(f"Formato inválido en {path.name}")
            return data

    def _guardar_json(self, path: Path, data: Any) -> None:
        """Escribe de forma atómica y limita el acceso al propietario."""

        with self._lock:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", dir=self.directorio_datos
            )
            try:
                os.chmod(temporary_name, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                    json.dump(data, file, ensure_ascii=False, indent=2)
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(temporary_name, path)
                os.chmod(path, 0o600)
            finally:
                if os.path.exists(temporary_name):
                    os.unlink(temporary_name)

    @staticmethod
    def _kdf_metadata() -> dict[str, int | str]:
        return {
            "name": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "length": SCRYPT_LENGTH,
        }

    @staticmethod
    def _derivar_password(password: str, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=SCRYPT_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def _verificar_password(password: str, salt: bytes, expected: bytes) -> bool:
        kdf = Scrypt(
            salt=salt,
            length=SCRYPT_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        )
        try:
            kdf.verify(password.encode("utf-8"), expected)
            return True
        except InvalidKey:
            return False

    @staticmethod
    def _validar_registro(data: dict[str, Any]) -> tuple[str, str, str, dict[str, Any]]:
        username = data.get("usuario")
        email = data.get("email")
        password = data.get("password")
        vault = data.get("vault")
        if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
            raise ValueError(
                "El usuario debe tener entre 3 y 32 caracteres alfanuméricos"
            )
        if (
            not isinstance(email, str)
            or len(email) > 254
            or not EMAIL_PATTERN.fullmatch(email)
        ):
            raise ValueError("Correo electrónico inválido")
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            raise ValueError("La contraseña debe tener entre 12 y 128 caracteres")
        if not isinstance(vault, dict):
            raise ValueError("Falta la bóveda cifrada")
        ManejadorDatosServidor._validar_vault(vault)
        return username, email.lower(), password, vault

    @staticmethod
    def _validar_vault(vault: dict[str, Any]) -> None:
        if (
            vault.get("version") != 1
            or vault.get("kdf") != ManejadorDatosServidor._kdf_metadata()
        ):
            raise ValueError("Parámetros de bóveda no soportados")
        decode_hex(vault.get("salt"), "salt", SALT_BYTES)
        decode_hex(vault.get("nonce"), "nonce", GCM_NONCE_BYTES)
        wrapped = decode_hex(vault.get("wrapped_key"), "wrapped_key")
        if len(wrapped) != 32 + 16:  # Clave AES-256 y tag de GCM.
            raise ValueError("Clave de bóveda protegida inválida")

    def agregar_log(self, event: str, username: str | None = None) -> None:
        """Registra metadatos mínimos; nunca contraseñas, claves o notas."""

        with self._lock:
            logs = self._cargar_json(self.archivo_logs, list)
            entry: dict[str, Any] = {"timestamp": utc_now_iso(), "event": event}
            if username:
                entry["usuario"] = username
            logs.append(entry)
            self._guardar_json(self.archivo_logs, logs[-5_000:])

    def registrar_usuario(self, data: dict[str, Any]) -> bool:
        username, email, password, vault = self._validar_registro(data)
        with self._lock:
            users = self._cargar_json(self.archivo_usuarios, dict)
            if username in users or any(
                str(user.get("email", "")).lower() == email
                for user in users.values()
                if isinstance(user, dict)
            ):
                self.agregar_log("registro_rechazado", username)
                return False

            salt = os.urandom(SALT_BYTES)
            password_hash = self._derivar_password(password, salt)
            now = utc_now_iso()
            users[username] = {
                "email": email,
                "password_hash": password_hash.hex(),
                "password_salt": salt.hex(),
                "password_kdf": self._kdf_metadata(),
                "vault": vault,
                "fecha_registro": now,
                "ultimo_login": now,
                "notes": {},
            }
            self._guardar_json(self.archivo_usuarios, users)
            self.agregar_log("registro_exitoso", username)
            return True

    def validar_login(self, data: dict[str, Any]) -> dict[str, Any] | None:
        identifier = data.get("usuario")
        password = data.get("password")
        if not isinstance(identifier, str) or not isinstance(password, str):
            raise ValueError("Credenciales inválidas")
        if len(identifier) > 254 or len(password) > 128:
            raise ValueError("Credenciales inválidas")

        with self._lock:
            users = self._cargar_json(self.archivo_usuarios, dict)
            username: str | None = None
            user: dict[str, Any] | None = None
            if identifier in users and isinstance(users[identifier], dict):
                username, user = identifier, users[identifier]
            else:
                normalized = identifier.lower()
                for candidate, candidate_data in users.items():
                    if (
                        isinstance(candidate_data, dict)
                        and str(candidate_data.get("email", "")).lower() == normalized
                    ):
                        username, user = candidate, candidate_data
                        break

            if user is None or username is None:
                self._verificar_password(password, self._dummy_salt, self._dummy_hash)
                self.agregar_log("login_rechazado")
                return None

            if user.get("password_kdf") != self._kdf_metadata():
                raise RuntimeError("Formato de contraseña no soportado")
            salt = decode_hex(user.get("password_salt"), "password_salt", SALT_BYTES)
            expected = decode_hex(
                user.get("password_hash"), "password_hash", SCRYPT_LENGTH
            )
            if not self._verificar_password(password, salt, expected):
                self.agregar_log("login_rechazado", username)
                return None

            user["ultimo_login"] = utc_now_iso()
            self._guardar_json(self.archivo_usuarios, users)
            self.agregar_log("login_exitoso", username)
            return {
                "usuario": username,
                "vault": user["vault"],
                "notes": list(user.get("notes", {}).values()),
            }

    @staticmethod
    def _validar_nota_cifrada(record: dict[str, Any]) -> tuple[str, str, str]:
        note_id = record.get("id")
        if not isinstance(note_id, str):
            raise ValueError("Identificador de nota inválido")
        try:
            uuid.UUID(note_id)
        except ValueError as exc:
            raise ValueError("Identificador de nota inválido") from exc
        nonce = decode_hex(record.get("nonce"), "nonce", GCM_NONCE_BYTES)
        ciphertext = decode_hex(record.get("ciphertext"), "ciphertext")
        if not 16 <= len(ciphertext) <= MAX_ENCRYPTED_NOTE_BYTES:
            raise ValueError("Tamaño de nota cifrada inválido")
        return note_id, nonce.hex(), ciphertext.hex()

    def listar_notas(self, username: str) -> list[dict[str, Any]]:
        with self._lock:
            users = self._cargar_json(self.archivo_usuarios, dict)
            user = users.get(username)
            if not isinstance(user, dict):
                raise ValueError("Usuario inexistente")
            notes = user.get("notes", {})
            if not isinstance(notes, dict):
                raise RuntimeError("Almacén de notas inválido")
            return sorted(
                (dict(record) for record in notes.values()),
                key=lambda item: str(item.get("updated_at", "")),
                reverse=True,
            )

    def guardar_nota(self, username: str, record: dict[str, Any]) -> dict[str, Any]:
        note_id, nonce, ciphertext = self._validar_nota_cifrada(record)
        with self._lock:
            users = self._cargar_json(self.archivo_usuarios, dict)
            user = users.get(username)
            if not isinstance(user, dict):
                raise ValueError("Usuario inexistente")
            notes = user.setdefault("notes", {})
            if not isinstance(notes, dict):
                raise RuntimeError("Almacén de notas inválido")
            if note_id not in notes and len(notes) >= MAX_NOTES_PER_USER:
                raise ValueError("Se ha alcanzado el máximo de notas")
            now = utc_now_iso()
            stored = {
                "id": note_id,
                "nonce": nonce,
                "ciphertext": ciphertext,
                "updated_at": now,
            }
            notes[note_id] = stored
            self._guardar_json(self.archivo_usuarios, users)
            self.agregar_log("nota_guardada", username)
            return dict(stored)

    def eliminar_nota(self, username: str, note_id: str) -> bool:
        try:
            uuid.UUID(note_id)
        except (ValueError, TypeError) as exc:
            raise ValueError("Identificador de nota inválido") from exc
        with self._lock:
            users = self._cargar_json(self.archivo_usuarios, dict)
            user = users.get(username)
            if not isinstance(user, dict):
                raise ValueError("Usuario inexistente")
            notes = user.get("notes", {})
            if not isinstance(notes, dict) or note_id not in notes:
                return False
            del notes[note_id]
            self._guardar_json(self.archivo_usuarios, users)
            self.agregar_log("nota_eliminada", username)
            return True

    def limpiar_datos(self) -> None:
        """Utilidad explícita para pruebas; no se usa durante la aplicación."""

        self._guardar_json(self.archivo_logs, [])
        self._guardar_json(self.archivo_usuarios, {})
