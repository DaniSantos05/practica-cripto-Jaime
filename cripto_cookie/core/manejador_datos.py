"""Cliente seguro de la API de CryptoNotes."""

from __future__ import annotations

import ipaddress
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, cast

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID

from core.crypto_utils import (
    GCM_NONCE_BYTES,
    SecurityError,
    canonical_json,
    create_vault,
    decode_hex,
    decrypt_note,
    encrypt_note,
    envelope_signing_bytes,
    transport_aad,
    unwrap_vault_key,
)


PROJECT_DIR = Path(__file__).resolve().parents[1]
ROOT_CERT_PATH = PROJECT_DIR / "certificados" / "root_ca.crt"


class ManejadorDatos:
    """Mantiene la sesión, verifica al servidor y cifra las notas localmente."""

    def __init__(self, server_url: str = "http://127.0.0.1:5000"):
        self.server_url = server_url.rstrip("/")
        self.http = requests.Session()
        self.session_key: bytes | None = None
        self.server_certificate: x509.Certificate | None = None
        self.server_public_key: RSAPublicKey | None = None
        self.client_id = ""
        self.client_sequence = 0
        self.server_sequence = 0
        self.username: str | None = None
        self.vault_key: bytes | None = None
        self.last_error = ""

    def _clear_transport(self) -> None:
        self.session_key = None
        self.server_certificate = None
        self.server_public_key = None
        self.client_sequence = 0
        self.server_sequence = 0
        self.client_id = ""

    def _clear_identity(self) -> None:
        self.username = None
        self.vault_key = None

    @staticmethod
    def _check_certificate_dates(certificate: x509.Certificate) -> None:
        now = datetime.now(timezone.utc)
        if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
            raise SecurityError("Hay un certificado caducado o todavía no válido")

    def _obtain_and_verify_certificates(self) -> None:
        if not ROOT_CERT_PATH.exists():
            raise SecurityError(
                "No existe el certificado raíz local; ejecuta generar_pki.py"
            )
        response = self.http.get(f"{self.server_url}/get-certs", timeout=4)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise SecurityError("Respuesta de certificados inválida")

        root = x509.load_pem_x509_certificate(ROOT_CERT_PATH.read_bytes())
        intermediate_pem = data.get("intermediate_ca")
        server_pem = data.get("server_cert")
        if not isinstance(intermediate_pem, str) or not isinstance(server_pem, str):
            raise SecurityError("Cadena de certificados incompleta")
        intermediate = x509.load_pem_x509_certificate(intermediate_pem.encode("ascii"))
        server = x509.load_pem_x509_certificate(server_pem.encode("ascii"))

        for certificate in (root, intermediate, server):
            self._check_certificate_dates(certificate)
        root.verify_directly_issued_by(root)
        intermediate.verify_directly_issued_by(root)
        server.verify_directly_issued_by(intermediate)

        root_constraints = root.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        intermediate_constraints = intermediate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        server_constraints = server.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not root_constraints.ca or not intermediate_constraints.ca or server_constraints.ca:
            raise SecurityError("Restricciones de la cadena PKI inválidas")
        usages = server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in usages:
            raise SecurityError("El certificado no es válido para autenticar servidores")
        san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_addresses = san.get_values_for_type(x509.IPAddress)
        if "localhost" not in dns_names or ipaddress.ip_address("127.0.0.1") not in ip_addresses:
            raise SecurityError("El certificado no identifica al servidor local")

        public_key = server.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
            raise SecurityError("La clave pública RSA del servidor es insuficiente")
        self.server_certificate = server
        self.server_public_key = public_key

    def _establish_secure_connection(self) -> None:
        self._clear_transport()
        self._obtain_and_verify_certificates()
        assert self.server_public_key is not None

        self.client_id = str(uuid.uuid4())
        self.session_key = AESGCM.generate_key(bit_length=256)
        challenge = os.urandom(32)
        encrypted_key = self.server_public_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        response = self.http.post(
            f"{self.server_url}/connect",
            json={
                "id_cliente": self.client_id,
                "encrypted_session_key": encrypted_key.hex(),
                "challenge": challenge.hex(),
            },
            timeout=5,
        )
        response.raise_for_status()
        confirmation = self._decrypt_response(response.json(), "/connect")
        if confirmation.get("status") != "ok" or confirmation.get("challenge") != challenge.hex():
            raise SecurityError("El servidor no confirmó el desafío del handshake")

    def _ensure_connection(self) -> bool:
        if self.session_key is not None:
            return True
        try:
            self._establish_secure_connection()
            self.last_error = ""
            return True
        except Exception as exc:
            self._clear_transport()
            self.last_error = f"No se pudo establecer la conexión segura: {exc}"
            return False

    def _encrypt_request(self, endpoint: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if self.session_key is None:
            raise SecurityError("No existe una clave de sesión")
        self.client_sequence += 1
        aad = transport_aad(
            "client", self.client_id, endpoint, self.client_sequence
        )
        nonce = os.urandom(GCM_NONCE_BYTES)
        ciphertext = AESGCM(self.session_key).encrypt(
            nonce, canonical_json(payload), aad
        )
        return {
            "id_cliente": self.client_id,
            "sequence": self.client_sequence,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }

    def _decrypt_response(
        self, response_json: Mapping[str, Any], endpoint: str
    ) -> dict[str, Any]:
        if self.session_key is None or self.server_public_key is None:
            raise SecurityError("No existe una sesión verificada")
        sequence = response_json.get("sequence")
        if not isinstance(sequence, int) or sequence != self.server_sequence + 1:
            raise SecurityError("Respuesta repetida o fuera de secuencia")
        nonce = decode_hex(response_json.get("nonce"), "nonce", GCM_NONCE_BYTES)
        ciphertext = decode_hex(response_json.get("ciphertext"), "ciphertext")
        signature = decode_hex(response_json.get("signature"), "signature")
        aad = transport_aad("server", self.client_id, endpoint, sequence)
        try:
            self.server_public_key.verify(
                signature,
                envelope_signing_bytes(aad, nonce, ciphertext),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise SecurityError("Firma digital del servidor inválida") from exc
        try:
            plaintext = AESGCM(self.session_key).decrypt(nonce, ciphertext, aad)
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise SecurityError("Respuesta cifrada inválida") from exc
        if not isinstance(payload, dict):
            raise SecurityError("Payload de respuesta inválido")
        self.server_sequence = sequence
        return payload

    def _secure_post(
        self, endpoint: str, payload: Mapping[str, Any]
    ) -> tuple[dict[str, Any] | None, int]:
        if not self._ensure_connection():
            return None, 0
        try:
            envelope = self._encrypt_request(endpoint, payload)
            response = self.http.post(
                f"{self.server_url}{endpoint}", json=envelope, timeout=5
            )
            body = response.json()
            if not isinstance(body, dict):
                raise SecurityError("Respuesta del servidor inválida")
            if {"sequence", "nonce", "ciphertext", "signature"} <= body.keys():
                decoded = self._decrypt_response(body, endpoint)
                if decoded.get("status") == "error":
                    self.last_error = str(decoded.get("message", "Operación rechazada"))
                else:
                    self.last_error = ""
                return decoded, response.status_code
            self.last_error = str(body.get("message", "Petición rechazada"))
            # Tras un error de protocolo no es seguro adivinar qué contador vio
            # el servidor; la siguiente operación negociará otra sesión.
            self._clear_transport()
            self._clear_identity()
            return None, response.status_code
        except Exception as exc:
            self.last_error = f"Fallo de seguridad o conexión: {exc}"
            self._clear_transport()
            self._clear_identity()
            return None, 0

    def _decrypt_note_records(self, records: Any) -> list[dict[str, str]]:
        if self.vault_key is None or self.username is None:
            raise SecurityError("La bóveda no está abierta")
        if not isinstance(records, list):
            raise SecurityError("Lista de notas inválida")
        notes = [decrypt_note(self.vault_key, self.username, record) for record in records]
        notes.sort(key=lambda note: note.get("updated_at", ""), reverse=True)
        return notes

    def registrar_usuario(self, data: dict[str, Any]) -> dict[str, Any] | None:
        password = data.get("password")
        if not isinstance(password, str):
            self.last_error = "Contraseña inválida"
            return None
        try:
            vault_key, vault = create_vault(password)
            payload = dict(data)
            payload["vault"] = vault
            response, status = self._secure_post("/register", payload)
            if response is None or status != 201 or response.get("status") != "ok":
                return None
            username = response.get("usuario")
            if not isinstance(username, str):
                raise SecurityError("El servidor no devolvió un usuario válido")
            self.username = username
            self.vault_key = vault_key
            return {"usuario": username, "notes": []}
        except Exception as exc:
            self.last_error = f"No se pudo crear la bóveda: {exc}"
            self._clear_identity()
            return None

    def validar_login(self, data: dict[str, Any]) -> dict[str, Any] | None:
        password = data.get("password")
        if not isinstance(password, str):
            self.last_error = "Credenciales inválidas"
            return None
        response, status = self._secure_post("/login", data)
        if response is None or status != 200 or response.get("status") != "ok":
            return None
        try:
            username = response.get("usuario")
            vault = response.get("vault")
            if not isinstance(username, str) or not isinstance(vault, dict):
                raise SecurityError("Respuesta de login inválida")
            vault_key = unwrap_vault_key(password, vault)
            self.username = username
            self.vault_key = vault_key
            notes = self._decrypt_note_records(response.get("notes"))
            self.last_error = ""
            return {"usuario": username, "notes": notes}
        except Exception as exc:
            self.last_error = f"No se pudo abrir la bóveda: {exc}"
            self._clear_identity()
            return None

    def listar_notas(self) -> list[dict[str, str]] | None:
        if self.username is None or self.vault_key is None:
            self.last_error = "No hay un usuario autenticado"
            return None
        response, status = self._secure_post("/notes/list", {})
        if response is None or status != 200 or response.get("status") != "ok":
            return None
        try:
            return self._decrypt_note_records(response.get("notes"))
        except SecurityError as exc:
            self.last_error = str(exc)
            return None

    def guardar_nota(
        self, title: str, content: str, note_id: str | None = None
    ) -> list[dict[str, str]] | None:
        if self.username is None or self.vault_key is None:
            self.last_error = "No hay un usuario autenticado"
            return None
        try:
            record = encrypt_note(
                self.vault_key, self.username, title, content, note_id
            )
        except ValueError as exc:
            self.last_error = str(exc)
            return None
        response, status = self._secure_post("/notes/save", {"note": record})
        if response is None or status != 200 or response.get("status") != "ok":
            return None
        return self.listar_notas()

    def eliminar_nota(self, note_id: str) -> list[dict[str, str]] | None:
        if self.username is None:
            self.last_error = "No hay un usuario autenticado"
            return None
        response, status = self._secure_post("/notes/delete", {"id": note_id})
        if response is None or status != 200 or response.get("status") != "ok":
            return None
        return self.listar_notas()

    def logout(self) -> bool:
        if self.username is None:
            self._clear_identity()
            self._clear_transport()
            return True
        response, status = self._secure_post("/logout", {})
        success = response is not None and status == 200 and response.get("status") == "ok"
        self._clear_identity()
        self._clear_transport()
        return success
