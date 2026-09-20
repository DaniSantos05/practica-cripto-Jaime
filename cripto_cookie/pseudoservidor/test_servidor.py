"""Pruebas reproducibles, positivas y negativas, del protocolo CryptoNotes."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.crypto_utils import (
    GCM_NONCE_BYTES,
    SecurityError,
    canonical_json,
    create_vault,
    decrypt_note,
    encrypt_note,
    envelope_signing_bytes,
    transport_aad,
    unwrap_vault_key,
)
from pseudoservidor.servidor import create_app


class SecureTestSession:
    """Cliente mínimo que permite manipular sobres durante las pruebas."""

    def __init__(self, flask_client: Any, server_key: rsa.RSAPrivateKey):
        self.client = flask_client
        self.server_public_key = server_key.public_key()
        self.client_id = str(uuid.uuid4())
        self.key = AESGCM.generate_key(bit_length=256)
        self.client_sequence = 0
        self.server_sequence = 0
        self._connect()

    def _connect(self) -> None:
        challenge = os.urandom(32)
        encrypted_key = self.server_public_key.encrypt(
            self.key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        response = self.client.post(
            "/connect",
            json={
                "id_cliente": self.client_id,
                "encrypted_session_key": encrypted_key.hex(),
                "challenge": challenge.hex(),
            },
        )
        if response.status_code != 200:
            raise AssertionError(response.get_json())
        payload = self.decrypt_response(response.get_json(), "/connect")
        if payload.get("challenge") != challenge.hex():
            raise AssertionError("El servidor no devolvió el desafío")

    def build_envelope(
        self,
        endpoint: str,
        payload: dict[str, Any],
        key: bytes | None = None,
        advance: bool = True,
    ) -> dict[str, Any]:
        sequence = self.client_sequence + 1
        nonce = os.urandom(GCM_NONCE_BYTES)
        aad = transport_aad("client", self.client_id, endpoint, sequence)
        ciphertext = AESGCM(key or self.key).encrypt(
            nonce, canonical_json(payload), aad
        )
        if advance:
            self.client_sequence = sequence
        return {
            "id_cliente": self.client_id,
            "sequence": sequence,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }

    def decrypt_response(
        self, body: dict[str, Any], endpoint: str, advance: bool = True
    ) -> dict[str, Any]:
        sequence = body["sequence"]
        nonce = bytes.fromhex(body["nonce"])
        ciphertext = bytes.fromhex(body["ciphertext"])
        signature = bytes.fromhex(body["signature"])
        aad = transport_aad("server", self.client_id, endpoint, sequence)
        self.server_public_key.verify(
            signature,
            envelope_signing_bytes(aad, nonce, ciphertext),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        plaintext = AESGCM(self.key).decrypt(nonce, ciphertext, aad)
        payload = json.loads(plaintext.decode("utf-8"))
        if advance:
            if sequence != self.server_sequence + 1:
                raise SecurityError("Respuesta fuera de secuencia")
            self.server_sequence = sequence
        return payload

    def post(
        self, endpoint: str, payload: dict[str, Any]
    ) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        envelope = self.build_envelope(endpoint, payload)
        response = self.client.post(endpoint, json=envelope)
        body = response.get_json()
        decoded = self.decrypt_response(body, endpoint)
        return response, decoded, envelope


class CryptoNotesSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temporary_directory.name)
        app = create_app(
            self.base_path,
            self.server_key,
            b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
        )
        app.config.update(TESTING=True)
        self.flask_client = app.test_client()
        self.secure = SecureTestSession(self.flask_client, self.server_key)
        self.username = f"user_{uuid.uuid4().hex[:10]}"
        self.password = "frase de prueba robusta 2026"
        self.vault_key, self.vault = create_vault(self.password)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def register(self) -> dict[str, Any]:
        response, payload, _ = self.secure.post(
            "/register",
            {
                "usuario": self.username,
                "email": f"{self.username}@example.test",
                "password": self.password,
                "vault": self.vault,
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(payload["status"], "ok")
        return payload

    @staticmethod
    def flip_hex_byte(value: str, byte_index: int = 0) -> str:
        raw = bytearray.fromhex(value)
        raw[byte_index] ^= 0x01
        return raw.hex()

    def test_registration_uses_scrypt_and_does_not_store_password(self) -> None:
        self.register()
        users_text = (self.base_path / "datos" / "usuarios.json").read_text(
            encoding="utf-8"
        )
        users = json.loads(users_text)
        stored = users[self.username]
        self.assertNotIn(self.password, users_text)
        self.assertEqual(stored["password_kdf"]["name"], "scrypt")
        self.assertNotEqual(stored["password_hash"], self.password)

    def test_wrong_password_is_rejected(self) -> None:
        self.register()
        response, payload, _ = self.secure.post("/logout", {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")

        second_session = SecureTestSession(self.flask_client, self.server_key)
        response, payload, _ = second_session.post(
            "/login",
            {"usuario": self.username, "password": "contraseña incorrecta"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(payload["status"], "error")

    def test_note_crud_and_ciphertext_at_rest(self) -> None:
        self.register()
        title = "Plan privado"
        content = "Este texto nunca debe aparecer en usuarios.json"
        encrypted = encrypt_note(
            self.vault_key, self.username, title, content
        )
        response, payload, _ = self.secure.post(
            "/notes/save", {"note": encrypted}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")

        response, payload, _ = self.secure.post("/notes/list", {})
        self.assertEqual(response.status_code, 200)
        clear_note = decrypt_note(self.vault_key, self.username, payload["notes"][0])
        self.assertEqual(clear_note["title"], title)
        self.assertEqual(clear_note["content"], content)

        stored_text = (self.base_path / "datos" / "usuarios.json").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(title, stored_text)
        self.assertNotIn(content, stored_text)

        response, payload, _ = self.secure.post(
            "/notes/delete", {"id": encrypted["id"]}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["deleted"])

    def test_modified_ciphertext_is_rejected_without_consuming_sequence(self) -> None:
        self.register()
        envelope = self.secure.build_envelope("/notes/list", {}, advance=True)
        valid_envelope = dict(envelope)
        envelope["ciphertext"] = self.flip_hex_byte(envelope["ciphertext"], 0)
        response = self.flask_client.post("/notes/list", json=envelope)
        self.assertEqual(response.status_code, 400)

        response = self.flask_client.post("/notes/list", json=valid_envelope)
        self.assertEqual(response.status_code, 200)
        payload = self.secure.decrypt_response(response.get_json(), "/notes/list")
        self.assertEqual(payload["status"], "ok")

    def test_modified_gcm_tag_is_rejected(self) -> None:
        self.register()
        envelope = self.secure.build_envelope("/notes/list", {})
        envelope["ciphertext"] = self.flip_hex_byte(envelope["ciphertext"], -1)
        response = self.flask_client.post("/notes/list", json=envelope)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "error")

    def test_wrong_session_key_is_rejected(self) -> None:
        self.register()
        envelope = self.secure.build_envelope(
            "/notes/list",
            {},
            key=AESGCM.generate_key(bit_length=256),
        )
        response = self.flask_client.post("/notes/list", json=envelope)
        self.assertEqual(response.status_code, 400)

    def test_replayed_message_is_rejected(self) -> None:
        self.register()
        envelope = self.secure.build_envelope("/notes/list", {})
        first = self.flask_client.post("/notes/list", json=envelope)
        self.assertEqual(first.status_code, 200)
        self.secure.decrypt_response(first.get_json(), "/notes/list")
        repeated = self.flask_client.post("/notes/list", json=envelope)
        self.assertEqual(repeated.status_code, 409)
        self.assertIn("repetido", repeated.get_json()["message"].lower())

    def test_modified_signature_is_rejected(self) -> None:
        self.register()
        envelope = self.secure.build_envelope("/notes/list", {})
        response = self.flask_client.post("/notes/list", json=envelope)
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        body["signature"] = self.flip_hex_byte(body["signature"], 0)
        with self.assertRaises(InvalidSignature):
            self.secure.decrypt_response(body, "/notes/list")

    def test_note_tampering_and_wrong_vault_password_are_rejected(self) -> None:
        record = encrypt_note(
            self.vault_key, self.username, "Título", "Contenido"
        )
        record["ciphertext"] = self.flip_hex_byte(record["ciphertext"], 0)
        with self.assertRaises(SecurityError):
            decrypt_note(self.vault_key, self.username, record)
        with self.assertRaises(SecurityError):
            unwrap_vault_key("otra contraseña suficientemente larga", self.vault)

    def test_endpoint_substitution_is_rejected(self) -> None:
        self.register()
        envelope = self.secure.build_envelope("/notes/list", {})
        response = self.flask_client.post("/notes/save", json=envelope)
        self.assertEqual(response.status_code, 400)

    def test_logout_must_be_authenticated(self) -> None:
        self.register()
        plain = self.flask_client.post(
            "/logout", json={"id_cliente": self.secure.client_id}
        )
        self.assertEqual(plain.status_code, 400)
        response, payload, _ = self.secure.post("/logout", {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")

    def test_input_limits_are_enforced(self) -> None:
        self.register()
        with self.assertRaises(ValueError):
            encrypt_note(self.vault_key, self.username, "", "contenido")
        with self.assertRaises(ValueError):
            encrypt_note(self.vault_key, self.username, "x" * 121, "contenido")
        with self.assertRaises(ValueError):
            encrypt_note(self.vault_key, self.username, "título", "x" * 10_001)


if __name__ == "__main__":
    unittest.main(verbosity=2)
