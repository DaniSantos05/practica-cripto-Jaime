"""API local de CryptoNotes con transporte autenticado y protección anti-replay."""

from __future__ import annotations

import getpass
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request

from core.crypto_utils import (
    AES_KEY_BYTES,
    GCM_NONCE_BYTES,
    canonical_json,
    decode_hex,
    envelope_signing_bytes,
    transport_aad,
)
from pseudoservidor.manejador_datos_servidor import ManejadorDatosServidor

PROJECT_DIR = Path(__file__).resolve().parents[1]
CERT_DIR = PROJECT_DIR / "certificados"
SESSION_TTL_SECONDS = 30 * 60
MAX_ACTIVE_SESSIONS = 1_000


class ProtocolError(ValueError):
    """El formato o la autenticación del sobre de transporte no es válido."""


class ReplayDetected(ProtocolError):
    """Se ha recibido un contador ya procesado."""


def create_app(
    data_base_path: str | os.PathLike[str],
    server_private_key: RSAPrivateKey,
    server_cert_pem: bytes,
    intermediate_cert_pem: bytes,
) -> Flask:
    """Crea la aplicación; la inyección de dependencias facilita pruebas aisladas."""

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
    manager = ManejadorDatosServidor(data_base_path)
    sessions: dict[str, dict[str, Any]] = {}
    app.config["DATA_MANAGER"] = manager
    app.config["SECURE_SESSIONS"] = sessions

    def plain_error(message: str, status: int):
        return jsonify({"status": "error", "message": message}), status

    def secure_response(
        client_id: str, endpoint: str, payload: dict[str, Any], status: int = 200
    ):
        session = sessions[client_id]
        session["server_sequence"] += 1
        sequence = session["server_sequence"]
        aad = transport_aad("server", client_id, endpoint, sequence)
        nonce = os.urandom(GCM_NONCE_BYTES)
        ciphertext = AESGCM(session["key"]).encrypt(nonce, canonical_json(payload), aad)
        signature = server_private_key.sign(
            envelope_signing_bytes(aad, nonce, ciphertext),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        return (
            jsonify(
                {
                    "sequence": sequence,
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex(),
                    "signature": signature.hex(),
                }
            ),
            status,
        )

    def request_json() -> dict[str, Any]:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ProtocolError("Se esperaba un objeto JSON")
        return data

    def decrypt_request(
        data: dict[str, Any], endpoint: str, authenticated: bool = False
    ) -> tuple[str, dict[str, Any]]:
        client_id = data.get("id_cliente")
        if not isinstance(client_id, str) or client_id not in sessions:
            raise ProtocolError("Sesión no válida")
        session = sessions[client_id]
        if time.monotonic() - session["last_activity"] > SESSION_TTL_SECONDS:
            del sessions[client_id]
            raise ProtocolError("Sesión caducada")
        if authenticated and not session.get("usuario"):
            raise ProtocolError("Sesión no autenticada")

        sequence = data.get("sequence")
        if not isinstance(sequence, int) or sequence < 1:
            raise ProtocolError("Secuencia inválida")
        expected = session["client_sequence"] + 1
        if sequence <= session["client_sequence"]:
            raise ReplayDetected("Mensaje repetido")
        if sequence != expected:
            raise ProtocolError("Mensaje fuera de secuencia")

        nonce = decode_hex(data.get("nonce"), "nonce", GCM_NONCE_BYTES)
        ciphertext = decode_hex(data.get("ciphertext"), "ciphertext")
        aad = transport_aad("client", client_id, endpoint, sequence)
        try:
            plaintext = AESGCM(session["key"]).decrypt(nonce, ciphertext, aad)
            payload = json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("Mensaje cifrado inválido") from exc
        if not isinstance(payload, dict):
            raise ProtocolError("Payload inválido")
        session["client_sequence"] = sequence
        session["last_activity"] = time.monotonic()
        return client_id, payload

    def decode_or_error(authenticated: bool = False):
        try:
            data = request_json()
            client_id, payload = decrypt_request(data, request.path, authenticated)
            return client_id, payload, None
        except ReplayDetected:
            return None, None, plain_error("Mensaje repetido rechazado", 409)
        except (ProtocolError, ValueError):
            return None, None, plain_error("Petición segura inválida", 400)

    @app.get("/")
    def index():
        return jsonify(
            {
                "application": "CryptoNotes",
                "status": "ok",
                "protocol": 1,
            }
        )

    @app.get("/get-certs")
    def get_certificates():
        return jsonify(
            {
                "status": "ok",
                "server_cert": server_cert_pem.decode("ascii"),
                "intermediate_ca": intermediate_cert_pem.decode("ascii"),
            }
        )

    @app.post("/connect")
    def connect():
        try:
            now = time.monotonic()
            expired = [
                session_id
                for session_id, session in sessions.items()
                if now - session["last_activity"] > SESSION_TTL_SECONDS
            ]
            for session_id in expired:
                del sessions[session_id]
            if len(sessions) >= MAX_ACTIVE_SESSIONS:
                return plain_error("Demasiadas sesiones activas", 503)
            data = request_json()
            client_id = data.get("id_cliente")
            if not isinstance(client_id, str):
                raise ProtocolError("Identificador inválido")
            uuid.UUID(client_id)
            if client_id in sessions:
                return plain_error("La sesión ya existe", 409)
            encrypted_key = decode_hex(
                data.get("encrypted_session_key"), "encrypted_session_key"
            )
            if len(encrypted_key) != server_private_key.key_size // 8:
                raise ProtocolError("Clave de sesión inválida")
            challenge = decode_hex(data.get("challenge"), "challenge", 32)
            session_key = server_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            if len(session_key) != AES_KEY_BYTES:
                raise ProtocolError("Clave de sesión inválida")
            sessions[client_id] = {
                "key": session_key,
                "usuario": None,
                "client_sequence": 0,
                "server_sequence": 0,
                "last_activity": now,
            }
            return secure_response(
                client_id,
                request.path,
                {"status": "ok", "challenge": challenge.hex()},
            )
        except (ProtocolError, ValueError, TypeError):
            return plain_error("No se pudo establecer la sesión segura", 400)
        except Exception:  # noqa: BLE001 - frontera de una petición no autenticada
            return plain_error("No se pudo establecer la sesión segura", 400)

    @app.post("/register")
    def register():
        client_id, payload, error = decode_or_error()
        if error is not None:
            return error
        assert client_id is not None and payload is not None
        if sessions[client_id]["usuario"] is not None:
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "La sesión ya está autenticada"},
                409,
            )
        try:
            if not manager.registrar_usuario(payload):
                return secure_response(
                    client_id,
                    request.path,
                    {"status": "error", "message": "Usuario o correo ya registrado"},
                    409,
                )
            username = payload["usuario"]
            sessions[client_id]["usuario"] = username
            return secure_response(
                client_id,
                request.path,
                {"status": "ok", "usuario": username, "notes": []},
                201,
            )
        except (ValueError, TypeError) as exc:
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": str(exc)},
                400,
            )
        except Exception:  # noqa: BLE001 - evita filtrar fallos internos al cliente
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "Error interno"},
                500,
            )

    @app.post("/login")
    def login():
        client_id, payload, error = decode_or_error()
        if error is not None:
            return error
        assert client_id is not None and payload is not None
        if sessions[client_id]["usuario"] is not None:
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "La sesión ya está autenticada"},
                409,
            )
        try:
            result = manager.validar_login(payload)
            if result is None:
                return secure_response(
                    client_id,
                    request.path,
                    {"status": "error", "message": "Credenciales inválidas"},
                    401,
                )
            sessions[client_id]["usuario"] = result["usuario"]
            return secure_response(
                client_id,
                request.path,
                {"status": "ok", **result},
            )
        except (ValueError, TypeError):
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "Credenciales inválidas"},
                400,
            )
        except Exception:  # noqa: BLE001 - frontera HTTP con respuesta controlada
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "Error interno"},
                500,
            )

    @app.post("/notes/list")
    def list_notes():
        client_id, _payload, error = decode_or_error(authenticated=True)
        if error is not None:
            return error
        assert client_id is not None
        try:
            records = manager.listar_notas(sessions[client_id]["usuario"])
            return secure_response(
                client_id, request.path, {"status": "ok", "notes": records}
            )
        except Exception:  # noqa: BLE001 - frontera HTTP con respuesta controlada
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "No se pudieron cargar las notas"},
                500,
            )

    @app.post("/notes/save")
    def save_note():
        client_id, payload, error = decode_or_error(authenticated=True)
        if error is not None:
            return error
        assert client_id is not None and payload is not None
        record = payload.get("note")
        if not isinstance(record, dict):
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "Nota inválida"},
                400,
            )
        try:
            stored = manager.guardar_nota(sessions[client_id]["usuario"], record)
            return secure_response(
                client_id,
                request.path,
                {"status": "ok", "note": stored},
            )
        except (ValueError, TypeError) as exc:
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": str(exc)},
                400,
            )
        except Exception:  # noqa: BLE001 - frontera HTTP con respuesta controlada
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "No se pudo guardar la nota"},
                500,
            )

    @app.post("/notes/delete")
    def delete_note():
        client_id, payload, error = decode_or_error(authenticated=True)
        if error is not None:
            return error
        assert client_id is not None and payload is not None
        try:
            deleted = manager.eliminar_nota(
                sessions[client_id]["usuario"], payload.get("id")
            )
            status = 200 if deleted else 404
            message = "ok" if deleted else "error"
            return secure_response(
                client_id,
                request.path,
                {"status": message, "deleted": deleted},
                status,
            )
        except (ValueError, TypeError):
            return secure_response(
                client_id,
                request.path,
                {"status": "error", "message": "Identificador inválido"},
                400,
            )

    @app.post("/logout")
    def logout():
        client_id, _payload, error = decode_or_error(authenticated=True)
        if error is not None:
            return error
        assert client_id is not None
        username = sessions[client_id]["usuario"]
        manager.agregar_log("logout", username)
        response = secure_response(
            client_id, request.path, {"status": "ok", "message": "Sesión cerrada"}
        )
        del sessions[client_id]
        return response

    return app


def load_server_identity() -> tuple[RSAPrivateKey, bytes, bytes]:
    """Carga la identidad sin contener la contraseña en el repositorio."""

    key_path = CERT_DIR / "server.key"
    cert_path = CERT_DIR / "server.crt"
    intermediate_path = CERT_DIR / "sub_ca.crt"
    required = (key_path, cert_path, intermediate_path)
    if any(not path.exists() for path in required):
        raise FileNotFoundError(
            "Faltan certificados. Ejecuta primero: python generar_pki.py"
        )
    password_text = os.environ.get("CRYPTONOTES_SERVER_KEY_PASSWORD")
    if password_text is None:
        password_text = getpass.getpass("Contraseña de la clave del servidor: ")
    if not password_text:
        raise ValueError("La contraseña de la clave no puede estar vacía")
    private_key = serialization.load_pem_private_key(
        key_path.read_bytes(), password=password_text.encode("utf-8")
    )
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("La clave del servidor debe ser RSA")
    return private_key, cert_path.read_bytes(), intermediate_path.read_bytes()


def main() -> None:
    private_key, server_cert, intermediate_cert = load_server_identity()
    app = create_app(
        PROJECT_DIR / "pseudoservidor",
        private_key,
        server_cert,
        intermediate_cert,
    )
    print("CryptoNotes disponible en http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
