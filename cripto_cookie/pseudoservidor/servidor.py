# pseudoservidor/servidor.py
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
# Importamos RSAPrivateKey para comprobación de tipos
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os
import json
import sys
from typing import Dict, Any
from manejador_datos_servidor import ManejadorDatosServidor

# Ajustes iniciales
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
app = Flask(__name__)
manejador = ManejadorDatosServidor(SCRIPT_DIR) 

# PATHS HACIA LOS CERTIFICADOS
SERVER_KEY_FILE = os.path.join(SCRIPT_DIR, "server.key")
SERVER_CERT_FILE = os.path.join(SCRIPT_DIR, "server.crt")
SUB_CA_CERT_FILE = os.path.join(SCRIPT_DIR, "sub_ca.crt")

# Variables globales para certificados
servidor_priv_key = None
servidor_cert_pem = b""
sub_ca_cert_pem = b""

# Contraseña de la clave privada de servidor:
# contrasena = input("Introduce la contraseña del servidor:\n").encode("utf-8")
contrasena = b"secreto_de_servidor"

# Comprobar que se ha ejecutado el generar_pki
if not os.path.exists(SERVER_KEY_FILE) or not os.path.exists(SERVER_CERT_FILE) or not os.path.exists(SUB_CA_CERT_FILE):
    print(f"[Servidor] Error crítico, no existe algun certificado de la cadena. Por favor regenerelos")
    sys.exit(1)
print("[Servidor] Cargando cadena de certificados...")

try:
    # Cargar Clave Privada del servidor sabiendo su contraseña
    with open(SERVER_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=contrasena)
        print("[Servidor] OBTENIDA LA CLAVE PRIVADA")
        if isinstance(private_key, RSAPrivateKey):
            servidor_priv_key = private_key
        else:
            raise ValueError("[Servidor] La clave privada no es RSA")
    
    # Cargar Certificado Servidor
    with open(SERVER_CERT_FILE, "rb") as f:
        servidor_cert_pem = f.read()

    # Cargar Certificado Intermedio (Sub-CA)
    with open(SUB_CA_CERT_FILE, "rb") as f:
        sub_ca_cert_pem = f.read()
        
    print("[Servidor] Identidad cargada correctamente.")
except Exception as e:
    print(f"[Servidor] Error cargando archivos: {e}")
    sys.exit(1)

# Diccionario de sesiones
sesiones = {} 

# ======== HELPERS DE CLAVE SIMÉTRICA (AES-GCM) CON FIRMA =========
def encrypt_mensaje(data_dict: Dict[str, Any], aes_key: bytes) -> Dict[str, str]:
    # ENCRYPT-THEN-SIGN: Primero ciframos, luego firmamos el paquete cifrado.
    # Ciframos los datos con la clave simetrica
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    data_json = json.dumps(data_dict).encode("utf-8")
    encrypted_data = aesgcm.encrypt(nonce, data_json, None)

    if servidor_priv_key:
        # Firmar el HASH del paquete cifrado (Nonce + texto cifrado)
        data_to_sign = nonce + encrypted_data
        # sign() calcula el HASH (SHA256) internamente y luego firma dicho hash.
        signature = servidor_priv_key.sign(
            data_to_sign,
            #Usamos un pading pss (estandar para firma)
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        signature_hex = signature.hex()
        # Devolvemos el mensaje cifrado con el nonce y con la firma del hash
        return {"nonce": nonce.hex(), 
            "encrypted_data": encrypted_data.hex(),
            "signature": signature_hex}
    else:
        return {"status":"error","menssage":"Error interno"}

def decrypt_response(response_json: Dict[str, Any], aes_key: bytes) -> Dict[str, Any]:
    try:
        nonce_hex = response_json.get("nonce")
        enc_data_hex = response_json.get("encrypted_data")
        if not isinstance(nonce_hex, str) or not isinstance(enc_data_hex, str):
             raise ValueError("Formato inválido")
         
        #Pasos contrarios al encrypt mensaje:
        aesgcm = AESGCM(aes_key)
        #Hexadecimal -> bytes
        nonce = bytes.fromhex(nonce_hex)
        encrypted_data = bytes.fromhex(enc_data_hex)
        #Desencriptamos
        decrypted_bytes = aesgcm.decrypt(nonce, encrypted_data, None)
        #Bytes -> str
        return json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Fallo al descifrar: {e}")

# ====== COSAS DE API ======
@app.route("/")
def index():
    return "Servidor Seguro Cookie Clicker con PKI Activa"

@app.route("/get_certs", methods=["GET"])
def get_certificate():
    #Devolvemos toda la cadena de certificados
    return jsonify({
        "status": "ok",
        "type": "certificate_chain",
        "server_cert": servidor_cert_pem.decode("utf-8"),
        "intermediate_ca": sub_ca_cert_pem.decode("utf-8")
    })

@app.route("/connect", methods=["POST"])
def connect():
    #Hacemos el handshake
    data = request.get_json()
    if data is None: 
        return jsonify({"status": "error", "message": "JSON vacío"}), 400
    
    #Comprobamos que los datos que nos llegan son los que queremos 
    # (el id y la clave simetrica)
    id_cliente = data.get("id_cliente")
    encrypted_key_hex = data.get("encrypted_session_key")
    
    if not id_cliente or not encrypted_key_hex:
        return jsonify({"status": "error", "message": "Faltan datos"}), 400

    if servidor_priv_key is None:
        return jsonify({"status": "error", "message": "Error interno"}), 500

    try:
        #hex -> bytes
        encrypted_key_bytes = bytes.fromhex(encrypted_key_hex)
        #Usamos un padding OAEP (estandar para cifrado)
        relleno = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        #Desciframos
        session_key = servidor_priv_key.decrypt(encrypted_key_bytes, relleno)
        
        # Guardamos dicha clave simetrica en nuestro diccionario (asociandolo al cliente)
        sesiones[id_cliente] = {"key": session_key, "usuario": None}
        print(f"[Servidor] Handshake completado para: {id_cliente[:8]}...")
        
        #Firmamos y ciframos la respuesta para que no le llegue un falso positivo al usuario
        msg_confirmacion = {"status": "ok", "message": "Conexión exitosa y verificada"}
        return jsonify(encrypt_mensaje(msg_confirmacion, session_key))

    except Exception as e:
        print(f"[Servidor] Error handshake: {e}")
        return jsonify({"status": "error", "message": "Fallo de seguridad"}), 500

@app.route("/login", methods=["POST"])
def login():
    #Tratamos de hacer login
    data = request.get_json()
    if data is None: 
        return jsonify({"status": "error"}), 400

    id_cliente = data.get("id_cliente")
    if id_cliente not in sesiones: 
        return jsonify({"status": "error", "message": "Sesión no válida"}), 403
    
    if sesiones[id_cliente]["usuario"] is not None:
        return jsonify({"status": "error", "message": "Ya hay un usuario logueado en esta sesión."}), 409

    try:
        #Utilizamos la clave asociada para descifrar los datos
        session_key = sesiones[id_cliente]["key"]
        datos_login = decrypt_response(data, session_key)
        #Validamos el login
        if manejador.validar_login(datos_login):
            #añadimos el nombre de usuario al id_cliente para tener mas informacion
            sesiones[id_cliente]["usuario"] = datos_login["usuario"]
            cookies = manejador.obtener_cookies(datos_login["usuario"])
            mejoras = manejador.obtener_mejoras(datos_login["usuario"])
            
            #Ciframos respuesta
            respuesta = {"status": "ok", "usuario": datos_login["usuario"], "cookies": cookies, "mejoras": mejoras}
            return jsonify(encrypt_mensaje(respuesta, session_key))
        else:
            return jsonify({"status": "error", "message": "Credenciales inválidas"}), 401
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/register", methods=["POST"])
def register():
    #Tratamos de hacer registro
    data = request.get_json()
    if data is None: return jsonify({"status": "error"}), 400

    id_cliente = data.get("id_cliente")
    if id_cliente not in sesiones: return jsonify({"status": "error"}), 403

    if sesiones[id_cliente]["usuario"] is not None:
        return jsonify({"status": "error", "message": "Ya hay un usuario logueado en esta sesión."}), 409

    try:
        #Utilizamos la clave asociada para descifrar los datos
        session_key = sesiones[id_cliente]["key"]
        datos_registro = decrypt_response(data, session_key)
        #Validamos el login
        if manejador.registrar_usuario(datos_registro):
            nombre_usuario = datos_registro["usuario"]
            #añadimos el nombre de usuario al id_cliente para tener mas informacion
            sesiones[id_cliente]["usuario"] = nombre_usuario
            respuesta = {"status": "ok", "usuario": nombre_usuario}
            
            #Ciframos respuesta
            return jsonify(encrypt_mensaje(respuesta, session_key))
        else:
            return jsonify({"status": "error", "message": "Usuario o email ya existen"}), 409
    except Exception as e:
        return jsonify({"status": "error"}), 400

@app.route("/update-data", methods=["POST"])
def update_data():
    data = request.get_json()
    if data is None: return jsonify({"status": "error"}), 400

    id_cliente = data.get("id_cliente")
    if id_cliente not in sesiones or sesiones[id_cliente]["usuario"] is None:
        return jsonify({"status": "error", "message": "Sesión no válida o no autenticada"}), 403
    try:
        #Utilizamos la clave asociada para descifrar los datos
        session_key = sesiones[id_cliente]["key"]
        nombre_usuario = sesiones[id_cliente]["usuario"] 
        datos_claros = decrypt_response(data, session_key)
        #Manejamos el update
        if "cookies" in datos_claros:
            manejador.actualizar_cookies(nombre_usuario, datos_claros["cookies"])
        if "mejoras" in datos_claros:
            manejador.guardar_mejoras(nombre_usuario, datos_claros["mejoras"])
        respuesta = {"status": "ok"}     
        #Ciframos respuesta
        return jsonify(encrypt_mensaje(respuesta, session_key))
    except Exception as e:
        return jsonify({"status": "error"}), 500

@app.route("/logout", methods=["POST"])
def logout():
    data = request.get_json()
    if data is None: return jsonify({"status": "error"}), 400

    id_cliente = data.get("id_cliente")
    if id_cliente in sesiones and sesiones[id_cliente]["usuario"] is not None:
        u = sesiones[id_cliente]["usuario"]
        session_key = sesiones[id_cliente]["key"]
        #Quitar al usuario del diccionario 
        #(seguimos guardando su id de conexion por si se registra con un nuevo usuario)
        sesiones[id_cliente]["usuario"] = None
        
        manejador.agregar_log("logout", {"usuario": u})
        respuesta = {"status": "ok"}
        
        #Ciframos respuesta
        return jsonify(encrypt_mensaje(respuesta, session_key))
    return jsonify({"status": "error", "message": "Sesión no válida o no autenticada"}), 403

if __name__ == "__main__":
    print("Iniciando pseudo-servidor...")
    app.run(debug=True, use_reloader=False, port=5000)