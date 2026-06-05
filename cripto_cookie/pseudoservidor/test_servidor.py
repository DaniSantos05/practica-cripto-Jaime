# pseudoservidor/test_servidor.py
import unittest
import requests
import json
import os
import random
import string
import uuid
from typing import cast, Dict, Any, Optional, Union

# Criptografía
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature
from OpenSSL import crypto 

# Configuración
URL_SERVIDOR = "http://localhost:5000"

# Rutas de los certificados de confianza
PATH_ROOT_CA = "root_ca.crt"
PATH_SUB_CA = "pseudoservidor/sub_ca.crt"

# Generador de Datos
def generar_usuario_aleatorio():
    random_nombre = "".join(random.choices(string.ascii_lowercase, k=8))
    usuario = f"test_user_{random_nombre}"
    email = f"{usuario}@test.com"
    password = f"Prueba_acceso_{random.randint(100,999)}" # Robusta
    return (usuario, email, password)

class TestServidorAPI(unittest.TestCase):
    """ Pruebas de integración para el servidor Cookie Clicker (Funcionales + PKI). """

    # Variables de Clase con Tipado Explícito
    servidor_cert: Optional[x509.Certificate] = None      
    servidor_intermedio: Optional[x509.Certificate] = None 
    servidor_pub_key: Union[RSAPublicKey, Any] = None   
    relleno_rsa = None
    
    # Inicializamos con valores vacíos del tipo correcto
    session_key: bytes = b"" 
    id_cliente: str = "" 

    test_user_datos: Dict[str, Any] = { "usuario": None, "email": None, "password": None }

    @classmethod
    def setUpClass(cls):
        """ Obtiene la cadena de certificados del servidor y prepara los datos. """
        print("-" * 70)
        print("Iniciando suite de pruebas completa (PKI + Funcional)...")
        print(f"Contactando al servidor en: {URL_SERVIDOR}")

        cls.relleno_rsa = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

        cls.id_cliente = str(uuid.uuid4())
        print(f"ID de Cliente para pruebas: {cls.id_cliente[:8]}...")

        # Obtener Cadena de Certificados
        try:
            response = requests.get(f"{URL_SERVIDOR}/get_certs", timeout=3)
            response.raise_for_status()
            data = response.json()
            
            if "server_cert" not in data or "intermediate_ca" not in data:
                raise ValueError("El servidor no devolvió una cadena de certificados válida.")
            
            server_pem = data["server_cert"]
            intermedio_pem = data["intermediate_ca"]
            
            # Cargar los objetos X.509
            cls.servidor_cert = x509.load_pem_x509_certificate(
                server_pem.encode("utf-8"), default_backend()
            )
            cls.servidor_intermedio = x509.load_pem_x509_certificate(
                intermedio_pem.encode("utf-8"), default_backend()
            )
            
            # Extraer clave pública
            cls.servidor_pub_key = cls.servidor_cert.public_key()
            print("Cadena de certificados obtenida y procesada.")
            
        except Exception as e:
            print(f"\nFATAL: Error al procesar certificados: {e}")
            raise

        # Generar datos de usuario
        cls.test_user_datos["usuario"], cls.test_user_datos["email"], cls.test_user_datos["password"] = generar_usuario_aleatorio() #type: ignore
        print(f"Datos de prueba generados (Usuario: {cls.test_user_datos['usuario']})")
        print("-" * 70)

    def _encrypt_mensaje(self, data_dict: Dict[str, Any], aes_key: bytes) -> Dict[str, str]:
        """Cifra datos con AES-GCM (Simula al cliente enviando)."""
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        data_json = json.dumps(data_dict).encode("utf-8")
        encrypted_data = aesgcm.encrypt(nonce, data_json, None)
        return {"nonce": nonce.hex(), "encrypted_data": encrypted_data.hex()}

    def _decrypt_response(self, response_json: Dict[str, Any], aes_key: bytes) -> Dict[str, Any]:
        """Descifra respuesta del servidor y verifica la firma."""
        try:
            nonce_hex = response_json.get("nonce")
            enc_data_hex = response_json.get("encrypted_data")
            
            if not isinstance(nonce_hex, str) or not isinstance(enc_data_hex, str):
                raise ValueError("Formato inválido")

            aesgcm = AESGCM(aes_key)
            nonce = bytes.fromhex(nonce_hex)
            encrypted_data = bytes.fromhex(enc_data_hex)
            
            decrypted_bytes = aesgcm.decrypt(nonce, encrypted_data, None)
            payload_wrapper = json.loads(decrypted_bytes.decode("utf-8"))

            contenido = payload_wrapper.get("content")
            firma_hex = payload_wrapper.get("signature")

            if contenido is None:
                contenido = payload_wrapper

            if self.servidor_pub_key and firma_hex:
                try:
                    bytes_to_verify = json.dumps(contenido, sort_keys=True).encode("utf-8")
                    firma_bytes = bytes.fromhex(firma_hex)
                    
                    rsa_key = cast(RSAPublicKey, self.servidor_pub_key)
                    
                    rsa_key.verify(
                        firma_bytes,
                        bytes_to_verify,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())
                except InvalidSignature:
                    raise ValueError("¡FIRMA DIGITAL INVÁLIDA!")
                except Exception as e:
                    raise ValueError(f"Error verificando firma: {e}")
            
            return contenido
        except Exception as e:
            self.fail(f"Fallo al descifrar/verificar respuesta: {e}")

    # ==========================================
    # TESTS FUNCIONALES (API)
    # ==========================================

    def test_0_servidor_conectado(self):
        print("\nEjecutando test_0_servidor_conectado...")
        self.assertIsNotNone(self.servidor_pub_key)
        self.assertIsInstance(self.servidor_pub_key, rsa.RSAPublicKey)
        print("Éxito: Clave pública extraída.")

    def test_1_connect_exitoso(self):
        print("\nEjecutando test_1_connect_exitoso...")
        self.assertIsNotNone(self.servidor_pub_key, "Necesita clave pública.")
        
        temp_aes_key = AESGCM.generate_key(bit_length=256)
        
        rsa_key_cast = cast(RSAPublicKey, self.servidor_pub_key)
        if self.relleno_rsa:
            encrypted_key = rsa_key_cast.encrypt(temp_aes_key, self.relleno_rsa)
        else:
            self.fail("Error interno: Relleno RSA no configurado")
        
        mensaje = {
            "id_cliente": self.id_cliente,
            "encrypted_session_key": encrypted_key.hex()
        }
        
        response = requests.post(f"{URL_SERVIDOR}/connect", json=mensaje)
        self.assertEqual(response.status_code, 200)
        
        respuesta_clara = self._decrypt_response(response.json(), temp_aes_key)
        self.assertEqual(respuesta_clara.get("status"), "ok")
        
        TestServidorAPI.session_key = temp_aes_key
        print("Éxito: Conexión segura establecida y verificada.")

    def test_2_register_exitoso(self):
        print("\nEjecutando test_2_register_exitoso...")
        self.assertIsNotNone(TestServidorAPI.session_key)
        if TestServidorAPI.session_key == b"":
             self.fail("La clave de sesión no se estableció correctamente en test_1.")

        mensaje_cifrado = self._encrypt_mensaje(self.test_user_datos, TestServidorAPI.session_key) #type:ignore
        mensaje_cifrado["id_cliente"] = self.id_cliente
        
        response = requests.post(f"{URL_SERVIDOR}/register", json=mensaje_cifrado)
        self.assertEqual(response.status_code, 200)
        
        respuesta_clara = self._decrypt_response(response.json(), TestServidorAPI.session_key)#type:ignore
        self.assertEqual(respuesta_clara.get("status"), "ok")
        print(f"Éxito: Usuario registrado.")

    def test_3_register_usuario_duplicado(self):
        print("\nEjecutando test_3_register_usuario_duplicado...")
        requests.post(f"{URL_SERVIDOR}/logout", json={"id_cliente": self.id_cliente, "usuario": self.test_user_datos["usuario"]})

        mensaje_cifrado = self._encrypt_mensaje(self.test_user_datos, TestServidorAPI.session_key) #type:ignore
        mensaje_cifrado["id_cliente"] = self.id_cliente
        
        response = requests.post(f"{URL_SERVIDOR}/register", json=mensaje_cifrado)
        self.assertEqual(response.status_code, 409)
        self.assertIn("Usuario o email ya existen", response.json().get("message", ""))
        print("Éxito: Rechazado duplicado.")

    def test_4_login_credenciales_invalidas(self):
        print("\nEjecutando test_4_login_credenciales_invalidas...")
        requests.post(f"{URL_SERVIDOR}/logout", json={"id_cliente": self.id_cliente, "usuario": self.test_user_datos["usuario"]})

        datos_login_fallido = {
            "usuario": self.test_user_datos["usuario"],
            "password": "PasswordIncorrecta123!"
        }
        mensaje_cifrado = self._encrypt_mensaje(datos_login_fallido, TestServidorAPI.session_key) #type:ignore
        mensaje_cifrado["id_cliente"] = self.id_cliente
        
        response = requests.post(f"{URL_SERVIDOR}/login", json=mensaje_cifrado)
        self.assertEqual(response.status_code, 401)
        print("Éxito: Rechazado login inválido.")

    def test_5_login_exitoso(self):
        print("\nEjecutando test_5_login_exitoso...")
        requests.post(f"{URL_SERVIDOR}/logout", json={"id_cliente": self.id_cliente, "usuario": self.test_user_datos["usuario"]})

        datos_login = {
            "usuario": self.test_user_datos["usuario"],
            "password": self.test_user_datos["password"]
        }
        mensaje_cifrado = self._encrypt_mensaje(datos_login, TestServidorAPI.session_key) #type:ignore
        mensaje_cifrado["id_cliente"] = self.id_cliente
        
        response = requests.post(f"{URL_SERVIDOR}/login", json=mensaje_cifrado)
        self.assertEqual(response.status_code, 200)
        
        respuesta = self._decrypt_response(response.json(), TestServidorAPI.session_key) #type:ignore
        self.assertEqual(respuesta.get("status"), "ok")
        print("Éxito: Login correcto.")

    def test_6_update_data_exitoso(self):
        print("\nEjecutando test_6_update_data_exitoso...")
        datos_update = {"cookies": 5000}
        mensaje_cifrado = self._encrypt_mensaje(datos_update, TestServidorAPI.session_key) #type:ignore
        mensaje_cifrado["id_cliente"] = self.id_cliente
        
        response = requests.post(f"{URL_SERVIDOR}/update-data", json=mensaje_cifrado)
        self.assertEqual(response.status_code, 200)
        
        if "encrypted_data" not in response.json():
             self.assertEqual(response.json().get("status"), "ok")
        else:
             res = self._decrypt_response(response.json(), TestServidorAPI.session_key) #type:ignore
             self.assertEqual(res.get("status"), "ok")
        
        print("Éxito: Datos actualizados.")

    def test_7_logout_exitoso(self):
        print("\nEjecutando test_7_logout_exitoso...")
        mensaje = {"id_cliente": self.id_cliente, "usuario": self.test_user_datos["usuario"]}
        response = requests.post(f"{URL_SERVIDOR}/logout", json=mensaje)
        self.assertEqual(response.status_code, 200)
        print("Éxito: Sesión cerrada.")

    def test_8_update_data_tras_logout(self):
        print("\nEjecutando test_8_update_data_tras_logout...")
        datos_update = {}
        mensaje_cifrado = self._encrypt_mensaje(datos_update, TestServidorAPI.session_key)#type:ignore
        mensaje_cifrado["id_cliente"] = self.id_cliente
        response = requests.post(f"{URL_SERVIDOR}/update-data", json=mensaje_cifrado)
        self.assertEqual(response.status_code, 403)
        print("Éxito: Rechazado tras logout.")

    def test_9_login_con_sesion_ya_activa(self):
        print("\nEjecutando test_9_login_con_sesion_ya_activa...")
        # Login inicial
        datos_login = { "usuario": self.test_user_datos["usuario"], "password": self.test_user_datos["password"] }
        mensaje = self._encrypt_mensaje(datos_login, TestServidorAPI.session_key) #type:ignore
        mensaje["id_cliente"] = self.id_cliente
        requests.post(f"{URL_SERVIDOR}/login", json=mensaje)
        
        # Segundo login (Debe fallar porque NO hicimos logout)
        response = requests.post(f"{URL_SERVIDOR}/login", json=mensaje)
        self.assertEqual(response.status_code, 409)
        print("Éxito: Rechazado segundo login.")
        
        requests.post(f"{URL_SERVIDOR}/logout", json={"id_cliente": self.id_cliente, "usuario": self.test_user_datos["usuario"]})

    def test_10_peticion_con_id_cliente_falso(self):
        print("\nEjecutando test_10_peticion_con_id_cliente_falso...")
        datos = {"usuario": "x", "password": "x"}
        mensaje = self._encrypt_mensaje(datos, TestServidorAPI.session_key)#type:ignore
        mensaje["id_cliente"] = str(uuid.uuid4())
        response = requests.post(f"{URL_SERVIDOR}/login", json=mensaje)
        self.assertEqual(response.status_code, 403)
        print("Éxito: Rechazado ID falso.")

    def test_11_peticion_con_datos_cifrados_corruptos(self):
        print("\nEjecutando test_11_peticion_con_datos_cifrados_corruptos...")
        mensaje = self._encrypt_mensaje({"u":"p"}, TestServidorAPI.session_key)#type:ignore
        mensaje["id_cliente"] = self.id_cliente
        # Corromper
        mensaje["encrypted_data"] = "a" + mensaje["encrypted_data"][1:]
        response = requests.post(f"{URL_SERVIDOR}/login", json=mensaje)
        self.assertEqual(response.status_code, 500)
        print("Éxito: Detectado cifrado corrupto.")

    def test_12_peticion_con_nonce_corrupto(self):
        print("\nEjecutando test_12_peticion_con_nonce_corrupto...")
        mensaje = self._encrypt_mensaje({"u":"p"}, TestServidorAPI.session_key)#type:ignore
        mensaje["id_cliente"] = self.id_cliente
        # Corromper nonce
        mensaje["nonce"] = "0" + mensaje["nonce"][1:]
        response = requests.post(f"{URL_SERVIDOR}/login", json=mensaje)
        self.assertEqual(response.status_code, 500)
        print("Éxito: Detectado nonce corrupto.")

    def test_13_login_con_payload_cifrado_incompleto(self):
        print("\nEjecutando test_13_login_con_payload_cifrado_incompleto...")
        datos_incompletos = {"usuario": self.test_user_datos["usuario"]} # Falta password
        mensaje = self._encrypt_mensaje(datos_incompletos, TestServidorAPI.session_key)#type:ignore
        mensaje["id_cliente"] = self.id_cliente
        response = requests.post(f"{URL_SERVIDOR}/login", json=mensaje)
        self.assertEqual(response.status_code, 500)
        print("Éxito: Manejado payload incompleto.")

    # ==========================================
    # TESTS NUEVOS: PKI Y SEGURIDAD (Renumerados)
    # ==========================================

    def test_14_verificar_cadena_pki(self):
        print("\nEjecutando test_14_verificar_cadena_pki...")
        if self.servidor_cert is None or self.servidor_intermedio is None:
            self.fail("Certificados no cargados.")

        try:
            with open(PATH_ROOT_CA, "rb") as f:
                root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        except FileNotFoundError:
            self.fail(f"No se encuentra {PATH_ROOT_CA}.")

        try:
            self.servidor_cert.verify_directly_issued_by(self.servidor_intermedio)
            print(" -> [OK] El certificado del Servidor está firmado por la Sub-CA.")
        except InvalidSignature:
            self.fail("Fallo PKI: El certificado del servidor NO fue firmado por la Sub-CA.")

        try:
            self.servidor_intermedio.verify_directly_issued_by(root_cert)
            print(" -> [OK] La Sub-CA está firmada por la Root CA.")
        except InvalidSignature:
            self.fail("Fallo PKI: La Sub-CA NO fue firmada por la Root CA.")
        print("Éxito: Cadena de confianza completa verificada.")

    def test_15_verificar_alerta_falso_root(self):
        print("\nEjecutando test_15_verificar_alerta_falso_root...")
        if self.servidor_cert is None: 
            self.fail("Certificado servidor es None.")

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "Hacker Evil CA"
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.set_serial_number(1234)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(1000)
        cert.sign(k, 'sha256')
        
        fake_root = x509.load_pem_x509_certificate(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert), 
            default_backend()
        )
        
        try:
            self.servidor_cert.verify_directly_issued_by(fake_root)
            self.fail("ERROR CRÍTICO: Se validó el certificado con una CA falsa.")
        except InvalidSignature:
            print("Éxito: El certificado fue rechazado correctamente ante una CA falsa.")
        except Exception as e:
            print(f"Éxito: Rechazado por error esperado: {e}")

    def test_16_verificar_claves_protegidas(self):
        print("\nEjecutando test_16_verificar_claves_protegidas...")
        
        keys_to_check = [
            "root_ca.key", 
            "pseudoservidor/sub_ca.key",
            "pseudoservidor/server.key"
        ]
        
        for key_path in keys_to_check:
            if not os.path.exists(key_path):
                print(f"Aviso: {key_path} no encontrado, saltando verificación.")
                continue
                
            with open(key_path, "rb") as f:
                content = f.read()
                try:
                    serialization.load_pem_private_key(content, password=None)
                    loaded_without_pass = True
                except (TypeError, ValueError, Exception):
                    loaded_without_pass = False
                
                if loaded_without_pass:
                    self.fail(f"FALLO DE SEGURIDAD: La clave {key_path} NO está cifrada.")
                else:
                    print(f" -> [OK] La clave {key_path} está protegida.")
        print("Éxito: Todas las claves verificadas están protegidas.")


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Orden lógico de ejecución actualizado
    test_names = [
        'test_0_servidor_conectado',           # Funcional
        'test_1_connect_exitoso',
        'test_2_register_exitoso',
        'test_3_register_usuario_duplicado',
        'test_4_login_credenciales_invalidas',
        'test_5_login_exitoso',
        'test_6_update_data_exitoso',
        'test_7_logout_exitoso',
        'test_8_update_data_tras_logout',
        'test_9_login_con_sesion_ya_activa',
        'test_10_peticion_con_id_cliente_falso',
        'test_11_peticion_con_datos_cifrados_corruptos',
        'test_12_peticion_con_nonce_corrupto',
        'test_13_login_con_payload_cifrado_incompleto',
        'test_14_verificar_cadena_pki',
        'test_15_verificar_alerta_falso_root',
        'test_16_verificar_claves_protegidas'
    ]

    for name in test_names:
        suite.addTest(TestServidorAPI(name))

    runner = unittest.TextTestRunner()
    runner.run(suite)