import requests
import json
import os
import uuid
from typing import Dict, Any, Optional, cast

# Módulos de criptografía
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature

ROOT_PATH = "root_ca.crt"

class ManejadorDatos:
    def __init__(self):
        self.servidor_url = "http://localhost:5000"
        self.session_key = None
        
        self.servidor_cert = None     
        self.servidor_pub_key = None  
        self.id_cliente = str(uuid.uuid4())

        print(f"[Cliente] Iniciando cliente con ID: {self.id_cliente[:8]}...")
        self._obtener_y_verificar_certificados()
        self._establecer_conexion_segura()

# ======== GESTION DE CERTIFICADOS =========
    def _obtener_y_verificar_certificados(self):
        try:
            response = requests.get(f"{self.servidor_url}/get_certs", timeout=3)
            response.raise_for_status()
            
            data = response.json()
            if data is None: 
                raise ValueError("Respuesta vacía")
            
            with open("root_ca.crt", "rb") as f:
                root_ca = x509.load_pem_x509_certificate(f.read(), default_backend())
            print("[Cliente] CA Raíz de confianza cargada localmente.")
            
            #Cargamos los certificados que nos ha pasado el servidor
            intermediate_pem = data.get("intermediate_ca")
            server_pem = data.get("server_cert")
            if not isinstance(server_pem, str) or not isinstance(intermediate_pem, str):
                raise ValueError("Cadena de certificados inválida.")
            self.servidor_cert = x509.load_pem_x509_certificate(server_pem.encode("utf-8"), default_backend())
            intermediate_cert = x509.load_pem_x509_certificate(intermediate_pem.encode("utf-8"), default_backend())
            
            print(f"[Cliente] Certificados recibidos del servidor.")
            
            # VERIFICACIÓN PKI (de toda la cadena)
            print("[Cliente] Iniciando verificación estricta de la cadena...")
            try:
                self.servidor_cert.verify_directly_issued_by(intermediate_cert)
                print("   [PKI] Servidor verificado por Intermedia.")
                intermediate_cert.verify_directly_issued_by(root_ca)
                print("   [PKI] Intermedia verificada por Raíz.")
                #La raiz no hay que verificarla ya que tenemos acceso a ella
                print("[Cliente] ¡Cadena de confianza COMPLETA y VÁLIDA!")
                self.servidor_pub_key = self.servidor_cert.public_key()
            except InvalidSignature:
                print("[Cliente] PELIGRO: La firma criptográfica de los certificados es INVÁLIDA.")
                self.servidor_pub_key = None
            except Exception as e:
                print(f"[Cliente] Error validando cadena: {e}")
                self.servidor_pub_key = None
        except Exception as e:
            print(f"[Cliente] Error obteniendo certificados: {e}")

# ======== HANDSHAKE =========
    def _establecer_conexion_segura(self):
        if not self.servidor_pub_key:
            print("[Cliente] No hay clave pública verificada. Abortando conexión.")
            return False
        try:
            print("\n[Cliente] --- HANDSHAKE ---")
            print("[Cliente] Generando clave de sesión (AES-256)...")
            self.session_key = AESGCM.generate_key(bit_length=256)
            rsa_key = cast(RSAPublicKey, self.servidor_pub_key)
            print(f"[Cliente] Cifrando clave de sesión para el servidor...")
            relleno = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), 
                label=None)
            
            #Encriptamos la clave simetrica con la clave privada
            encrypted_key = rsa_key.encrypt(self.session_key, relleno)
            mensaje = {"id_cliente": self.id_cliente, "encrypted_session_key": encrypted_key.hex()}
            #Pasamos los datos al servidor
            response = requests.post(f"{self.servidor_url}/connect", json=mensaje, timeout=5)
            
            if response.status_code == 200:
                resp_json = response.json()
                print("[Cliente] Respuesta de handshake recibida. Descifrando...")
                #Desciframos con la clave simetrica
                confirmacion = self._decrypt_response(resp_json)
                if confirmacion.get("status") == "ok":
                    print("[Cliente] Conexión segura establecida y confirmada bidireccionalmente.")
                    return True
            
            raise Exception("Servidor rechazó el handshake o la respuesta fue inválida")

        except Exception as e:
            print(f"[Cliente] ERROR handshake: {e}")
            self.session_key = None
            return False

# ======== HELPERS DE CLAVE SIMÉTRICA (+ FIRMA) =========
    def _encrypt_mensaje(self, data_dict: Dict[str, Any]) -> Dict[str, str]:
        if not self.session_key:
            raise ValueError("No hay clave de sesión")
        print(f"[Cifrado Simétrico] Algoritmo: AES-GCM | Clave: {len(self.session_key)*8} bits | Modo: Autenticado")
        aesgcm = AESGCM(self.session_key)
        nonce = os.urandom(12)
        data_json = json.dumps(data_dict).encode("utf-8")
        encrypted_data = aesgcm.encrypt(nonce, data_json, None)

        return {"nonce": nonce.hex(), "encrypted_data": encrypted_data.hex()}

    def _decrypt_response(self, response_json: Dict[str, Any]) -> Any:
        #Ahora tambien comprueba la firma
        if not self.session_key:
            raise ValueError("No hay clave de sesión")

        try:
            nonce_hex = response_json.get("nonce")
            enc_data_hex = response_json.get("encrypted_data")
            firma_hex = response_json.get("signature")
        
            if not isinstance(nonce_hex, str) or not isinstance(enc_data_hex, str) or not isinstance(firma_hex,str):
                 raise ValueError("Formato de respuesta inválido")
            #Hex->bytes
            nonce = bytes.fromhex(nonce_hex)
            encrypted_data = bytes.fromhex(enc_data_hex)
            firma_bytes = bytes.fromhex(firma_hex)
            #Pasamos de objeto de Openssl a objeto de cryptography
            rsa_key = cast(RSAPublicKey, self.servidor_pub_key)
            
            # VERIFICACIÓN DE FIRMA DIGITAL (Encrypt-then-Sign)                
            # Concatenamos Nonce + Datos Cifrados para asegurar la integridad de todo el bloque
            bytes_to_verify = nonce + encrypted_data
            
            try:
                # verify calcula internamente el hash (SHA256) de bytes_to_verify y lo compara con la firma
                rsa_key.verify(
                    firma_bytes,
                    bytes_to_verify,
                    padding.PSS(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                print("   [Firma Digital] ¡VERIFICADA! Integridad y Autenticidad confirmadas.")
            except InvalidSignature:
                print("   [Firma Digital] ¡ERROR! Firma inválida. El paquete ha sido alterado o no proviene del servidor.")
                raise ValueError("Firma digital inválida - Abortando descifrado")
            
            # DESCIFRADO SIMÉTRICO (Solo si la firma pasó)
            aesgcm = AESGCM(self.session_key)
            decrypted_bytes = aesgcm.decrypt(nonce, encrypted_data, None)
            #bytes-> dict
            contenido = json.loads(decrypted_bytes.decode("utf-8"))
            return contenido

        except Exception as e:
            print(f"   [Error Criptográfico] {e}")
            raise ValueError(f"Fallo al descifrar/verificar: {e}")

# ======== USO DE LA API =========
    def validar_login(self, datos_login: Dict[str, Any]):
        if not self.session_key: return None
        usuario = datos_login.get('usuario', 'Desconocido')
        print(f"\n[Cliente] Iniciando proceso de LOGIN para usuario: '{usuario}'")
        
        try:
            mensaje = {"id_cliente": self.id_cliente}
            mensaje.update(self._encrypt_mensaje(datos_login))
            response = requests.post(f"{self.servidor_url}/login", json=mensaje, timeout=2)
            
            if response.status_code != 200:
                # Intento leer el mensaje de error del servidor si viene en JSON plano
                try:
                    error_msg = response.json().get("message", "Error desconocido")
                except:
                    error_msg = f"Status {response.status_code}"
                print(f"[Cliente] Login RECHAZADO por el servidor: {error_msg}")
                return None
            
            respuesta = self._decrypt_response(response.json())
            if respuesta and respuesta.get("status") == "ok":
                print(f"[Cliente] Login EXITOSO. Datos de usuario recibidos.")
                return respuesta
            
            print(f"[Cliente] Login fallido tras descifrar respuesta: {respuesta.get('message')}")
            return None
        except Exception as e:
            print(f"[Cliente] Error crítico durante login: {e}")
            return None

    def registrar_usuario(self, datos_usuario: Dict[str, Any]):
        if not self.session_key: return None
        usuario = datos_usuario.get('usuario', 'Desconocido')
        print(f"\n[Cliente] Iniciando proceso de REGISTRO para usuario: '{usuario}'")

        try:
            mensaje = {"id_cliente": self.id_cliente}
            mensaje.update(self._encrypt_mensaje(datos_usuario))

            response = requests.post(f"{self.servidor_url}/register", json=mensaje, timeout=2)
            
            if response.status_code != 200:
                # Intento leer el mensaje de error del servidor si viene en JSON plano
                try:
                    error_msg = response.json().get("message", "Error desconocido")
                except:
                    error_msg = f"Status {response.status_code}"
                print(f"[Cliente] Registro RECHAZADO por el servidor: {error_msg}")
                return None

            respuesta = self._decrypt_response(response.json())
            if respuesta and respuesta.get("status") == "ok":
                print(f"[Cliente] Registro EXITOSO. Usuario creado.")
                return respuesta
            
            print(f"[Cliente] Registro fallido tras descifrar respuesta: {respuesta.get('message')}")
            return None
        except Exception as e:
            print(f"[Cliente] Error crítico durante registro: {e}")
            return None

    def actualizar(self, datos: Dict[str, Any]):
        if not self.session_key: return
        print(f"\n[Cliente] Sincronizando datos con servidor (Cookies/Mejoras)...")
        try:
            mensaje = {"id_cliente": self.id_cliente}
            #Añadimos los nuevos datos
            mensaje.update(self._encrypt_mensaje(datos))
            response = requests.post(f"{self.servidor_url}/update-data", json=mensaje, timeout=2)
            
            if response.status_code != 200:
                # Intento leer el mensaje de error del servidor si viene en JSON plano
                try:
                    error_msg = response.json().get("message", "Error desconocido")
                except:
                    error_msg = f"Status {response.status_code}"
                print(f"[Cliente] UPDATE RECHAZADO por el servidor: {error_msg}")
                return None
            
            respuesta = self._decrypt_response(response.json())
            if respuesta and respuesta.get("status") == "ok":
                print(f"[Cliente] UPDATE EXITOSO. Datos guardados.")
                return respuesta
            
            print(f"[Cliente] Update fallido tras descifrar respuesta: {respuesta.get('message')}")
            return None
        except Exception as e:
            print(f"[Cliente] Fallo de conexión al actualizar: {e}")
            return None

    def logout(self, nombre_usuario) -> bool:
        if not nombre_usuario: return False
        print(f"\n[Cliente] Cerrando sesión de '{nombre_usuario}'...")
        try: 
            mensaje = {"usuario": nombre_usuario, "id_cliente": self.id_cliente}
            response = requests.post(f"{self.servidor_url}/logout", json=mensaje, timeout=2)
            
            if response.status_code != 200:
                # Intento leer el mensaje de error del servidor si viene en JSON plano
                try:
                    error_msg = response.json().get("message", "Error desconocido")
                except:
                    error_msg = f"Status {response.status_code}"
                print(f"[Cliente] LOGOUT RECHAZADO por el servidor: {error_msg}")
                return False
            
            respuesta = self._decrypt_response(response.json())
            if respuesta and respuesta.get("status") == "ok":
                print(f"[Cliente] LOGOUT EXITOSO. Salida de sesion.")
                return True
            
            print(f"[Cliente] LOGOUT fallido tras descifrar respuesta: {respuesta.get('message')}")
            return False
            
        except Exception as e: 
            print(f"[Cliente] Error al enviar logout: {e}")
            return False