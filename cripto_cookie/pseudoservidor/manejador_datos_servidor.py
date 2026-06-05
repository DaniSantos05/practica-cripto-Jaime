import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import urandom
from cryptography.hazmat.primitives import hashes

class ManejadorDatosServidor:
    def __init__(self, base_path: str):
        #Rutas relativas a la ubicación del servidor
        self.directorio_datos = os.path.join(base_path, "datos")
        self.archivo_usuarios = os.path.join(self.directorio_datos, "usuarios.json")
        self.archivo_logs = os.path.join(self.directorio_datos, "logs.json")
        
        os.makedirs(self.directorio_datos, exist_ok=True)
        
        if not os.path.exists(self.archivo_usuarios):
            self._guardar_json(self.archivo_usuarios, {})
            
        if not os.path.exists(self.archivo_logs):
            self._guardar_json(self.archivo_logs, [])
                
    def _cargar_json(self,archivo):
        try:
            with open(archivo, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _guardar_json(self, archivo: str, datos):
        try:
            with open(archivo, "w", encoding="utf-8") as f:
                json.dump(datos, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error al guardar {archivo}: {e}")

    def agregar_log(self, tipo: str, datos: Dict):
        logs = self._cargar_json(self.archivo_logs)
        nueva_entrada = {
            "timestamp": datetime.now().isoformat(),
            "tipo": tipo,
            "datos": datos
        }
        # nos aseguramos que si esta vacio sea una lista
        if not isinstance(logs, list):
            logs = []
        logs.append(nueva_entrada)
        self._guardar_json(self.archivo_logs, logs)
    
    def hash_password(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100
        )
        return kdf.derive(password.encode())

    def registrar_usuario(self, datos_usuario: Dict) -> bool:
        usuarios = self._cargar_json(self.archivo_usuarios)
        #nos aseguramos que si esta vacio sea un diccionario
        if not isinstance(usuarios, dict):
            usuarios = {}
        salt = urandom(16)
        #creamos el hash de la contraseña
        hashed_password = self.hash_password(datos_usuario["password"], salt)

        if datos_usuario["usuario"] in usuarios:
            self.agregar_log("registro_fallido", {"usuario": datos_usuario["usuario"], "razon": "Usuario ya existe"})
            return False
        
        for usuario_existente in usuarios.values():
            if usuario_existente.get("email") == datos_usuario["email"]:
                self.agregar_log("registro_fallido", {"usuario": datos_usuario["usuario"], "email": datos_usuario["email"], "razon": "Email ya registrado"})
                return False
        
        usuarios[datos_usuario["usuario"]] = {
            "email": datos_usuario["email"],
            "password": hashed_password.hex(),
            "salt": salt.hex(),
            "fecha_registro": datetime.now().isoformat(),
            "ultimo_login": None,
            "cookies": 0,
            "mejoras": []
        }
        
        self._guardar_json(self.archivo_usuarios, usuarios)
        self.agregar_log("registro_exitoso", {"usuario": datos_usuario["usuario"], "email": datos_usuario["email"]})
        return True
    
    def validar_login(self, datos_login: Dict) -> bool:
        #usuarios = {nombre:{password:,salt:,email:..}}
        usuarios = self._cargar_json(self.archivo_usuarios)
        usuario_input = datos_login["usuario"]
        password_input = datos_login["password"]
        
        usuario_encontrado = None
        nombre_usuario = None
        
        if usuario_input in usuarios:
            usuario_encontrado = usuarios[usuario_input]
            nombre_usuario = usuario_input
        else:
            for nombre, datos in usuarios.items():
                if datos.get("email") == usuario_input:
                    usuario_encontrado = datos
                    nombre_usuario = nombre
                    break

        if usuario_encontrado and nombre_usuario:
            salt = bytes.fromhex(usuario_encontrado["salt"])
            hashed_input_password = self.hash_password(password_input, salt)
            hashed_input_password = hashed_input_password.hex()
            if usuario_encontrado["password"] == hashed_input_password:
                usuarios[nombre_usuario]["ultimo_login"] = datetime.now().isoformat()
                self._guardar_json(self.archivo_usuarios, usuarios)
                self.agregar_log("login_exitoso", {"usuario": nombre_usuario})
                return True
        return False
    
    def actualizar_cookies(self, nombre_usuario: str, cookies: int):
        usuarios = self._cargar_json(self.archivo_usuarios)
        if nombre_usuario in usuarios:
            usuarios[nombre_usuario]["cookies"] = cookies
            self._guardar_json(self.archivo_usuarios, usuarios)
        return
    
    def obtener_cookies(self, nombre_usuario: str) -> int:
        usuarios = self._cargar_json(self.archivo_usuarios)
        if nombre_usuario in usuarios:
            return usuarios[nombre_usuario].get("cookies", 0)
        return 0
    
    def guardar_mejoras(self, nombre_usuario: str, mejoras_data: List[Dict]):
        usuarios = self._cargar_json(self.archivo_usuarios)
        if nombre_usuario in usuarios:
            usuarios[nombre_usuario]["mejoras"] = mejoras_data
            self._guardar_json(self.archivo_usuarios, usuarios)
    
    def obtener_mejoras(self, nombre_usuario: str) -> List[Dict]:
        usuarios = self._cargar_json(self.archivo_usuarios)
        if nombre_usuario in usuarios:
            return usuarios[nombre_usuario].get("mejoras", [])
        return []
    
    def limpiar_datos(self):
        self._guardar_json(self.archivo_logs,[])
        self._guardar_json(self.archivo_usuarios,{})
        return True