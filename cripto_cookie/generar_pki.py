from OpenSSL import crypto
import random
import os

#Guardamos las rutas
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.join(BASE_DIR, "pseudoservidor")
os.makedirs(SERVER_DIR, exist_ok=True)

#Func auxiliares
def guardar_archivo(contenido, ruta):
    with open(ruta, "wb") as f:
        f.write(contenido)

def leer_clave_privada(ruta, passphrase=None):
    with open(ruta, "rb") as f:
        # Pasamos la passphrase a load_privatekey
        return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), passphrase)

def leer_certificado(ruta):
    with open(ruta, "rb") as f:
        return crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

#Generamos la ca raiz (se autofirma)
def generar_root_ca(cn_name, key_file, cert_file, your_passphrase=None):
    print(f"--- [Nivel 1] Generando Root CA: {cn_name} ---")
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    cert = crypto.X509()
    subject = cert.get_subject()
    subject.C = "ES"
    subject.O = "Cookie Clicker Corp"
    subject.CN = cn_name
    
    cert.set_issuer(subject)
    cert.set_pubkey(k)
    cert.set_serial_number(random.randint(1, 10000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(20*365*24*60*60) 
    cert.set_version(2) 

    cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
    ])

    cert.sign(k, 'sha256')
    
    # Contraseña para cifrar la clave privada de root_ca
    guardar_archivo(crypto.dump_privatekey(crypto.FILETYPE_PEM, k, 
                                           cipher="aes-256-cbc", 
                                           passphrase=your_passphrase), 
                    key_file)
    #Guardamos el certificado tmb
    guardar_archivo(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), cert_file)
    print(f" -> Guardada Root CA en: {cert_file}")


# --- Añadir parámetro parent_passphrase ---
def generar_certificado_firmado(cn_name, parent_key_path, parent_cert_path, out_key_path, out_cert_path, 
                                es_autoridad=False, parent_passphrase=None, your_passphrase=None):
    """
    Genera un certificado firmado por una entidad superior (padre).
    """
    if es_autoridad:
        tipo = "Subordinada"
    else: 
        tipo = "Servidor Final"
    print(f"\n--- Generando {tipo}: {cn_name} ---")
    
    # Cargar identidad del Padre USANDO LA CONTRASEÑA
    parent_key = leer_clave_privada(parent_key_path, passphrase=parent_passphrase)
    parent_cert = leer_certificado(parent_cert_path)

    # Generar nueva clave para este hijo (privada y publica)
    k_child = crypto.PKey()
    k_child.generate_key(crypto.TYPE_RSA, 2048)

    # Configurar Certificado
    cert = crypto.X509()
    subject = cert.get_subject()
    subject.C = "ES"
    subject.O = "Cookie Clicker Corp"
    subject.CN = cn_name
    if es_autoridad:
        subject.OU = "Seguridad PKI"
    else:
        subject.OU = "Servidores Web"

    cert.set_issuer(parent_cert.get_subject())
    cert.set_pubkey(k_child)
    cert.set_serial_number(random.randint(1, 10000))
    cert.gmtime_adj_notBefore(0)
    
    #10 añitos
    dias_validez = 3650
    cert.gmtime_adj_notAfter(dias_validez * 24 * 60 * 60)
    #Version 3 realmente para las extensiones
    cert.set_version(2)

    extensions = []
    
    extensions.append(crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=parent_cert))
    extensions.append(crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert))

    if es_autoridad:
        #Le damos permiso para firmar mas certificados
        extensions.append(crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"))
        
        extensions.append(crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"))
    else:
        #No puede firmar otros certificados
        extensions.append(crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"))
        # Sirve para el handshake TLS (HTTPS).
        extensions.append(crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"))
        #Pseudonimos
        extensions.append(crypto.X509Extension(b"subjectAltName", False, f"DNS:{cn_name}, DNS:localhost, IP:127.0.0.1".encode("utf-8")))

    cert.add_extensions(extensions)

    # FIRMAR CON LA CLAVE DEL PADRE (ya descifrada)
    cert.sign(parent_key, 'sha256')

    # Guardar la clave del hijo (Cifrada con su propia contraseña)
    guardar_archivo(crypto.dump_privatekey(crypto.FILETYPE_PEM, 
                                           k_child, 
                                           cipher="aes-256-cbc", 
                                           passphrase=your_passphrase), 
                    out_key_path)
    #Guardamos el certificado tmb
    guardar_archivo(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), out_cert_path)
    print(f" -> Guardado {tipo} en: {out_cert_path}")


def generar_todo():
    # Rutas de archivos
    root_key = os.path.join(BASE_DIR, "root_ca.key")
    root_crt = os.path.join(BASE_DIR, "root_ca.crt")
    root_key_password = b"secreto_raiz"
    sub_key = os.path.join(SERVER_DIR, "sub_ca.key")
    sub_crt = os.path.join(SERVER_DIR, "sub_ca.crt")
    sub_key_password = b"secreto_AC_subordinada"
    server_key = os.path.join(SERVER_DIR, "server.key")
    server_crt = os.path.join(SERVER_DIR, "server.crt")
    server_key_password = b"secreto_de_servidor"

    print("=== INICIANDO GENERACIÓN DE PKI (LÓGICA UNIFICADA) ===")
    
    # Generar Raíz (Se cifra con su misma clave)
    generar_root_ca("Cookie Root CA", root_key, root_crt,root_key_password)
    
    # Generar Subordinada 
    # Como necesita leer la clave privada de la raiz la pasamos como argumento
    generar_certificado_firmado(
        cn_name="Cookie Sub CA", 
        parent_key_path=root_key, 
        parent_cert_path=root_crt, 
        out_key_path=sub_key, 
        out_cert_path=sub_crt, 
        es_autoridad=True,
        parent_passphrase=root_key_password,
        your_passphrase=sub_key_password
    )
    
    # Generar Servidor
    # Como necesita leer la clave privada de la AC intermedia la pasamos como argumento
    generar_certificado_firmado(
        cn_name="localhost", 
        parent_key_path=sub_key, 
        parent_cert_path=sub_crt, 
        out_key_path=server_key, 
        out_cert_path=server_crt, 
        es_autoridad=False,
        parent_passphrase=sub_key_password,
        your_passphrase=server_key_password
    )
    
    print("\n=== PKI GENERADA CORRECTAMENTE ===")

if __name__ == "__main__":
    generar_todo()