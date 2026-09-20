# Memoria de CryptoNotes

> Completar antes de entregar: grupo, identificador, nombres, correos, enlace
> del repositorio y capturas marcadas en este documento.

## Datos del grupo

- Grupo: **[PENDIENTE]**
- ID de grupo de prácticas: **[PENDIENTE]**
- Alumnos: **[PENDIENTE]**
- Correos: **[PENDIENTE]**
- Repositorio: **[PENDIENTE]**

## 1. Propósito y estructura

CryptoNotes es un gestor de notas de texto privadas. Cada usuario dispone de
una bóveda y puede crear, consultar, editar y eliminar notas. El título y el
contenido se cifran en el cliente antes de enviarse, por lo que el servidor
solo almacena identificadores, nonces, ciphertext y fechas.

La aplicación se divide en cuatro capas:

1. Interfaz Pygame y formularios (`core/menu.py`, `entities/formularios.py`).
2. Cliente y protocolo seguro (`core/manejador_datos.py`).
3. Primitivas y formatos comunes (`core/crypto_utils.py`).
4. API Flask y persistencia (`pseudoservidor/`).

**[CAPTURA 1: pantalla inicial y editor con una nota de demostración]**

## 2. Autenticación y contraseñas

El registro exige un usuario de entre 3 y 32 caracteres, un correo válido y
una contraseña de entre 12 y 128 caracteres. El servidor nunca almacena la
contraseña. Genera un salt aleatorio de 16 bytes y aplica scrypt con:

- `N = 32768`;
- `r = 8`;
- `p = 1`;
- salida de 32 bytes.

Se eligió scrypt porque es una función específica para contraseñas y requiere
memoria, lo que encarece ataques masivos con GPU frente a un hash rápido. Los
parámetros y el salt se guardan junto al resultado para permitir auditoría y
una futura migración. La verificación utiliza la operación `verify` de la
librería, que evita comparar manualmente secretos.

Para reducir diferencias temporales, el intento de login de un usuario
inexistente también ejecuta una derivación scrypt ficticia. Los errores
devueltos no distinguen entre usuario y contraseña incorrectos.

**[CAPTURA 2: registro y rechazo de una contraseña incorrecta]**

## 3. Cifrado y gestión de claves, IVs y nonces

### Bóveda y notas

Durante el registro, el cliente genera una clave de bóveda aleatoria de 256
bits con el generador criptográfico del sistema. Esta clave cifra todas las
notas del usuario mediante AES-256-GCM. Para cada guardado se genera un nonce
nuevo de 12 bytes. El identificador de usuario y el UUID de la nota se incluyen
como datos autenticados adicionales (AAD), impidiendo mover un ciphertext a
otro usuario o identificador.

La clave de bóveda no se almacena en claro. El cliente deriva otra clave desde
la contraseña mediante scrypt, genera salt y nonce independientes, y envuelve
la clave de bóveda con AES-256-GCM. El servidor conserva únicamente esa versión
envuelta. Tras el login, el cliente la desenvuelve y la mantiene en memoria
durante la sesión.

### Transporte

Cada cliente genera una clave de sesión AES-256 y la cifra para el servidor
con RSA-OAEP, MGF1 y SHA-256. Un desafío aleatorio confirma que la respuesta
pertenece al handshake actual. Todas las operaciones posteriores se cifran con
AES-256-GCM.

Los AAD del transporte incluyen versión, dirección, UUID de cliente, endpoint
y número de secuencia. Cliente y servidor mantienen contadores independientes,
por lo que un mensaje repetido o enviado a otro endpoint es rechazado. Los
nonces de GCM son siempre 96 bits obtenidos de `os.urandom`; no existen claves,
IVs ni nonces constantes.

Las claves privadas RSA son de 3072 bits, se guardan en PKCS#8 cifrado y sus
contraseñas se solicitan por consola o variable de entorno. Los ficheros de
datos y claves tienen permisos restrictivos. Las claves privadas y los datos
generados están excluidos de Git.

**[CAPTURA 3: fichero `usuarios.json` mostrando una nota solo como ciphertext]**

## 4. Integridad y autenticidad

AES-GCM es un esquema AEAD: genera un tag que autentica simultáneamente el
ciphertext y los AAD. Por este motivo no se añade un HMAC separado. Al modificar
el ciphertext, el tag, el usuario, el UUID, el endpoint o la secuencia, la
operación de descifrado falla y los datos no se procesan.

El código captura esos fallos, devuelve un mensaje genérico y conserva el
último contador válido. Las notas manipuladas nunca se muestran parcialmente:
la comprobación de GCM sucede antes de decodificar el JSON.

**[CAPTURA 4: prueba de ciphertext o tag modificado que resulta rechazada]**

## 5. Firma digital y PKI

El servidor firma todas sus respuestas seguras sobre AAD, nonce y ciphertext
mediante RSA-PSS con SHA-256, MGF1-SHA-256 y una longitud de salt igual al
resumen. El cliente verifica la firma antes de descifrar. Así se autentica el
origen de las respuestas y se evita aceptar un paquete fabricado, incluso si
un atacante controla el canal local.

La clave pública de firma procede de un certificado de servidor. El cliente
verifica una cadena compuesta por una CA raíz local, una CA intermedia y el
certificado final. También comprueba vigencia, restricciones de CA, uso de
servidor, nombres `localhost`/`127.0.0.1` y un tamaño RSA mínimo de 3072 bits.

La PKI no es obligatoria en el enunciado actual, pero resuelve la autenticación
de la clave pública. Las claves privadas de la raíz, intermedia y servidor se
generan localmente y permanecen cifradas.

La prueba `test_modified_signature_is_rejected` altera un byte de la firma y
comprueba que la verificación lanza `InvalidSignature` antes del descifrado.

**[CAPTURA 5: ejecución de la prueba de firma modificada]**

## 6. Pruebas de calidad y seguridad

La suite se ejecuta mediante:

```bash
python -m unittest pseudoservidor.test_servidor -v
```

Cada prueba crea almacenamiento, servidor y claves temporales, por lo que no
depende del orden ni modifica datos reales. Incluye casos positivos de
registro, login, guardado, listado, descifrado y borrado, además de:

- contraseña incorrecta;
- ciphertext modificado;
- tag GCM modificado;
- clave de sesión incorrecta;
- firma digital modificada;
- nota almacenada alterada;
- contraseña incorrecta al desenvolver la bóveda;
- repetición del mismo mensaje;
- sustitución de un mensaje entre endpoints;
- logout sin sobre autenticado;
- títulos, contenidos e identificadores inválidos.

### Ataques relevantes y mitigaciones

1. **Robo de `usuarios.json`.** El atacante obtiene hashes scrypt y notas
   cifradas, no contraseñas, clave de bóveda ni textos. Los salts únicos evitan
   tablas precalculadas y el coste de memoria dificulta fuerza bruta.
2. **Manipulación de mensajes o notas.** AES-GCM autentica ciphertext y
   contexto. Cualquier cambio produce rechazo antes de usar el contenido. Las
   respuestas también llevan firma RSA-PSS.
3. **Replay o sustitución de operación.** Los contadores estrictamente
   crecientes detectan repeticiones; el endpoint, dirección y sesión están
   incluidos en los AAD.
4. **Suplantación del servidor.** La cadena PKI autentica la clave pública; el
   desafío del handshake y RSA-PSS autentican cada respuesta.

Como limitaciones, esta práctica no incorpora recuperación de contraseña,
sincronización entre varios dispositivos, rate limiting persistente ni
revocación en línea. Serían requisitos adicionales para un despliegue real.

**[CAPTURA 6: suite completa con todos los casos superados]**

## 7. Dependencias y reproducción

Versiones fijadas en `requirements.txt`:

- Python 3.11 o posterior;
- cryptography 48.0.1;
- Flask 3.1.2;
- Pygame 2.6.1;
- Requests 2.32.5.

Los pasos completos para crear el entorno, generar certificados, ejecutar el
servidor, iniciar el cliente y lanzar las pruebas están documentados en el
`README.md`. El repositorio no contiene contraseñas, claves privadas,
credenciales reales ni datos personales de prueba.
