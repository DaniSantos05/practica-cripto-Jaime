# CryptoNotes

Aplicación académica cliente-servidor para crear y guardar notas de texto
cifradas. El servidor autentica usuarios y almacena los registros, pero no
recibe el título ni el contenido de las notas en claro.

## Funciones de seguridad

- Contraseñas almacenadas mediante scrypt (`N=32768`, `r=8`, `p=1`), con salt
  aleatorio de 128 bits por usuario.
- Clave de bóveda AES-256 aleatoria por usuario. Se envuelve con otra clave
  derivada de la contraseña mediante scrypt.
- Notas cifradas en el cliente con AES-256-GCM y nonce aleatorio de 96 bits.
- Transporte de aplicación protegido con una clave AES-256-GCM por sesión.
- Intercambio de la clave de sesión mediante RSA-OAEP-SHA-256.
- Respuestas firmadas mediante RSA-PSS-SHA-256.
- Clave pública del servidor autenticada mediante una PKI raíz/intermedia.
- Datos autenticados adicionales que ligan mensajes y notas a su contexto.
- Contadores por dirección para rechazar mensajes repetidos o desordenados.
- Caducidad de sesiones inactivas a los 30 minutos y límite de sesiones activas.
- Claves privadas PKI cifradas y archivos de datos con permisos restrictivos.

La PKI es una ampliación: el enunciado actual no la exige, pero permite
autenticar la clave pública empleada para el intercambio y las firmas.

## Requisitos

- Python 3.11 o posterior.
- Dependencias fijadas en `cripto_cookie/requirements.txt`.
- Un entorno con interfaz gráfica compatible con Pygame.

## Instalación y ejecución manual

Desde la raíz del repositorio:

```bash
cd cripto_cookie
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python generar_pki.py
```

El generador solicita tres contraseñas. No se guardan en el código. Después,
en una terminal, inicia el servidor:

```bash
cd cripto_cookie
source .venv/bin/activate
python -m pseudoservidor.servidor
```

En otra terminal inicia el cliente:

```bash
cd cripto_cookie
source .venv/bin/activate
python main.py
```

También se incluyen `ejecutar.sh` y `ejecutar.bat`. En sistemas Unix:

```bash
cd cripto_cookie
./ejecutar.sh
```

La contraseña del servidor puede proporcionarse sin escribirla en el código:

```bash
export CRYPTONOTES_SERVER_KEY_PASSWORD='valor introducido durante la generación'
```

No deben compartirse variables reales ni incluirse en capturas o commits.

## Pruebas

Las pruebas crean servidor, claves y almacenamiento temporales. No necesitan
tener el servidor real en ejecución:

```bash
cd cripto_cookie
source .venv/bin/activate
python -m unittest pseudoservidor.test_servidor -v
```

La suite cubre, entre otros casos:

- registro, autenticación y operaciones CRUD;
- contraseña incorrecta;
- ciphertext y tag GCM modificados;
- clave de sesión incorrecta;
- firma digital alterada;
- nota cifrada manipulada;
- contraseña incorrecta para abrir la bóveda;
- repetición de mensajes y sustitución entre endpoints;
- logout sin autenticación y límites de entrada.

La ejecución de referencia supera 13 pruebas, incluida una integración real
cliente HTTP + PKI + servidor + persistencia.

## Organización

```text
cripto_cookie/
├── core/
│   ├── core.py                 coordinación de interfaz y cliente
│   ├── crypto_utils.py         formatos y primitivas compartidas
│   ├── manejador_datos.py      cliente, PKI y protocolo seguro
│   └── menu.py                 interfaz de notas en Pygame
├── entities/formularios.py     registro y login
├── pseudoservidor/
│   ├── servidor.py             API Flask y sesiones seguras
│   ├── manejador_datos_servidor.py
│   └── test_servidor.py
├── certificados/               generado localmente; claves ignoradas por Git
├── generar_pki.py
└── main.py
```

## Modelo y límites

CryptoNotes protege las notas frente a lectura o modificación del fichero del
servidor. Un atacante que desconozca la contraseña no puede desenvolver la
clave de la bóveda. Las respuestas falsas se rechazan por su firma, y el
ciphertext manipulado se rechaza antes de procesar su contenido.

Como limitación académica, el servidor Flask se ejecuta únicamente en
`127.0.0.1` y mantiene las sesiones en memoria. Para producción serían
necesarios HTTPS, gestión centralizada de secretos, rate limiting, revocación
de certificados, copias de seguridad y una base de datos transaccional.

La memoria alineada con las preguntas del enunciado está en
[`MEMORIA.md`](MEMORIA.md).
