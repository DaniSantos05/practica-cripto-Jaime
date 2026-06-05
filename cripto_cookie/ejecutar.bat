@REM Comprobar y crear entorno virtual si no existe
if not exist ".venv" (
    echo Creando entorno virtual en .venv...
    py -m venv ".venv"
    if errorlevel 1 (
        echo Error al crear el entorno virtual.
        PAUSE
        exit /b 1
    )
) else (
    echo Entorno virtual ya existe.
)

@REM Actualizar pip y verificar/instalar dependencias (SIEMPRE)
".venv\Scripts\python.exe" -m pip install -r "requirements.txt"
if errorlevel 1 (
    echo Error al instalar/verificar dependencias.
    PAUSE
    exit /b 1
)
echo Creando los certificados
".venv\Scripts\python.exe" generar_pki.py

@REM Lanzar los scripts
echo Lanzando el servidor...
START "Ventana del Servidor" ".venv\Scripts\python.exe" pseudoservidor/servidor.py

@REM Esperar un momento para que el servidor inicie
TIMEOUT /T 2
echo Lanzando el programa principal...
".venv\Scripts\python.exe" main.py