@echo off
cd /d "%~dp0"

if not exist ".venv" py -m venv .venv
if errorlevel 1 exit /b 1

".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

if not exist "certificados\server.key" (
    ".venv\Scripts\python.exe" generar_pki.py
    if errorlevel 1 exit /b 1
)

echo El servidor pedira la contrasena de su clave privada en otra ventana.
start "Servidor CryptoNotes" cmd /k ".venv\Scripts\python.exe -m pseudoservidor.servidor"
timeout /t 2 /nobreak >nul
".venv\Scripts\python.exe" main.py
