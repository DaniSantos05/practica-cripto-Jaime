#!/bin/bash

echo "Preparando entorno..."

# Crear .venv si no existe
if [ ! -d ".venv" ]; then
    echo "Creando entorno virtual..."
    python3 -m venv .venv
fi

# Instalar dependencias (silencioso)
echo "Verificando dependencias..."
.venv/bin/python -m pip install -r "requirements.txt" 1> /dev/null

#2.5. Generar certificados
source .venv/bin/activate && python -u "generar_pki.py"

# PREPARAR EL NOMBRE DEL LOG
mkdir -p logs
NUM=1
while [ -f "logs/servidor_$NUM.log" ]; do
    NUM=$((NUM + 1))
done
LOG_FILE="logs/servidor_$NUM.log"
echo "Los logs se guardarán en: $LOG_FILE"

# PREPARAR EL COMANDO DEL SERVIDOR
# - 'source' activa el entorno.
# - 'python -u' (unbuffered) evita que los logs salgan con retraso.
# - '2>&1' captura también los errores.
# - '| tee' muestra en pantalla Y guarda en archivo al mismo tiempo.
CMD_SERVER="source .venv/bin/activate && python -u "pseudoservidor/servidor.py" 2>&1 | tee \"$LOG_FILE\"; echo ''; echo 'Servidor detenido. Presiona ENTER para cerrar esta ventana...'; read"

echo "Abriendo Servidor en una ventana independiente..."

# DETECTAR TERMINAL Y LANZAR
if command -v gnome-terminal &> /dev/null; then
    # GNOME (Ubuntu, Fedora, Debian)
    gnome-terminal --title="SERVIDOR (Log: $LOG_FILE)" -- bash -c "$CMD_SERVER" &

elif command -v konsole &> /dev/null; then
    # KDE (Kubuntu, Manjaro)
    konsole -e bash -c "$CMD_SERVER"

elif command -v xfce4-terminal &> /dev/null; then
    # XFCE (Xubuntu, Kali)
    xfce4-terminal --title="SERVIDOR (Log: $LOG_FILE)" -e "bash -c \"$CMD_SERVER\"" &

elif command -v xterm &> /dev/null; then
    # xterm
    xterm -T "SERVIDOR (Log: $LOG_FILE)" -e "bash -c \"$CMD_SERVER\"" &

else
    # Si no hay interfaz gráfica, usamos tu método original (background)
    echo "No se encontró terminal gráfica. Ejecutando en segundo plano..."
    .venv/bin/python -u "pseudoservidor/servidor.py" > "$LOG_FILE" 2>&1 &
    bg_pid=$!
    echo "   PID del segundo plano: $bg_pid"
    trap "kill $bg_pid 2>/dev/null" EXIT
fi

# ESPERAR Y LANZAR CLIENTE
echo "Esperando arranque del servidor..."
sleep 1

echo "Lanzando Cookie Clicker..."
.venv/bin/python "main.py"

echo "FIN"