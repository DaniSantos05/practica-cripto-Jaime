#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

.venv/bin/python -m pip install -r requirements.txt

if [ ! -f "certificados/server.key" ]; then
    .venv/bin/python generar_pki.py
fi

if [ -z "${CRYPTONOTES_SERVER_KEY_PASSWORD:-}" ]; then
    read -r -s -p "Contraseña de la clave privada del servidor: " CRYPTONOTES_SERVER_KEY_PASSWORD
    echo
    export CRYPTONOTES_SERVER_KEY_PASSWORD
fi

mkdir -p logs
.venv/bin/python -m pseudoservidor.servidor > logs/servidor.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

SERVER_READY=0
for _ in {1..30}; do
    if .venv/bin/python -c "import requests; requests.get('http://127.0.0.1:5000', timeout=1).raise_for_status()" 2>/dev/null; then
        SERVER_READY=1
        break
    fi
    sleep 0.2
done

if [ "$SERVER_READY" -ne 1 ]; then
    echo "El servidor no pudo iniciarse. Revisa logs/servidor.log."
    exit 1
fi

.venv/bin/python main.py
