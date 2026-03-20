#!/usr/bin/env bash
# Build eseguibile per macOS ARM (Apple Silicon)
set -euo pipefail

NAME="ipmon"
SCRIPT="ping_monitor.py"
VENV="/tmp/ipmon-build"

echo "==> Creazione virtualenv..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet pyinstaller rich

echo "==> Build macOS ARM — $NAME"
"$VENV/bin/pyinstaller" \
    --onefile \
    --clean \
    --strip \
    --name "$NAME" \
    "$SCRIPT"

OUT="dist/$NAME"
if [ -f "$OUT" ]; then
    SIZE=$(du -sh "$OUT" | cut -f1)
    echo ""
    echo "OK  Eseguibile: $OUT  ($SIZE)"
    echo "    Uso: ./$OUT --csv hosts.csv"
else
    echo "ERRORE: Build fallita."
    exit 1
fi
