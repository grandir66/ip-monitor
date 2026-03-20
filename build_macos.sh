#!/usr/bin/env bash
# Build eseguibile per macOS ARM (Apple Silicon)
# Richiede: pip install pyinstaller rich
set -euo pipefail

NAME="ipmon"
SCRIPT="ping_monitor.py"
DIST="dist"

echo "==> Verifica dipendenze..."
python3 -m pip install --quiet pyinstaller rich

echo "==> Build macOS ARM — $NAME"
python3 -m PyInstaller \
    --onefile \
    --clean \
    --strip \
    --name "$NAME" \
    --target-arch arm64 \
    "$SCRIPT"

OUT="$DIST/$NAME"
if [ -f "$OUT" ]; then
    SIZE=$(du -sh "$OUT" | cut -f1)
    echo ""
    echo "✓ Eseguibile: $OUT  ($SIZE)"
    echo "  Uso: ./$OUT --csv hosts.csv"
else
    echo "✗ Build fallita."
    exit 1
fi
