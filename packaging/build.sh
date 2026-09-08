#!/usr/bin/env bash
# Build the eMRTD Reader as a single-file executable with PyInstaller.
#
# Usage:  packaging/build.sh
#
# Output: dist/eMRTDReader   (Linux/macOS)   dist/eMRTDReader.exe   (Windows via msys/Git-Bash)
set -euo pipefail

cd "$(dirname "$0")/.."

# Prefer the project venv python if present, else fall back to python3.
if [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"
else
    PY="$(command -v python3 || command -v python)"
fi

echo "[build] using python: $($PY --version)"

echo "[build] installing runtime deps + pyinstaller ..."
"$PY" -m pip install --quiet -r requirements.txt -r packaging/requirements-build.txt

echo "[build] running PyInstaller (one-file, windowed) ..."
"$PY" -m PyInstaller --noconfirm --clean packaging/eMRTDReader.spec

echo "[build] done."
ls -lh dist/eMRTDReader* 2>/dev/null || true
