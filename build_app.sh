#!/usr/bin/env bash
# Builds "Privacy Shield.app", a normal double-clickable Mac app, and puts it in ~/Applications.
#   ./build_app.sh                          uses .venv/bin/python if present, else python3
#   PYTHON=/path/to/python ./build_app.sh
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-.venv/bin/python}"
[ -x "$PY" ] || PY=python3

DEST="$HOME/Applications/Privacy Shield.app"
if pgrep -qf "$DEST/Contents/MacOS"; then
  echo "$DEST is running. Quit it first (its DNS settings get put back when it quits)." >&2
  exit 1
fi

"$PY" -m PyInstaller --version >/dev/null 2>&1 || "$PY" -m pip install "pyinstaller>=6"
[ -f assets/PrivacyShield.icns ] || "$PY" assets/make_icon.py
"$PY" -m PyInstaller --noconfirm --clean --log-level WARN PrivacyShield.spec

# Your lists and stats live in Application Support, so replacing the app doesn't touch them.
SUPPORT="$HOME/Library/Application Support/PrivacyShield"
mkdir -p "$SUPPORT"
for list in whitelist.txt blacklist.txt; do
  if [ -f "$list" ] && [ ! -f "$SUPPORT/$list" ]; then
    cp "$list" "$SUPPORT/$list"
    echo "Copied $list to $SUPPORT"
  fi
done

mkdir -p "$HOME/Applications"
rm -rf "$DEST"
ditto "dist/Privacy Shield.app" "$DEST"
echo "Installed $DEST"
