#!/usr/bin/env bash
# Builds the single-file sensor program into dist/. Used by CI and the release workflow.
# The sensor needs only capture and upload code; excluding the rest keeps the program small.
set -euo pipefail
pip install . pyinstaller
pyinstaller --noconfirm --onefile --name intrusionsense-sensor \
  --collect-submodules scapy \
  --exclude-module scipy --exclude-module pandas --exclude-module sqlalchemy --exclude-module matplotlib \
  --exclude-module IPython --exclude-module sklearn --exclude-module joblib --exclude-module fastapi \
  --exclude-module uvicorn --exclude-module tkinter \
  src/intrusionsense/sensor_cli.py
./dist/intrusionsense-sensor --help
