#!/bin/bash
echo "Building Linux Binary..."

python3 -m pip install pyinstaller
pyinstaller --name Amnezia-Web-Panel \
  --add-data "static:static" \
  --add-data "templates:templates" \
  --add-data "translations:translations" \
  --hidden-import uvicorn \
  --hidden-import fastapi \
  --clean \
  -y \
  -F app.py

echo "Build complete! Executable is in the dist/ folder."
