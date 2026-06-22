#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing system dependencies (requires sudo)..."
pkexec bash -c "
    apt-get update -y &&
    apt-get install -y \
        make \
        libsodium-dev \
        python3-pip \
        python3-pyqt5 \
        python3-pyqt5.qtmultimedia \
        libxcb-xinerama0 \
        libgl1 \
        libglib2.0-0
"

echo "==> Installing Python dependencies..."
pip3 install --break-system-packages \
    PyQt5 \
    opencv-python \
    pyqtgraph \
    requests

echo "==> Building chamlon_client..."
cd "$SCRIPT_DIR/chamlon_client"
make clean
make

echo "==> Building chamlon_server..."
cd "$SCRIPT_DIR/chamlon_server"
make clean
make

echo ""
echo "Done! All dependencies installed and both projects built successfully."
