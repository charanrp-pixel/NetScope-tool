#!/bin/bash
# Script to build Netscope as a macOS Application

echo "Activating virtual environment..."
source venv/bin/activate

echo "Ensuring pyinstaller is installed..."
pip install pyinstaller

echo "Building Netscope.app..."
pyinstaller --name=Netscope --windowed --add-data="templates:templates" --add-data="static:static" launcher.py --noconfirm

echo "Done! The application is located in the 'dist' folder."
echo "You can move dist/Netscope.app to your Applications folder."
