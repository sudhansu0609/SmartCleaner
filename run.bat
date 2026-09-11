@echo off
cd /d "%~dp0"
python -m pip show PySide6 >nul 2>&1 || python -m pip install -r requirements.txt
start "" pythonw SmartCleaner.pyw
