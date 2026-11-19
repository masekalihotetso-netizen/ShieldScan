@echo off
REM Builds dist\ShieldScan\ShieldScan.exe (needs internet once, to install PyInstaller).
cd /d "%~dp0"
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt pyinstaller
.venv\Scripts\python -m shieldscan.train_text
.venv\Scripts\pyinstaller --noconfirm --name ShieldScan --add-data "templates;templates" --add-data "static;static" ^
  --add-data "shieldscan\text_model.joblib;shieldscan" --add-data "logos;logos" --collect-data cv2 app.py
echo.
echo Done. Copy ffmpeg.exe and ffprobe.exe next to ShieldScan.exe (or add them to PATH), then run dist\ShieldScan\ShieldScan.exe
