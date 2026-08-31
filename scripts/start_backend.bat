@echo off
REM Start the SentinelTrap backend in the background (Windows helper).
cd /d "%~dp0..\backend"
start "sentineltrap-backend" /min cmd /c "python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > %TEMP%\sentineltrap_server.log 2>&1"
echo Backend starting on http://127.0.0.1:8000
echo Log: %TEMP%\sentineltrap_server.log
