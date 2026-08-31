@echo off
REM Starts the Vite dev server for the SentinelTrap SOC dashboard in the background.
cd /d "%~dp0..\frontend"
start /min powershell -NoProfile -Command "npm run dev *> '%TEMP%\sentineltrap_frontend.log' 2>&1"
