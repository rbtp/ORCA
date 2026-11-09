@echo off
REM Stop ORCA. Data is kept; start again with start.bat.
cd /d "%~dp0"
docker compose down
echo [ORCA] Stopped.
pause
