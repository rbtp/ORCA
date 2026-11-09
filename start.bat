@echo off
REM Start ORCA (after it has been installed with install.ps1).
cd /d "%~dp0"
echo [ORCA] Starting...
docker compose up -d
if errorlevel 1 (
  echo [ORCA] Failed to start. Is Docker Desktop running?
  pause
  exit /b 1
)
set ORCA_URL=
for /f "tokens=1,* delims==" %%A in ('findstr /b "ORCA_SERVER_URL=" .env 2^>nul') do set ORCA_URL=%%B
if not defined ORCA_URL set ORCA_URL=https://localhost
echo [ORCA] Running: %ORCA_URL%
pause
