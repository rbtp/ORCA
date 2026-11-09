@echo off
REM Follow ORCA's logs (Ctrl+C to stop watching).
cd /d "%~dp0"
docker compose logs -f
