@echo off
echo [ORCA] Starting containers...
docker compose up -d --no-deps orca-backend orca-frontend

echo [ORCA] Connecting existing postgres to compose network...
docker network connect orcaweb_orca-net orca-postgres 2>nul
echo [ORCA] Network linked.

echo [ORCA] Restarting backend to pick up DB connection...
docker restart orca-backend

echo [ORCA] Ready.
echo Frontend : http://10.11.110.60
echo Backend  : https://10.11.110.60:8000
pause
