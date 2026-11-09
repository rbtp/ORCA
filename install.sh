#!/usr/bin/env bash
# ORCA installer for Linux (Docker Engine + compose plugin).
#
#   1. Checks Docker is installed and running
#   2. Creates .env from .env.example (random JWT_SECRET / DB_PASSWORD, server address)
#   3. Builds the images
#   4. Downloads the Grype vulnerability DB if it isn't already present
#   5. Starts ORCA and prints the first-boot admin login
#
# Safe to re-run: an existing .env and an existing Grype DB are kept.
#
# Usage: ./install.sh [--server-address IP_OR_HOSTNAME] [--skip-grype-db]
set -euo pipefail
cd "$(dirname "$0")"

SERVER_ADDRESS=""
SKIP_GRYPE_DB=0
while [ $# -gt 0 ]; do
    case "$1" in
        --server-address) SERVER_ADDRESS="$2"; shift 2 ;;
        --skip-grype-db)  SKIP_GRYPE_DB=1; shift ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

step() { printf '\n\033[36m[ORCA] %s\033[0m\n' "$1"; }
fail() { printf '\033[31m[ORCA] ERROR: %s\033[0m\n' "$1"; exit 1; }
secret() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# ── 1. Docker ────────────────────────────────────────────────────────────────
step "Checking Docker..."
command -v docker >/dev/null || fail "Docker is not installed. See https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || fail "Docker is not running, or this user can't access it (try sudo, or add yourself to the docker group)."
docker compose version >/dev/null 2>&1 || fail "'docker compose' plugin is not installed."

for name in orca-backend orca-frontend orca-postgres; do
    if proj=$(docker inspect "$name" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null); then
        [ "$proj" = "orcaweb" ] || fail "A container named '$name' already exists and isn't part of this ORCA install. Remove or rename it first."
    fi
done

# ── 2. .env ──────────────────────────────────────────────────────────────────
if [ -f .env ]; then
    step ".env already exists, keeping it."
else
    step "Creating .env..."
    if [ -z "$SERVER_ADDRESS" ]; then
        detected=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
        detected=${detected:-localhost}
        read -r -p "Server IP/hostname analysts and agents will use [$detected]: " answer || true
        SERVER_ADDRESS=${answer:-$detected}
    fi
    sed -e "s|^JWT_SECRET=.*|JWT_SECRET=$(secret)|" \
        -e "s|^DB_PASSWORD=.*|DB_PASSWORD=$(secret)|" \
        -e "s|^CORS_ORIGINS=.*|CORS_ORIGINS=https://$SERVER_ADDRESS,https://localhost|" \
        -e "s|^# ORCA_SERVER_URL=.*|ORCA_SERVER_URL=https://$SERVER_ADDRESS|" \
        .env.example > .env
    chmod 600 .env
    echo "       Server address: https://$SERVER_ADDRESS"
fi

# ── 3. Build ─────────────────────────────────────────────────────────────────
step "Building images (first build takes 10-20 minutes)..."
docker compose build || fail "Image build failed (see output above)."

# ── 4. Grype DB ──────────────────────────────────────────────────────────────
if [ "$SKIP_GRYPE_DB" = 1 ]; then
    step "Skipping Grype DB download (--skip-grype-db)."
elif [ -f backend/bin/syftgrype/grype-db/6/vulnerability.db ]; then
    step "Grype vulnerability DB already present, keeping it."
else
    step "Downloading Grype vulnerability DB (several hundred MB download, ~3 GB on disk)..."
    mkdir -p backend/bin/syftgrype/grype-db
    docker compose run --rm --no-deps --user root \
        -v ./backend/bin/syftgrype/grype-db:/grype-db \
        -e GRYPE_DB_CACHE_DIR=/grype-db \
        --entrypoint sh orca-backend -c 'grype db update && chmod -R a+rX /grype-db' \
    || printf '\033[33m[ORCA] WARN: Grype DB download failed. ORCA will still run; vulnerability scans will not work until you re-run this installer or populate the DB (see docs/ADMIN_GUIDE.md).\033[0m\n'
fi

# ── 5. Start ─────────────────────────────────────────────────────────────────
step "Starting ORCA..."
docker compose up -d || fail "'docker compose up' failed (see output above)."

step "Waiting for the backend to finish starting (first boot loads the database, up to ~5 minutes)..."
ready=0
for _ in $(seq 1 72); do
    if docker compose logs --no-log-prefix orca-backend 2>&1 | grep -q "Application startup complete"; then ready=1; break; fi
    sleep 5
done
[ "$ready" = 1 ] || fail "Backend didn't come up in time. Check: docker compose logs orca-backend"

url=$(grep -E '^ORCA_SERVER_URL=' .env | cut -d= -f2-)
url=${url:-https://localhost}
printf '\n\033[32m================================================================\033[0m\n'
printf '\033[32m ORCA is running: %s\033[0m\n' "$url"
echo " (accept the self-signed certificate warning on first visit)"
creds=$(docker compose logs --no-log-prefix orca-backend 2>&1 | grep -A3 "FIRST-BOOT ADMIN ACCOUNT CREATED" | grep -E "username:|password:" || true)
if [ -n "$creds" ]; then
    echo
    printf '\033[33m First-boot admin login (shown once; change it under Options > My Account):\033[0m\n'
    echo "$creds"
else
    echo " Log in with your existing admin account."
fi
printf '\033[32m================================================================\033[0m\n\n'
