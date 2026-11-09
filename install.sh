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
        [ "$proj" = "orcaweb" ] || fail "A container named '$name' already exists and isn't managed by this ORCA install (older start.sh-style install?). Run ./uninstall.sh first."
    fi
done

# ── 2. .env ──────────────────────────────────────────────────────────────────
# .env holds this machine's secrets and address. Installs made by this script
# record the machine in ORCA_INSTALL_HOST, so a .env that arrived with a
# folder copied from another machine can be recognised and not reused.
THIS_HOST=$(hostname)
PROJECT="${COMPOSE_PROJECT_NAME:-orcaweb}"
PORTABLE_KEYS="VT_API_KEY VT_RECHECK_DAYS VT_RATE_LIMIT_SECONDS SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD SMTP_FROM SMTP_USE_TLS ORCA_BOOTSTRAP_ADMIN_USERNAME ORCA_BOOTSTRAP_ADMIN_PASSWORD ORCA_BOOTSTRAP_ADMIN_INITIALS"

env_get() { grep -E "^$2=" "$1" 2>/dev/null | head -1 | cut -d= -f2-; }
env_set() {  # env_set FILE KEY VALUE
    if grep -qE "^$2=" "$1"; then sed -i "s|^$2=.*|$2=$3|" "$1"
    elif grep -qE "^# $2=" "$1"; then sed -i "s|^# $2=.*|$2=$3|" "$1"
    else printf '%s=%s\n' "$2" "$3" >> "$1"; fi
}
read_server_address() {
    if [ -n "$SERVER_ADDRESS" ]; then echo "$SERVER_ADDRESS"; return; fi
    detected=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
    detected=${detected:-localhost}
    read -r -p "Server IP/hostname analysts and agents will use [$detected]: " answer </dev/tty || true
    echo "${answer:-$detected}"
}
is_local_address() {
    case "$1" in localhost|127.0.0.1|"$THIS_HOST") return 0 ;; esac
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -qxF "$1"
}

HAVE_DATABASE=0
docker volume inspect "${PROJECT}_orca-postgres-data" >/dev/null 2>&1 && HAVE_DATABASE=1
if [ "$HAVE_DATABASE" = 0 ] && [ -z "${COMPOSE_PROJECT_NAME:-}" ]; then
    docker inspect orca-postgres >/dev/null 2>&1 && HAVE_DATABASE=1
fi

ENV_HOST=""
[ -f .env ] && ENV_HOST=$(env_get .env ORCA_INSTALL_HOST)

if [ -f .env ] && [ "$ENV_HOST" = "$THIS_HOST" ]; then
    step ".env already exists for this machine, keeping it."
    if [ -n "$SERVER_ADDRESS" ]; then
        env_set .env ORCA_SERVER_URL "https://$SERVER_ADDRESS"
        env_set .env CORS_ORIGINS "https://$SERVER_ADDRESS,https://localhost"
        echo "       Server address set to: https://$SERVER_ADDRESS"
    fi
elif [ -f .env ] && [ "$HAVE_DATABASE" = 1 ]; then
    # Pre-marker .env with an existing ORCA database: the DB password is
    # baked into that database, so the secrets must stay. Only the address
    # may need fixing.
    step ".env found alongside an existing ORCA database, keeping its secrets."
    url=$(env_get .env ORCA_SERVER_URL)
    url_host=$(echo "$url" | sed -E 's|^https?://||; s|[:/].*$||')
    if [ -n "$SERVER_ADDRESS" ] || [ -z "$url_host" ] || ! is_local_address "$url_host"; then
        [ -z "$SERVER_ADDRESS" ] && [ -n "$url_host" ] && printf '\033[33m       ORCA_SERVER_URL (%s) is not an address of this machine.\033[0m\n' "$url"
        addr=$(read_server_address)
        env_set .env ORCA_SERVER_URL "https://$addr"
        env_set .env CORS_ORIGINS "https://$addr,https://localhost"
        echo "       Server address: https://$addr"
    fi
    env_set .env ORCA_INSTALL_HOST "$THIS_HOST"
else
    if [ -f .env ]; then
        backup=".env.from-${ENV_HOST:-another-machine}-$(date +%Y%m%d-%H%M%S)"
        mv .env "$backup"
        step ".env came from another machine (saved as $backup). Creating a new one for this machine..."
    else
        step "Creating .env..."
    fi
    addr=$(read_server_address)
    cp .env.example .env
    env_set .env JWT_SECRET "$(secret)"
    env_set .env DB_PASSWORD "$(secret)"
    env_set .env CORS_ORIGINS "https://$addr,https://localhost"
    env_set .env ORCA_SERVER_URL "https://$addr"
    if [ -n "${backup:-}" ]; then
        for k in $PORTABLE_KEYS; do
            v=$(env_get "$backup" "$k")
            if [ -n "$v" ]; then env_set .env "$k" "$v"; echo "       Carried over $k"; fi
        done
    fi
    env_set .env ORCA_INSTALL_HOST "$THIS_HOST"
    chmod 600 .env
    echo "       Server address: https://$addr"
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
step "Starting the database..."
docker compose up -d orca-postgres || fail "Could not start the database container (see output above)."
# TCP check (-h 127.0.0.1): on a new volume Postgres first runs the schema and
# seed scripts on a socket-only server, which a socket check would report as ready.
db_ready=0
for _ in $(seq 1 100); do
    if docker compose exec -T orca-postgres pg_isready -h 127.0.0.1 -U postgres -d orca_db >/dev/null 2>&1; then db_ready=1; break; fi
    sleep 3
done
[ "$db_ready" = 1 ] || fail "Database didn't become ready. Check: docker compose logs orca-postgres"

# Make the database password match .env. Postgres only applies
# POSTGRES_PASSWORD when a volume is first created, so a database kept from an
# earlier install (or a .env copied from another machine) could otherwise
# have a different password and the backend couldn't connect. Runs over the
# container's local socket, which needs no password.
db_password=$(env_get .env DB_PASSWORD)
docker compose exec -T orca-postgres psql -U postgres -d postgres -q -c "ALTER USER postgres WITH PASSWORD '$db_password'" >/dev/null \
    || fail "Could not set the database password. Check: docker compose logs orca-postgres"

step "Starting ORCA..."
docker compose up -d || fail "'docker compose up' failed (see output above)."

step "Waiting for the backend to finish starting (first boot loads the database, up to ~5 minutes)..."
ready=0
for _ in $(seq 1 72); do
    if docker compose logs --no-log-prefix orca-backend 2>&1 | grep -q "Application startup complete"; then ready=1; break; fi
    if docker compose logs --no-log-prefix orca-backend 2>&1 | grep -q "Backend not started"; then
        docker compose logs --no-log-prefix orca-backend 2>&1 | grep FATAL
        fail "Database migration failed (see above). Full log: docker compose logs orca-backend"
    fi
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
