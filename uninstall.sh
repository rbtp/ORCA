#!/usr/bin/env bash
# Removes ORCA from this machine's Docker (containers, images and, if you
# choose, all data). Handles install.sh / docker compose installs and older
# installs with a standalone 'orca-postgres' container.
#
# Usage: ./uninstall.sh [--remove-data | --keep-data] [--remove-env]
#   --remove-data  delete the database, evidence and certificate volumes
#                  without asking (CANNOT BE UNDONE)
#   --keep-data    keep the data volumes without asking
#   --remove-env   also delete this folder's .env
set -uo pipefail
cd "$(dirname "$0")"

REMOVE_DATA=""; REMOVE_ENV=0
while [ $# -gt 0 ]; do
    case "$1" in
        --remove-data) REMOVE_DATA=1; shift ;;
        --keep-data)   REMOVE_DATA=0; shift ;;
        --remove-env)  REMOVE_ENV=1; shift ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

step() { printf '\n\033[36m[ORCA] %s\033[0m\n' "$1"; }
fail() { printf '\033[31m[ORCA] ERROR: %s\033[0m\n' "$1"; exit 1; }

command -v docker >/dev/null || fail "Docker is not installed."
docker info >/dev/null 2>&1 || fail "Docker is not running, or this user can't access it."

project="${COMPOSE_PROJECT_NAME:-orcaweb}"

containers=$(docker ps -a --filter "label=com.docker.compose.project=$project" --format '{{.Names}}')
if [ -z "${COMPOSE_PROJECT_NAME:-}" ]; then
    for name in orca-backend orca-frontend orca-postgres; do
        docker inspect "$name" >/dev/null 2>&1 && containers="$containers $name"
    done
fi
containers=$(echo $containers | tr ' ' '\n' | sort -u | tr '\n' ' ')

volumes=$(docker volume ls -q --filter "label=com.docker.compose.project=$project")
for c in $containers; do
    volumes="$volumes $(docker inspect "$c" --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}')"
done
volumes=$(echo $volumes | tr ' ' '\n' | sort -u | tr '\n' ' ')

images=$(docker images --format '{{.Repository}}' | grep -xE "${project}-orca-(backend|frontend)" | sort -u | tr '\n' ' ')

if [ -z "${containers// }" ] && [ -z "${volumes// }" ] && [ -z "${images// }" ]; then
    step "No ORCA containers, volumes or images found. Nothing to remove."
else
    echo
    printf '\033[36m[ORCA] Found:\033[0m\n'
    echo "   containers:   ${containers:-(none)}"
    echo "   images:       ${images:-(none)}"
    echo "   data volumes: ${volumes:-(none)}"

    if [ -n "${volumes// }" ] && [ -z "$REMOVE_DATA" ]; then
        echo
        printf '\033[33m   Deleting the data volumes permanently erases the ORCA database (cases, evidence, users)\n   and stored evidence files. Keep them if you want a reinstall to pick up where you left off.\033[0m\n'
        read -r -p "   Type DELETE to remove all ORCA data, or press Enter to keep it: " answer || true
        [ "${answer:-}" = "DELETE" ] && REMOVE_DATA=1 || REMOVE_DATA=0
    fi

    if [ -f docker-compose.yml ]; then
        step "Stopping ORCA (docker compose down)..."
        docker compose down --remove-orphans
    fi
    if [ -n "${containers// }" ]; then
        step "Removing containers: $containers"
        docker rm -f $containers >/dev/null 2>&1
    fi
    if [ -n "${images// }" ]; then
        step "Removing images: $images"
        docker rmi -f $images >/dev/null 2>&1
    fi
    docker network rm "${project}_orca-net" >/dev/null 2>&1

    if [ "$REMOVE_DATA" = 1 ] && [ -n "${volumes// }" ]; then
        step "Deleting data volumes: $volumes"
        docker volume rm -f $volumes
    elif [ -n "${volumes// }" ]; then
        step "Kept data volumes: $volumes (re-run with --remove-data to delete them)"
    fi
fi

if [ "$REMOVE_ENV" = 1 ] && [ -f .env ]; then
    rm -f .env
    step "Deleted .env"
fi

printf '\n\033[32m[ORCA] Uninstall complete.\033[0m\n\n'
