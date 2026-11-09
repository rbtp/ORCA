# ORCA Deployment Guide

For the full reference (env vars, TLS, backup/restore, troubleshooting), see [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md).

## Fresh Install

Requirements: Docker Desktop (Windows, with WSL2) or Docker Engine + compose plugin (Linux), ports 80 and 443 free, internet access for the first build, ~25 GB disk.

**Windows** (PowerShell, from the repo folder):
```powershell
git clone https://github.com/rbtp/ORCA.git
cd ORCA
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

**Linux:**
```bash
git clone https://github.com/rbtp/ORCA.git
cd ORCA
./install.sh
```

The installer:
1. Checks Docker is installed and running
2. Creates `.env` from `.env.example` with random `JWT_SECRET` / `DB_PASSWORD`, and sets `ORCA_SERVER_URL` / `CORS_ORIGINS` to this machine's IP (it asks; pass `-ServerAddress` / `--server-address` to skip the prompt)
3. Builds the images (10–20 minutes the first time)
4. Downloads the Grype vulnerability DB into `backend/bin/syftgrype/grype-db/` (skip with `-SkipGrypeDb` / `--skip-grype-db`)
5. Starts everything and prints the first-boot admin username and password

On first start, a fresh database volume automatically gets:
- the schema (`backend/schema.sql`)
- reference data (`seed_data/*.sql`: MITRE analytics, artifact library, VQL mappings, threat attribution)
- the MITRE ATT&CK import (`backend/data/mitre-attack.json`)
- one admin account (password printed once by the installer, also in `docker logs orca-backend`)

Then open `https://<server-ip>`, accept the self-signed certificate warning, log in, change the admin password under **Options → My Account**, and invite analysts from **Options → User Registry**.

The installer is safe to re-run. It keeps an existing `.env` and Grype DB.

## Everyday Commands

```bash
docker compose up -d          # start
docker compose down           # stop (data volumes are kept)
docker compose logs -f orca-backend
```

## Updating

```bash
git pull
docker compose up -d --build
```

Then apply any new files in `migrations/` that your database doesn't have yet (they're idempotent):
```bash
docker exec -i orca-postgres psql -U postgres -d orca_db < migrations/<file>.sql
```

## Refreshing the Grype Vulnerability DB

The DB is used as-is and never auto-updated. To pull newer vulnerability data (e.g. monthly):
```bash
docker compose run --rm --no-deps --user root -v ./backend/bin/syftgrype/grype-db:/grype-db -e GRYPE_DB_CACHE_DIR=/grype-db --entrypoint sh orca-backend -c 'grype db update && chmod -R a+rX /grype-db'
```

## Moving to a New Server IP

Edit `ORCA_SERVER_URL` and `CORS_ORIGINS` in `.env`, then `docker compose up -d`. The TLS certificate is regenerated automatically on boot if it doesn't cover the new `ORCA_SERVER_URL`. No rebuild needed.

## Migrating Data to a New Machine

1. On the old machine: `docker exec orca-postgres pg_dump -U postgres -Fc orca_db > orca_backup.dump`
2. On the new machine: run the installer as above
3. Restore over the fresh database:
   ```bash
   docker cp orca_backup.dump orca-postgres:/tmp/
   docker exec orca-postgres pg_restore -U postgres -d orca_db --clean --if-exists /tmp/orca_backup.dump
   docker compose restart orca-backend
   ```

## Air-Gapped Deployment

Run the installer on an internet-connected machine first, then copy to the offline machine:

```bash
docker save orcaweb-orca-backend orcaweb-orca-frontend postgres:15 | gzip > orca-images.tar.gz
```

Copy `orca-images.tar.gz` and the whole ORCA folder (including `backend/bin/syftgrype/grype-db/`, which isn't in git) to the offline machine, then:

```bash
docker load < orca-images.tar.gz
docker compose up -d
```

Delete the copied `.env` first if the offline machine has a different IP, or edit `ORCA_SERVER_URL` / `CORS_ORIGINS` in it.

## Ports

| Port | Service |
|------|---------|
| 443 | Web UI + API (nginx, HTTPS) |
| 80 | Redirects to 443 |

The backend (8000) and PostgreSQL (5432) are only reachable inside the Docker network.
