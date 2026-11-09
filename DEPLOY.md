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

The installer is safe to re-run. It keeps this machine's `.env` and the Grype DB.

### Installing from a copied folder (instead of git)

Copying the whole ORCA folder from another machine works. The installer recognises that the copied `.env` belongs to the other machine (installs record the machine name as `ORCA_INSTALL_HOST`). It saves the copied file as `.env.from-<machine>-<date>` and creates a fresh one with new secrets and this machine's address. Portable settings (VirusTotal key, SMTP, bootstrap admin) are carried over; machine-specific ones like `CASES_DIR` are not. The Grype DB in the copied folder is reused, so there's no 3 GB download.

### Replacing an existing install

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1                          # asks before deleting data
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveData -RemoveEnv   # complete wipe, no prompt
```
```bash
./uninstall.sh                              # asks before deleting data
./uninstall.sh --remove-data --remove-env   # complete wipe
```

Uninstall removes ORCA's containers, images and network. Data (database, evidence, certificate volumes) is only deleted if you type `DELETE` at the prompt or pass `-RemoveData`. It also finds older installs whose `orca-postgres` container was started outside compose (`start.bat` era). If you keep the data, the next install reuses it: the installer sets the database password to whatever the new `.env` says, so a different `.env` can't lock the backend out.

## Everyday Commands

Windows: `start.bat`, `stop.bat`, `logs.bat` in the ORCA folder. Or anywhere:
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

Database migrations are applied automatically when the backend starts (`backend/migrate.py`): it runs any file in `migrations/` and `backend/*_migration.sql` that this database hasn't had yet, before the app serves requests. Check with `docker compose logs orca-backend | grep -i migration`.

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
| 8889 | Velociraptor GUI (only while started from Options → Velociraptor; has its own login) |

The backend (8000) and PostgreSQL (5432) are only reachable inside the Docker network.
