# ORCA Administration Guide

This guide covers installation, configuration, maintenance, and troubleshooting for ORCA administrators.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Full Installation Walkthrough](#full-installation-walkthrough)
3. [Air-Gapped Deployment](#air-gapped-deployment)
4. [Environment Variables Reference](#environment-variables-reference)
5. [TLS Certificate Management](#tls-certificate-management)
6. [Database Backup and Restore](#database-backup-and-restore)
7. [Updating ORCA](#updating-orca)
8. [User Management](#user-management)
9. [Audit Trail](#audit-trail)
10. [Troubleshooting](#troubleshooting)

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10/11, Ubuntu 22.04+ | Windows 10 Enterprise or Ubuntu 22.04 LTS |
| CPU | 4 cores | 8 cores |
| RAM | 4 GB | 16 GB |
| Storage | 20 GB free | 100 GB+ (evidence volumes grow) |
| Docker Desktop | 4.x+ with Compose v2 | Latest stable |
| WSL2 | Required on Windows | Ubuntu 22.04 distro |

### Windows Prerequisites

1. **Enable WSL2** — Run in an elevated PowerShell:
   ```powershell
   wsl --install
   wsl --set-default-version 2
   ```
   Restart when prompted. If you see a "nested virtualisation" error in Docker, enable it in your hypervisor or BIOS settings.

2. **Install Docker Desktop** — Download from docker.com. During setup, ensure "Use WSL 2 based engine" is selected.

3. **Execution Policy** — The collection bootstrap scripts are unsigned PowerShell. Target endpoints (not the ORCA server) need to allow `Bypass` execution policy. The bootstrap itself passes `-ExecutionPolicy Bypass` so no permanent policy change is required on targets.

---

## Full Installation Walkthrough

### Step 1 — Clone the Repository

```bash
git clone https://github.com/rbtp/ORCA.git
cd ORCA
```

All tool binaries (Velociraptor, ClamAV + signatures, Grype/Syft Windows builds, Volatility3, Arsenal Image Mounter, WinPMem...), the MITRE ATT&CK bundle and the reference data are in the repository. The only thing not in git is the ~3 GB Grype vulnerability DB, which the installer downloads.

### Step 2 — Run the Installer

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1     # Windows
./install.sh                                               # Linux
```

Options: `-ServerAddress <ip>` / `--server-address <ip>` (skip the prompt), `-SkipGrypeDb` / `--skip-grype-db`.

The installer creates `.env` from `.env.example`. It generates random `JWT_SECRET` and `DB_PASSWORD`, sets `ORCA_SERVER_URL=https://<server>` and `CORS_ORIGINS=https://<server>,https://localhost`, then builds, downloads the Grype DB, starts the stack, and prints the first-boot admin password. An existing `.env` is kept, so to change settings later, edit `.env` and run `docker compose up -d`.

`ORCA_SERVER_URL` must be the address remote targets and browsers use to reach this machine, **without** `:8000` (the backend port is internal; everything goes through nginx on 443).

### Step 3 — Manual Alternative

If you'd rather not use the installer:

```bash
cp .env.example .env      # then set JWT_SECRET, DB_PASSWORD, CORS_ORIGINS, ORCA_SERVER_URL
docker compose build
# optional: Grype DB, see "Grype Vulnerability Database" below
docker compose up -d
```

### Step 4 — What Happens on First Boot

On first run:
- PostgreSQL 15 initialises the `orca_db` database
- The backend container generates a self-signed ECDSA P-256 TLS certificate and writes it to the `orca-certs` shared volume
- The frontend nginx waits up to 60 seconds for the cert to appear before starting
- ClamAV signatures are updated via `freshclam` (non-fatal if this fails)
- LibreOffice is pre-warmed to eliminate cold-start delay on the first PDF export

Wait 30–60 seconds for all services to be healthy, then open `https://<server-ip>` in your browser.

### Step 5 — Initialise the Database

**Schema (automatic on a fresh volume):** `docker-compose.yml` mounts `backend/schema.sql` into Postgres's `docker-entrypoint-initdb.d/`. A brand-new `orca-postgres-data` volume therefore gets the full current schema on first start, with no manual migration step. `schema.sql` is regenerated from the live database after every schema change, so it already includes everything in `migrations/` and `backend/*_migration.sql`.

**Existing database (upgrading):** `schema.sql` is *not* re-applied to a volume that already exists. Apply any migrations you don't have yet, for example:

```bash
docker exec -i orca-postgres psql -U postgres -d orca_db < migrations/add_user_account_management.sql
```

All migration files use `IF NOT EXISTS`, so re-running one that's already applied is harmless.

**Reference data (automatic on a fresh volume):** right after the schema, `backend/initdb/02-seed-data.sh` loads `seed_data/*.sql` (MITRE analytics/actors/log sources, artifact library, VQL mappings, threat attribution: reference tables only, no users/cases/evidence). On first backend start, `backend/data/mitre-attack.json` is imported into the MITRE technique/group/software tables. Loading `seed_data/` into an already-populated database fails on duplicate keys. Those files are only for empty databases.

**First admin account (automatic):** if the `users` table is empty at backend startup, `backend/bootstrap_admin.py` creates an admin account:
- If `ORCA_BOOTSTRAP_ADMIN_USERNAME` / `ORCA_BOOTSTRAP_ADMIN_PASSWORD` / `ORCA_BOOTSTRAP_ADMIN_INITIALS` are set, it uses those.
- Otherwise it generates a random password and logs it **once**. Find it with `docker logs orca-backend 2>&1 | grep -A3 "FIRST-BOOT ADMIN"`, then change it under **Options → My Account**.

Log in with that account, then invite everyone else from **Options → User Registry** (see [User Management](#user-management)).

### Step 6 — Connect an Existing PostgreSQL Container

If you have a pre-existing `orca-postgres` standalone container (not managed by this compose project):

```bash
# Create the compose network
docker network create orcaweb_orca-net 2>/dev/null || true

# Connect the existing container
docker network connect orcaweb_orca-net orca-postgres

# Start only backend and frontend (skip the postgres service)
docker compose up -d --no-deps orca-backend orca-frontend
```

---

## Air-Gapped Deployment

### On an Internet-Connected Machine

```bash
# Build images
docker compose build

# Export images
docker save \
  orcaweb-orca-backend \
  orcaweb-orca-frontend \
  postgres:15 \
  | gzip > orca-export.tar.gz

# Also export the ORCA project directory (contains backend/bin/, config, etc.)
# zip or tar the ORCA folder
```

### On the Air-Gapped Machine

```powershell
# Load Docker images
docker load < orca-export.tar.gz

# Extract the ORCA project folder, configure .env, then:
docker compose up -d
```

### ClamAV Signatures (Air-Gapped)

ClamAV signature updates require internet access. For air-gapped deployments:

1. On a connected machine, run `freshclam` and copy the resulting `.cvd` and `.cld` files.
2. Place them in `backend/bin/clamav/`.
3. Rebuild the backend image: `docker compose build orca-backend`.

The backend entrypoint attempts `freshclam` on each start — failures are non-fatal (`[ORCA] WARN: freshclam update failed, using existing signatures`).

### Grype Vulnerability Database (Air-Gapped)

The Grype DB (~3 GB) is **not** in the git repository (it's gitignored). `install.ps1` / `install.sh` download it automatically using the Linux `grype` in the backend image. To do it by hand:

```bash
docker compose run --rm --no-deps --user root -v ./backend/bin/syftgrype/grype-db:/grype-db -e GRYPE_DB_CACHE_DIR=/grype-db --entrypoint sh orca-backend -c 'grype db update && chmod -R a+rX /grype-db'
# Result: backend/bin/syftgrype/grype-db/6/vulnerability.db (+ import.json)
# chmod: grype creates the DB owner-only as root; the backend runs as the
# unprivileged 'orca' user and must be able to read it.
# (chmod: grype creates the DB owner-only as root; the backend runs as the
#  unprivileged 'orca' user and must be able to read it)
```

Then copy the ORCA folder, including `backend/bin/syftgrype/grype-db/`, to the air-gapped machine. The backend points Grype at this directory (`GRYPE_DB_DIR` in `config.py`; override with the `GRYPE_DB_CACHE_DIR` env var). It also serves the directory to agents as `grype-db.zip`. The backend never auto-updates it (the folder is read-only to the backend) and skips Grype's DB age check, so scans keep working as the DB ages. To get newer vulnerability data, re-run the command above periodically.

---

## Environment Variables Reference

Set these in the root `.env` file. All are passed to the `orca-backend` container via `docker-compose.yml`.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | **Yes** | `orca-secret-change-me` | HMAC-SHA256 secret for JWT signing. Generate with `python -c "import secrets; print(secrets.token_hex(32))"`. |
| `DB_PASSWORD` | **Yes** | — | PostgreSQL password for `orca_db`. Used in `DATABASE_URL` and `POSTGRES_PASSWORD`. |
| `DATABASE_URL` | **Yes** | `postgresql://postgres:${DB_PASSWORD}@orca-postgres:5432/orca_db` | Full PostgreSQL connection string. Auto-constructed from `DB_PASSWORD` in docker-compose.yml. |
| `TLS_CERT_PATH` | **Yes** | `/app/certs/orca.crt` | Path to TLS certificate inside the backend container. |
| `TLS_KEY_PATH` | **Yes** | `/app/certs/orca.key` | Path to TLS private key inside the backend container. |
| `CORS_ORIGINS` | Recommended | `https://localhost` | Comma-separated list of allowed CORS origins (browser origins that can call the API). Set to `https://<your-server-ip>` or `https://<hostname>`. |
| `ORCA_SERVER_URL` | Recommended | Auto-detected | Absolute HTTPS URL that remote Windows endpoints will use to reach the ORCA API (e.g. `https://10.x.x.x`, no port). If unset, ORCA auto-detects its own IP — may be wrong in multi-homed environments. |
| `VITE_API_URL` | No | `` (empty) | Backend URL baked into the frontend at build time. Leave empty to use relative `/api/...` paths (recommended). Only set if your frontend is served from a different origin than the API proxy. |
| `ORCA_DATA_ROOT` | No | `/app/evidence` | Directory inside the container where evidence packages and results are stored. |
| `ORCA_VR_MAX_WORKERS` | No | `5` | Maximum concurrent Velociraptor worker processes for local collection. |
| `ORCA_VR_EXE_LOCAL` | No | `bin/velociraptor` | Path to the Velociraptor binary executed inside the container (Linux build). |
| `ORCA_VR_EXE_WINDOWS` | No | `bin/velociraptor.exe` | Path to the Velociraptor Windows binary packaged into collection ZIPs for remote targets. |
| `GRYPE_DB_CACHE_DIR` | No | `bin/syftgrype/grype-db` | Grype vulnerability DB directory. |
| `SMTP_HOST` | No | — | SMTP relay for emailing enrollment/reset links. If unset, email is disabled and links are shown in the admin UI instead. |
| `SMTP_PORT` | No | `587` | SMTP port. |
| `SMTP_USER` / `SMTP_PASSWORD` | No | — | SMTP credentials. |
| `SMTP_FROM` | No | `SMTP_USER` | Sender address. |
| `SMTP_USE_TLS` | No | `true` | Use STARTTLS. |

### Startup Validation

The backend fails hard at startup if `DATABASE_URL`, `TLS_CERT_PATH`, or `TLS_KEY_PATH` are missing from the environment. Check `docker compose logs orca-backend` if the container exits immediately.

---

## TLS Certificate Management

### Auto-Generated Certificate

On first boot, `backend/entrypoint.sh` generates a self-signed ECDSA P-256 certificate:
- Subject: `CN=orca`
- SANs: container IP, container hostname, `orca-backend`, `localhost`
- Validity: 365 days
- Written to: `orca-certs` Docker volume (shared with nginx)

Analysts must accept the certificate in their browser on first visit. Subsequent visits are seamless.

### Regenerating the Certificate

From the ORCA UI (admin role required):
1. Navigate to **Options → Network**.
2. Review the current certificate details (expiry, SANs, key type).
3. Click **Regenerate Certificate**.
4. The backend restarts in 5 seconds; nginx detects the cert file change via md5 polling (every 10 seconds) and reloads gracefully.
5. Analysts will need to accept the new certificate in their browser.

From the command line:
```bash
curl -k -b orca.jar -X POST https://<server>/api/network/regenerate-cert   # orca.jar: see "Via the API" under User Management
```

### Custom Certificates

To use a certificate from your own CA:
1. Place `orca.crt` and `orca.key` in the `orca-certs` Docker volume:
   ```bash
   docker run --rm -v orca-certs:/certs -v /path/to/your/cert:/src alpine \
     sh -c "cp /src/orca.crt /certs/orca.crt && cp /src/orca.key /certs/orca.key"
   ```
2. Restart both containers: `docker compose restart orca-backend orca-frontend`.
3. Update nginx's `proxy_ssl_trusted_certificate` if your CA cert differs from the server cert — edit `frontend/nginx.conf` and rebuild: `docker compose build orca-frontend && docker compose up -d orca-frontend`.

---

## Database Backup and Restore

### Backup

```bash
# Dump to a SQL file on the host
docker exec orca-postgres pg_dump -U postgres orca_db > orca_backup_$(date +%Y%m%d).sql

# Or dump in custom format (faster restore, smaller file)
docker exec orca-postgres pg_dump -U postgres -Fc orca_db > orca_backup_$(date +%Y%m%d).dump
```

### Restore

```bash
# From a plain SQL dump
docker exec -i orca-postgres psql -U postgres orca_db < orca_backup_20260101.sql

# From a custom-format dump (must use pg_restore, same PostgreSQL major version)
docker exec -i orca-postgres pg_restore -U postgres -d orca_db < orca_backup_20260101.dump
```

> **Version mismatch**: If you see `pg_restore: error: unsupported version` when restoring a dump taken from a different PostgreSQL major version, always use `pg_dump` from the same version as the target database. The ORCA compose stack pins PostgreSQL 15.

### Migrate to a New Machine

1. On the old machine:
   ```bash
   docker exec orca-postgres pg_dump -U postgres orca_db > orca_data.sql
   ```
2. Transfer `orca_data.sql` and the ORCA project folder to the new machine.
3. On the new machine, complete [Full Installation Walkthrough](#full-installation-walkthrough) through Step 4.
4. Restore data:
   ```bash
   docker exec -i orca-postgres psql -U postgres orca_db < orca_data.sql
   ```

---

## Updating ORCA

```bash
git pull origin main

# Rebuild images (picks up new Python dependencies and frontend changes)
docker compose build

# Restart (--no-deps avoids recreating the standalone orca-postgres if it exists)
docker compose up -d --no-deps orca-backend orca-frontend
```

Run any new SQL migration files:
```bash
for f in migrations/*.sql; do
  docker exec -i orca-postgres psql -U postgres -d orca_db < "$f"
done
```

---

## User Management

All user management requires the `admin` role.

### Via the UI

Requires `migrations/add_user_account_management.sql` and `migrations/add_users_token_version.sql` (adds `email`, `is_active`, `last_login` to `users`, plus the `enrollment_tokens` and `password_reset_tokens` tables).

**Options → User Registry:**
- View all users (username, initials, role, email, active status, last login)
- **Invite user** (username, initials, role, optional email): creates a one-time enrollment link, valid for 7 days. The invitee opens it and sets their own password. The `users` row is only created when enrollment is completed.
- **Reset password**: creates a one-time reset link, valid for 1 hour. Admins never see or set a user's password.
- **Edit** initials, role, or email
- **Deactivate / reactivate**: a deactivated user can't log in, but their audit-log and case-assignment history stays intact. Use this rather than deleting.

**Changes take effect immediately.** Every request re-checks the account, so deactivating a user, or a password change or reset, logs them out of all open sessions at once (a user changing their own password stays logged in where they did it). Role changes apply on the user's next request. This needs `migrations/add_users_token_version.sql` on existing databases.
- Delete user (cannot delete yourself)

**Link delivery:** if SMTP is configured (see `SMTP_*` in the [Environment Variables Reference](#environment-variables-reference)), invite and reset links are emailed to the user's address. Either way, the link is also shown to the admin in the UI so it can be handed over manually. That is the normal workflow on an air-gapped install. Links are built from `ORCA_SERVER_URL`, so make sure it's set to the address analysts actually browse to.

**Self-service:** every user can edit their own initials/email and change their password under **Options → My Account**. The "Forgot password" link on the login screen only works when SMTP is configured. Without SMTP it tells the user to contact an admin.

### Via the API

```bash
ORCA="https://<server>"
# Log in once; the session is an HttpOnly cookie, kept in ./orca.jar
curl -k -c orca.jar -X POST $ORCA/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"..."}'

# List users
curl -k -b orca.jar $ORCA/api/admin/users

# Invite user (response includes "link" and "emailed")
curl -k -b orca.jar -X POST $ORCA/api/admin/users/invite -H "Content-Type: application/json" -d '{"username":"alice","initials":"ALC","role":"analyst","email":"alice@example.com"}'

# Generate a password reset link
curl -k -b orca.jar -X POST $ORCA/api/admin/users/alice/reset-password

# Deactivate / reactivate
curl -k -b orca.jar -X POST $ORCA/api/admin/users/alice/toggle-active

# Delete user
curl -k -b orca.jar -X DELETE $ORCA/api/admin/users/alice
```

The legacy `POST /api/admin/users/create` (admin sets the password directly) still exists.

### Roles

| Role | Permissions |
|------|-------------|
| `analyst` | Full read/write access to cases, evidence, notes, verdicts, collection |
| `admin` | All analyst permissions + user management, certificate regeneration, agent deletion, evidence deletion, audit trail access |

---

## Audit Trail

Deleting evidence is destructive and, unlike most actions in ORCA, is restricted to `admin` — an analyst can upload, review, and set verdicts on evidence, but only an admin can flush it. Every deletion is written to the `audit_log` table so there's a durable record of who removed what, from where.

### Deleting Evidence (Admin)

In the Evidence Window, a technique that already has evidence shows a `⚠ FLUSH_EVIDENCE` button next to its verdict selector — visible only to admins. Clicking it steps through three gates before the delete fires:

1. **Confirm** — plain "are you sure" prompt.
2. **Verify** — a randomly generated math problem (e.g. `23 + 17 = ?`); an incorrect answer regenerates the problem rather than locking the action out.
3. **Acknowledge** — an explicit warning that the deletion is logged and attributed to your account, with a final `CONFIRM_DELETE`.

The backend endpoint (`DELETE /api/mitre/evidence/{asset_id}/{t_code}`) rejects non-admins with `403` regardless of what the UI shows, and writes the `audit_log` row in the same transaction as the delete — a deletion can't happen without being logged, even via direct API calls.

### Reviewing the Log

**Options → Audit Trail** (admin only) lists every logged action — timestamp, operator, action, investigation, asset, technique, and details — with dropdown filters to narrow by investigation and by asset. It calls `GET /api/admin/audit-log`, which also accepts `case_name`/`asset_id` query params directly:

```bash
TOKEN="<admin-jwt>"

# Full log (most recent 1000)
curl -k -b orca.jar https://<server>/api/admin/audit-log

# Scoped to one investigation
curl -k -b orca.jar "https://<server>/api/admin/audit-log?case_name=Op%20Phantom"
```

The `audit_log` table (`backend/audit_log_migration.sql`) is general-purpose — `action` is free text — so future admin-gated actions can log into the same table without another migration.

---

## Troubleshooting

### Container Exits Immediately on Start

Check logs:
```bash
docker compose logs orca-backend
```

Common causes:
- **Missing env vars**: `FATAL: Missing required environment variables: DATABASE_URL, TLS_CERT_PATH, TLS_KEY_PATH` — set them in `.env`.
- **JWT_SECRET not set**: The backend hard-fails if `JWT_SECRET` is the default placeholder. Generate a real secret.
- **Database unreachable**: The backend validates the DB connection at startup. Ensure `orca-postgres` is on the `orca-net` network and healthy.

### Frontend Shows "nginx: [emerg] cannot load certificate"

The nginx container starts before the cert is ready. The `nginx-entrypoint.sh` polls for the cert file for up to 60 seconds. If this times out:
```bash
# Check if the cert was generated
docker exec orca-backend ls /app/certs/

# If empty, check entrypoint logs
docker compose logs orca-backend | grep -i cert
```

### PowerShell Scripts Fail with Smart-Quote Errors

If a bootstrap PS1 script was copied through a tool that substitutes straight quotes (`'`, `"`) with curly/smart quotes (`'`, `'`, `"`, `"`), PowerShell will fail to parse it. Always copy one-liner commands from the ORCA UI directly; do not paste through Word, Outlook, or other rich-text editors.

Symptom: `The term '...' is not recognized as a name of a cmdlet`

Fix: Use the raw one-liner from the ORCA UI's **PKG** panel clipboard copy function.

### Compose Project Name Mismatch

If you see network names like `orca-net` not found, the compose project name may differ. The `docker-compose.yml` sets `name: orcaweb`, making the network `orcaweb_orca-net`. If you started compose from a directory with a different project name previously, cleanup the old network:

```bash
docker network ls | grep orca
docker network connect orcaweb_orca-net orca-postgres
```

### pg_restore Version Errors

`pg_restore: error: unsupported version (1.15)` means the dump was made with a newer `pg_dump` than the target `pg_restore` understands. Always use a matching PostgreSQL version. The ORCA compose file pins `postgres:15`; dump from and restore to the same major version.

### Nested Virtualisation / WSL2 Errors

Docker Desktop on Windows requires Hyper-V or WSL2. If you see `WSL2 requires nested virtualisation`:
- In VMware: Machine Settings → Processors → Enable "Virtualise Intel VT-x/EPT or AMD-V/RVI"
- In Hyper-V: `Set-VMProcessor -VMName <name> -ExposeVirtualizationExtensions $true`
- In VirtualBox: Settings → System → Processor → Enable "Enable Nested VT-x/AMD-V"

After enabling nested virtualisation, restart the VM and Docker Desktop.

### Frontend Shows Old IP / API Calls Fail After Moving Servers

If you moved ORCA to a new server and the browser is making API calls to the old IP:
1. Ensure `VITE_API_URL` is empty in `.env` (recommended) — this makes all API calls relative paths, so they always hit whatever server served the page.
2. If `VITE_API_URL` was set to a hardcoded IP at build time, rebuild the frontend:
   ```bash
   # Clear VITE_API_URL in .env, then:
   docker compose build orca-frontend
   docker compose up -d orca-frontend
   ```
3. Update `CORS_ORIGINS` to the new server IP/hostname.
4. Update `ORCA_SERVER_URL` to the new IP so remote collection packages reach back correctly.

### Remote Collection Fails — SMB Transport

Symptoms: deploy returns `ERROR: Host unreachable or SMB (445) not enabled`

Checks:
- Confirm port 445 is reachable from the ORCA server to the target: `Test-NetConnection -ComputerName <ip> -Port 445`
- Confirm the credentials have local administrator rights on the target
- Confirm the `ADMIN$` share is accessible (default on most Windows systems)
- If the target has Windows Firewall blocking SMB, add an inbound rule for port 445

### Remote Collection Fails — Authentication

Symptoms: `Authentication failed — check credentials`

Checks:
- Verify the username format — for domain accounts use `DOMAIN` in the `domain` field, not `DOMAIN\user` in the username
- For local accounts, leave the `domain` field blank
- Verify the account is not locked out
- The account must be a member of the local `Administrators` group (not just Remote Desktop Users)

### LibreOffice PDF Export Fails

Symptoms: `PDF conversion failed: soffice not found` or timeout

```bash
# Verify LibreOffice is present in the container
docker exec orca-backend soffice --version

# Check the pre-warm log on startup
docker compose logs orca-backend | grep LibreOffice
```

If LibreOffice is missing, rebuild the backend image (it's installed via `apt-get` in the Dockerfile).

### ClamAV Database Missing / Signatures Outdated

Symptoms: `clamscan: Can't open/parse the config file`

```bash
# Check ClamAV database files
docker exec orca-backend ls /var/lib/clamav/

# Trigger a manual freshclam update
docker exec orca-backend freshclam
```

For air-gapped systems, manually copy `.cvd` and `.cld` files into `backend/bin/clamav/` and rebuild.

### Viewing Logs

```bash
# All services
docker compose logs -f

# Backend only
docker compose logs -f orca-backend

# Frontend/nginx only
docker compose logs -f orca-frontend

# PostgreSQL
docker compose logs -f orca-postgres
```
