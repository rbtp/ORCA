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

### Step 2 — Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Required
JWT_SECRET=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
DB_PASSWORD=<strong-password>

# Required for remote collection — set to the IP/hostname where target endpoints can reach this server
ORCA_SERVER_URL=https://10.x.x.x:8000

# Required for CORS — must match the origin analysts use in their browsers
CORS_ORIGINS=https://10.x.x.x

# Optional — leave empty for relative-path frontend (recommended)
VITE_API_URL=
```

### Step 3 — Place Binaries

The following binaries must be present in `backend/bin/` before building:

| Path | Description |
|------|-------------|
| `backend/bin/velociraptor.exe` | Velociraptor Windows binary (deployed to remote targets) |
| `backend/bin/velociraptor` | Velociraptor Linux binary (runs inside the container) |
| `backend/bin/syftgrype/syft` | Syft SBOM generator |
| `backend/bin/syftgrype/grype` | Grype vulnerability scanner |
| `backend/bin/clamav/` | ClamAV binaries and signature files |
| `backend/bin/remora/volatility3/` | Volatility3 Python package |
| `backend/bin/arsenal/aim_cli` | Arsenal Image Mounter CLI |

These are excluded from the Git repository (`.gitignore`) and must be sourced separately.

### Step 4 — Build and Start

```bash
docker compose up -d
```

On first run:
- PostgreSQL 15 initialises the `orca_db` database
- The backend container generates a self-signed ECDSA P-256 TLS certificate and writes it to the `orca-certs` shared volume
- The frontend nginx waits up to 60 seconds for the cert to appear before starting
- ClamAV signatures are updated via `freshclam` (non-fatal if this fails)
- LibreOffice is pre-warmed to eliminate cold-start delay on the first PDF export

Wait 30–60 seconds for all services to be healthy, then open `https://<server-ip>` in your browser.

### Step 5 — Initialise the Database

Run migrations to create all required tables:

```bash
# Core tables (run all SQL files in the migrations directory)
docker exec -i orca-postgres psql -U postgres -d orca_db < migrations/add_package_tokens.sql

# Agent tables
docker exec -i orca-postgres psql -U postgres -d orca_db < backend/agent_migration.sql

# Behavioral analysis tables (CAPA / FLOSS / Speakeasy)
docker exec -i orca-postgres psql -U postgres -d orca_db < backend/behavioral_analysis_migration.sql

# Audit log (evidence deletion and future admin-action logging)
docker exec -i orca-postgres psql -U postgres -d orca_db < backend/audit_log_migration.sql
```

`backend/schema.sql` is a full schema-only snapshot of a running `orca_db` (see [Database Schema](../README.md#database-schema) in the README) — useful as a reference for what the database should look like after all migrations are applied, but the migration files above are still the source of truth for a fresh install.

Create the initial admin user:
```bash
docker exec -i orca-postgres psql -U postgres -d orca_db <<'EOF'
INSERT INTO users (username, password_hash, initials, role)
VALUES ('admin', '<bcrypt-hash>', 'ADM', 'admin');
EOF
```

To generate a bcrypt hash:
```bash
docker exec orca-backend python -c "from passlib.hash import bcrypt; print(bcrypt.hash('your-password'))"
```

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

```bash
# On a connected machine
grype db update
# Copy ~/.cache/grype/db/ to the air-gapped machine

# Set the GRYPE_DB_CACHE_DIR env var to point at the pre-populated cache
```

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
| `ORCA_SERVER_URL` | Recommended | Auto-detected | Absolute HTTPS URL that remote Windows endpoints will use to reach the ORCA API (e.g. `https://10.x.x.x:8000`). If unset, ORCA auto-detects its own IP — may be wrong in multi-homed environments. |
| `VITE_API_URL` | No | `` (empty) | Backend URL baked into the frontend at build time. Leave empty to use relative `/api/...` paths (recommended). Only set if your frontend is served from a different origin than the API proxy. |
| `ORCA_DATA_ROOT` | No | `/app/evidence` | Directory inside the container where evidence packages and results are stored. |
| `ORCA_VR_MAX_WORKERS` | No | `5` | Maximum concurrent Velociraptor worker processes for local collection. |
| `ORCA_VR_EXE_LOCAL` | No | `bin/velociraptor` | Path to the Velociraptor binary executed inside the container (Linux build). |
| `ORCA_VR_EXE_WINDOWS` | No | `bin/velociraptor.exe` | Path to the Velociraptor Windows binary packaged into collection ZIPs for remote targets. |

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
# Trigger via the API
curl -k -X POST https://localhost:8000/api/network/regenerate-cert \
  -H "Authorization: Bearer <admin-jwt>"
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

**Options → User Registry:**
- View all users (username, initials, role)
- Create user: username, password, initials, role (`admin` or `analyst`)
- Delete user (cannot delete yourself)

### Via the API

```bash
TOKEN="<admin-jwt>"

# List users
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/admin/users

# Create user
curl -k -X POST https://localhost:8000/api/admin/users/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"s3cur3","initials":"ALC","role":"analyst"}'

# Delete user
curl -k -X DELETE https://localhost:8000/api/admin/users/alice \
  -H "Authorization: Bearer $TOKEN"
```

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
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/admin/audit-log

# Scoped to one investigation
curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:8000/api/admin/audit-log?case_name=Op%20Phantom"
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
