# ORCA — Operational Response & Collection Architecture

**ORCA** is a self-hosted, web-based digital forensics and incident response (DFIR) platform. It orchestrates Velociraptor artifact collection, memory forensics with Volatility3, malware scanning with ClamAV, vulnerability scanning with Grype/Syft, and threat-intelligence-driven triage — all inside a dark-ops terminal UI, delivered as a containerised Docker stack.

---

## Features

### Case & Asset Management
- Create and manage investigation cases scoped to a geopolitical threat focus (country) or a custom threat-group selection
- Add assets (endpoints) with hostname, IP, OS, and analysis mode (live remote, dead-disk local, or dead-disk mounted)
- Interactive network map with drag-and-drop node placement saved to the case
- Per-case BLUF notes and technique-level analyst notes with author attribution
- 4-step deletion confirmation with a math challenge and typed confirmation phrase

### MITRE ATT&CK Integration
- Full ATT&CK knowledge base (groups, techniques, sub-techniques, tactics, campaigns) loaded from STIX data
- Geopolitical threat attribution — country → threat groups → ATT&CK techniques chain resolved automatically
- Browsable MITRE dossier view with per-group technique hierarchy
- Per-technique verdict workflow: `MALICIOUS`, `NON-MALICIOUS`, `Evidence Found`, `NO_ARTIFACTS`, `Undetermined`
- Per-technique status lifecycle: `UNCLAIMED` → `IN_PROGRESS` → `PENDING_REVIEW` → `CLOSED`
- Analyst notes and BLUF notes at both case and technique level

### Artifact Collection
- **Remote deployment** — builds a self-contained ZIP package (Velociraptor binary + PowerShell bootstrap + per-technique VQL/YAML) and triggers it on the remote Windows target via SMB+Task Scheduler (port 445 only; no WinRM required by default)
- **Triage collection** — targeted artifact pull across 12 categories: Event Logs, Prefetch, MFT, Registry, Browser Artifacts, LNK/Jump Lists, Scheduled Tasks, WMI Persistence, SRUM, Amcache, Recycle Bin, USB Artifacts
- **Manual package** — one-click generation of a downloadable bootstrap command for air-gapped or manual deployment
- **Three-path collection fallback** per technique: surgical YAML → custom VQL → generic fallback VQL
- Tokenised ingest pipeline: each package uses a single-use time-limited token; the agent auto-revokes it on completion
- Real-time progress polling shows per-technique status as evidence arrives

### Memory Forensics (Volatility3)
- Run individual Volatility3 plugins (Windows, Linux, macOS) against a memory image
- Full-scan mode: automatically selects all relevant plugins for the target OS
- Actor-targeted scan: selects plugins mapped to a specific threat actor's TTPs
- Memory acquisition via WinPMem
- Process memory dump by PID
- Results written to database and displayed per MITRE T-code

### Malware Scanning (ClamAV)
- Recursive directory scan against bundled ClamAV signatures
- Scan results stored per asset with hit count and malware names
- Online signature update via freshclam (runs on container start and on-demand)

### Vulnerability Scanning (Grype + Syft)
- Syft generates a CycloneDX SBOM for a target path
- Grype queries the vulnerability database against the SBOM
- Results deduplicated and stored per asset: CVE ID, severity, package, version, fix version
- Severity breakdown (Critical / High / Medium / Low)

### Disk Image Mounting
- Mount E01, VMDK, VHD, VHDX, QCOW2 and other formats via Arsenal Image Mounter CLI
- Read-only mount with automatic provider detection by file extension
- Mount session tracking per asset; graceful dismount

### Detection Coverage
- Per-country and per-investigation-profile coverage heat map
- Shows total techniques in scope, how many have custom VQL, how many have YAML-only coverage
- Expandable per-T-code table with VQL/YAML presence and last-updated date

### Investigation Profiles
- Named custom technique sets stored in the database
- Used as an alternative to country-based geopolitical focus
- Appear in the Detection Coverage tool alongside country profiles

### IOC Management
- Store discovered IOCs (IP, domain, hash, etc.) against a case
- Cross-reference IOC values against evidence table via substring search

### Reporting
- DOCX report export via Node.js + `docx` library with a terminal/dark theme
- PDF export via LibreOffice headless conversion
- Sections: cover page, investigation summary, asset breakdown, BLUF/executive notes, analyst timeline, technique verdicts table, network map (rendered as embedded image)

### Agent Fleet
- Persistent Python agent (`orca_agent.py`) deployed to endpoints via remote SMB trigger or manual install
- Agent registers with the server, polls for jobs (long-poll), streams results back via SSE
- Deploy agent remotely from the ORCA UI: downloads binaries, creates a scheduled task, and waits for registration
- Dashboard widget shows online/offline agent count

### TLS & Network Configuration
- Self-signed ECDSA P-256 certificate auto-generated on first container boot into a shared Docker volume
- Admin-only certificate regeneration from the Options → Network page
- Certificate info: expiry, SANs, key type, days remaining
- Backend restarts automatically after cert regeneration; nginx detects cert change and reloads

### Access Control
- JWT authentication (HS256, 60-minute expiry)
- `admin` and `analyst` roles
- Rate-limited login: 5 requests per minute per IP
- Admin-only routes: user creation/deletion, cert regeneration, agent deletion

---

## Architecture

```
Browser
  │  HTTPS 443
  ▼
nginx (orca-frontend)       ← React SPA + static assets
  │  /api/ proxy → HTTPS 8000
  ▼
FastAPI (orca-backend)      ← Python 3.9, Uvicorn, TLS 1.2+
  │  SQLAlchemy / psycopg2
  ▼
PostgreSQL 15 (orca-postgres)

Shared volume: orca-certs   ← ECDSA P-256 cert/key, written by backend, read by nginx
Shared volume: orca-evidence ← collected artifacts, SBOM files, vuln results
```

All API calls from the browser are relative `/api/...` paths. nginx proxies them to the backend by Docker service name (`orca-backend:8000`). Moving to a new host requires only editing `CORS_ORIGINS` in `.env` and running `docker compose up --build`.

---

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Frontend framework | React | 19.x |
| Frontend build | Vite | 7.x |
| Frontend server | nginx | alpine |
| Charts | Recharts | 3.x |
| Graph visualisation | D3.js | 7.x |
| Backend framework | FastAPI | 0.111 |
| Backend server | Uvicorn | 0.30 |
| ORM | SQLAlchemy | 2.0 |
| Database | PostgreSQL | 15 |
| Auth | python-jose (JWT HS256) + passlib bcrypt | — |
| Rate limiting | slowapi | 0.1.9 |
| Remote exec (SMB) | impacket | 0.12.0 |
| Remote exec (WinRM) | pywinrm | 0.4.3 |
| Artifact collection | Velociraptor | (bundled binary) |
| Memory forensics | Volatility3 | (bundled) |
| Malware scanning | ClamAV | (apt package) |
| Vulnerability scanning | Syft + Grype | (bundled binaries) |
| Disk imaging | Arsenal Image Mounter CLI | (bundled) |
| Report generation | Node.js + docx | 8.x |
| PDF conversion | LibreOffice headless | (apt package) |
| Containerisation | Docker Compose | v2 |

---

## Prerequisites

- **Docker Desktop** (Windows or Linux) with Docker Compose v2
- **WSL2** (Windows only) with nested virtualisation enabled — required for Linux containers under Docker Desktop
- **Ports available**: 80, 443 (frontend), 8000 (backend)
- **Hardware**: 4 GB RAM minimum; 8 GB recommended (LibreOffice and memory analysis are heavyweight)
- **Storage**: 20 GB+ for evidence volumes and container images
- Target Windows endpoints must have **SMB port 445** reachable and local administrator credentials available for remote collection

---

## Quick Start

```bash
git clone https://github.com/rbtp/ORCA.git
cd ORCA

# Copy and configure the environment file
cp .env.example .env
# Edit .env — set JWT_SECRET and (optionally) CORS_ORIGINS and ORCA_SERVER_URL

docker compose up -d
```

Open `https://<server-ip>` in your browser. Accept the self-signed certificate warning on the first visit.

Default credentials are created by the database seed migration. See [First-Run Setup](#first-run-setup) below.

### First-Run Setup

1. The backend auto-generates a self-signed TLS certificate on first boot — no manual cert files needed.
2. Log in with the seeded admin account (set during database initialisation).
3. Navigate to **Options → User Registry** to create analyst accounts.
4. Navigate to **Investigations** → create a case → add assets.

---

## Air-Gapped / Offline Deployment

For networks without internet access:

**On an internet-connected machine:**
```powershell
# Save all container images to a tar archive
docker save orca-backend orca-frontend postgres:15 | gzip > orca-images.tar.gz

# Copy orca-images.tar.gz and the ORCA project folder to the target machine
```

**On the air-gapped machine:**
```powershell
# Load the images
docker load < orca-images.tar.gz

# Configure and start
cp .env.example .env
# Edit .env

docker compose up -d
```

ClamAV signatures are bundled in `backend/bin/clamav/`. The Grype vulnerability database can be pre-populated by running `grype db update` on a connected machine and copying the cache directory.

---

## Screenshots

> _Screenshots coming soon._

| Screen | Path |
|--------|------|
| Dashboard | `docs/screenshots/dashboard.png` |
| Case Detail | `docs/screenshots/case-detail.png` |
| Evidence Window | `docs/screenshots/evidence-window.png` |
| MITRE ATT&CK Browser | `docs/screenshots/mitre-browser.png` |
| Detection Coverage | `docs/screenshots/detection-coverage.png` |
| Report Export | `docs/screenshots/report-export.png` |

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Step-by-step usage for analysts |
| [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) | Deployment, configuration, and administration |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Full REST API reference |
| [DEPLOY.md](DEPLOY.md) | Quick deployment cheat-sheet |

---

## License

TBD
