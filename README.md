# ORCA — Operational Response & Collection Architecture

**ORCA** is a self-hosted, web-based digital forensics and incident response (DFIR) platform. It orchestrates Velociraptor artifact collection, memory forensics with Volatility3, behavioral analysis with Mandiant CAPA/FLOSS/Speakeasy, malware scanning with ClamAV, vulnerability scanning with Grype/Syft, and threat-intelligence-driven triage — all inside a dark-ops terminal UI, delivered as a containerised Docker stack.

---

## Features

### Case & Asset Management
- Create and manage investigation cases scoped to a geopolitical threat focus (country) or a custom threat-group selection
- Add assets (endpoints) with hostname, IP, OS, and analysis mode (live remote, dead-disk local, or dead-disk mounted)
- Interactive network map with drag-and-drop node placement saved to the case
- Per-case BLUF notes and technique-level analyst notes with author attribution
- 4-step deletion confirmation with a math challenge and typed confirmation phrase
- Edit investigation details (mission lead, team, support unit, personnel, country) from the case header at any time
- Add Asset fields cascade top-to-bottom (Asset Type → Operating System → Form Factor); Operating System is the only field that actually drives MITRE technique association (see below), so a Network Device asset locks OS to `Network` automatically instead of leaving it as an independently-settable field that could silently mismatch and pull in the wrong platform's techniques
- Network map: new nodes spawn near-center with slight jitter (no more stacking directly on top of existing nodes or flinging in from a default off-screen point); a hidden hit-area under each icon means dragging a node no longer falls through to panning the canvas
- Network map: optional background image (upload / replace / clear), rendered behind nodes and links
- Network map: devices (routers, switches, firewalls, etc.) can be renamed independently of their hostname

### MITRE ATT&CK Integration
- Full ATT&CK knowledge base (groups, techniques, sub-techniques, tactics, campaigns) loaded from STIX data
- Geopolitical threat attribution — country → threat groups → ATT&CK techniques chain resolved automatically
- Browsable MITRE dossier view with per-group technique hierarchy
- **Custom technique creation** — the Artifact Library Editor can define a technique that isn't a real ATT&CK T-code (its own identifier, name, and live/dead/VQL/YAML collection logic); custom techniques aren't picked up by the automatic geopolitical attribution chain, but are selectable in Investigation Profiles and the Detection Coverage tool the same as any cataloged technique
- Per-technique verdict workflow: `MALICIOUS`, `NON-MALICIOUS`, `Evidence Found`, `NO_ARTIFACTS`, `Undetermined`
- Per-technique status lifecycle: `UNCLAIMED` → `IN_PROGRESS` → `PENDING_REVIEW` → `CLOSED`, live-updated for every analyst viewing the case (not just the one making the change)
- Evidence starring/favoriting per technique, with a starred-only filter independent of the keyword search
- A caution-triangle indicator marks evidence that came from the broad/fallback collection path rather than a surgical query, so analysts can weigh it accordingly
- Analyst notes and BLUF notes at both case and technique level

### Artifact Collection
- **Remote deployment** — builds a self-contained ZIP package (Velociraptor binary + PowerShell launcher + per-technique VQL/YAML) and pushes it to the remote Windows target directly over SMB (port 445), then triggers execution locally on the target — no HTTP download step and no certificate-bypass class needed once push delivery is in use, removing the download-cradle signature some AV/EDR products flag
- **SMB/Task Scheduler or WinRM trigger** — after the package is staged, execution is triggered either via a throwaway Windows service (SMB/Task Scheduler, the default) or directly over WinRM (port 5985) for environments where avoiding service-registration is preferred; a WinRM trigger reports back real captured exit code and output instead of assuming success once the process launches
- **Parallel collection workers** — the collection and triage scripts split techniques/artifacts across up to `$MaxWorkers` concurrent child processes on the target (default 3) instead of running strictly sequentially, cutting wall-clock time on larger technique sets
- **Live per-technique monitoring** — the deploy panel shows each technique's current status (running / pending / complete / no-artifacts), time since its last heartbeat, and flags a technique as stalled if it's been running 2+ minutes with no update, instead of only an aggregate progress bar
- **Triage collection** — targeted artifact pull across 12 categories: Event Logs, Prefetch, MFT, Registry, Browser Artifacts, LNK/Jump Lists, Scheduled Tasks, WMI Persistence, SRUM, Amcache, Recycle Bin, USB Artifacts
- **Manual package** — one-click generation of a downloadable bootstrap command for air-gapped or manual deployment
- **Three-path collection fallback** per technique: surgical YAML → custom VQL → generic fallback VQL
- Tokenised ingest pipeline: each package uses a single-use time-limited token; the agent auto-revokes it on completion
- Real-time progress polling shows per-technique status as evidence arrives
- Manual evidence upload (JSON / JSONL / CSV / TXT) is available for any technique that doesn't yet have evidence — not gated behind a prior automatic-collection attempt

### Memory Forensics (Volatility3)
- Run individual Volatility3 plugins (Windows, Linux, macOS) against a memory image
- Full-scan mode: automatically selects all relevant plugins for the target OS
- Actor-targeted scan: selects plugins mapped to a specific threat actor's TTPs
- Memory acquisition via WinPMem
- Process memory dump by PID
- Results written to database and displayed per MITRE T-code
- SSE-streamed execution log with real-time Volatility3 progress (PDB scan %, stacking %, cache updates)
- Volatility3 stderr streamed live so long-running scans (large dumps) show progress instead of silence
- Symbol table auto-detected from local ISF pack; diagnostic error shown if the kernel build is not in the pack

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
- **Agent-based remote mounting** — an online `orca_agent.py` instance with mount capability can be selected as the mount target, so the image is mounted on that analyst/endpoint machine rather than requiring the image to be reachable from the ORCA server itself
- Mount session tracking per asset; graceful dismount (dismount always targets the agent that performed the mount, not a client-supplied one)

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
- Edit existing IOC Reliquary entries in place, including an optional label field for analyst-facing context
- Cross-reference IOC values against all evidence via SSE-streamed correlation scan — results stream in as each IOC is checked; scan continues in the background if you navigate away and results are restored when you return
- Per-IOC hit table: case, hostname, T-code, artifact alias
- Promote evidence directly to the IOC library from any technique row

### Behavioral Analysis (CAPA / FLOSS / Speakeasy)
- Static capability analysis via **Mandiant CAPA** — maps binary capabilities to MITRE ATT&CK techniques; badges appear on the matching technique rows in the investigation checklist
- Obfuscated string extraction via **Mandiant FLOSS** — extracts static, stack, tight, and decoded strings; automatically flags IOCs (IPs, domains, URLs, registry keys, file paths, emails); cross-references extracted IOCs against the global IOC library with threat-actor attribution
- Windows PE emulation via **Speakeasy** — captures API call sequences, network connections, file/registry activity, and memory operations without executing the sample on a real system
- Submit binaries by file upload or by selecting a previously collected artifact directly from the evidence library
- SSE-streamed pipeline: live progress per tool with technique and string counts updating in real time
- Full results persisted to database; history picker lets analysts compare runs across multiple samples on the same asset
- Behavioral summary card in the asset Overview tab; BEHAVIORAL ANALYSIS tab badge shows live technique count
- Behavioral data included in DOCX/PDF report exports
- **Uploaded samples are stored on a `noexec,nosuid,nodev` tmpfs mount** (`/tmp/orca_behavioral`, see `docker-compose.yml`) — kernel-enforced, not just file-permission bits, so a submitted sample can never be executed on the host or in the container regardless of application-level bugs. tmpfs also means samples live in RAM only: they never touch disk and are wiped on every container restart, independent of the app's own per-job cleanup

### Reporting
- DOCX report export via Node.js + `docx` library with a terminal/dark theme
- PDF export via LibreOffice headless conversion
- Sections: cover page, investigation summary, asset breakdown, BLUF/executive notes, analyst timeline, technique verdicts table, network map (rendered as embedded image), behavioral analysis (CAPA techniques, FLOSS IOCs, Speakeasy network events, top API calls)

### Agent Fleet
- Persistent Python agent (`orca_agent.py`) deployed to endpoints via remote SMB trigger or manual install
- Agent registers with the server, polls for jobs (long-poll), streams results back via SSE
- Deploy agent remotely from the ORCA UI: downloads binaries, creates a scheduled task, and waits for registration
- Job types include disk image mount/dismount (backs Disk Image Mounting's agent-based mode above), with capabilities self-reported so only agents that support a given job type are offered as targets for it
- Dashboard widget shows online/offline agent count

### TLS & Network Configuration
- Self-signed ECDSA P-256 certificate auto-generated on first container boot into a shared Docker volume, with `ORCA_SERVER_URL`'s host folded into the certificate's SAN (not just the container's internal Docker IP) so it validates correctly for the address remote targets actually connect back to
- Certificate `notBefore` is backdated by a day at generation time, absorbing host clock drift/corrections that would otherwise make a freshly-generated certificate appear "not yet valid" until real time caught up
- Boot-time check auto-regenerates the certificate if the existing one doesn't cover the currently-configured `ORCA_SERVER_URL`, not just on first boot ever
- Admin-only certificate regeneration from the Options → Network page (uses the same `ORCA_SERVER_URL`-aware SAN logic as the boot-time path)
- Certificate info: expiry, SANs, key type, days remaining
- Backend restarts automatically after cert regeneration; nginx detects cert change and reloads

### Access Control
- JWT authentication (HS256, 60-minute expiry)
- `admin` and `analyst` roles
- Rate-limited login: 5 requests per minute per IP
- Admin-only routes: user creation/deletion, cert regeneration, agent deletion, evidence deletion

### Audit Trail
- Evidence deletion is admin-only and gated behind three sequential confirmations — an explicit "are you sure", a math-problem verification, and a final warning that the action is logged and attributed to the operator's account — before the delete is issued
- Every evidence deletion writes an `audit_log` row (operator, timestamp, investigation, asset, technique, and what was removed); the table is general-purpose so future admin actions can log into it too
- Admin-only Audit Trail view (Options → Audit Trail) lists all logged activity, filterable by investigation and by asset

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

### Database Schema

`backend/schema.sql` is a schema-only `pg_dump` snapshot of `orca_db` (tables, columns, constraints, indexes — no data). It's a reference/bootstrap artifact, not a migration tool: the backend reflects the live database via SQLAlchemy `automap_base()` rather than declared ORM models, and incremental changes ship as standalone `*_migration.sql` files (e.g. `backend/audit_log_migration.sql`) applied directly with `psql`. Regenerate the snapshot after a schema change with:
```bash
docker exec orca-postgres pg_dump -U postgres -d orca_db --schema-only --no-owner --no-privileges > backend/schema.sql
```

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
| Capability analysis | Mandiant CAPA (flare-capa) | 7.4.x |
| String extraction | Mandiant FLOSS (flare-floss) | 3.1.x |
| PE emulation | Speakeasy (speakeasy-emulator) | 1.5.x |
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
- Target Windows endpoints must have **SMB port 445** reachable and local administrator credentials available for remote collection; **WinRM port 5985** is only needed if you choose WinRM as the trigger transport instead of the SMB/Task Scheduler default — package staging still goes over SMB either way

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

### Enabling Behavioral Analysis

Run the included PowerShell helper to create the database tables and rebuild the backend image with CAPA rules pre-installed:

```powershell
.\deploy-behavioral.ps1
```

This applies the `behavioral_analysis_migration.sql` schema, downloads flare-capa rules matching the installed version, and recreates the `orca-backend` container. No manual download or configuration is required.

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
