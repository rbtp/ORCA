# ORCA Project — Claude Code Context

## Project Location
`C:\Users\Sentinel\Desktop\Tests\ORCAWEB`

## Stack
- Backend: FastAPI (Python 3.9), entry point `backend/main.py`
- Frontend: React/Vite, source in `frontend/src`
- Database: PostgreSQL in Docker container `orca-postgres`, db `orca_db`, user `postgres`, port 5432
- Backend runs on `https://0.0.0.0:8000` with self-signed ECDSA P-256 TLS cert auto-generated into `orca-certs` Docker volume
- Frontend nginx serves HTTPS on port 443; HTTP port 80 redirects → HTTPS; cert shared from `orca-certs` volume
- Routes live in `backend/routes/mitre_routes.py` and other files in `backend/routes/`
- Node.js used for `backend/report_gen.js` (docx generation via pptxgenjs/docx)
- ClamAV binaries at `backend/bin/clamav/`
- Velociraptor binary at `backend/bin/velociraptor.exe` (Windows)
- Grype/Syft binaries at `backend/bin/`

## Architecture Decisions (DO NOT CHANGE)
- PostgreSQL stays in existing `orca-postgres` Docker container — do not recreate it
- Backend must remain Windows-compatible for local Velociraptor execution
- TLS is required — self-signed cert must be used
- Frontend is served separately (Vite dev server or nginx)
- **Fully portable, no hardcoded IPs (as of 2026-06-18)**: frontend builds with `VITE_API_URL` empty, so all `fetch()` calls resolve to relative `/api/...` paths against whatever host served the page; nginx proxies `/api/` to the backend by Docker service name (`orca-backend:8000`); CORS reads allowed origins from `CORS_ORIGINS` in `.env` (comma-separated, default `https://localhost`); TLS cert auto-generates on first boot for whatever IP/hostname the container has. Moving to a new server requires editing only `.env` (`CORS_ORIGINS`) and running `docker compose up --build` — no source changes.

## Current Task
**Fresh-clone install verified and pushed (2026-11-09). Awaiting next task.**
Fresh `git clone` + `install.ps1` (Windows PowerShell 5.1) tested from scratch in an isolated `orcatest` stack: build, Grype DB download, schema + seed + MITRE import, first-boot admin, login, real UI-path vuln scan (68 findings), clamav.zip, password change/session revocation, zero backend tracebacks. To re-run that test: clone to a temp dir, set `COMPOSE_PROJECT_NAME=orcatest` and `COMPOSE_FILE=docker-compose.yml;<override>` where the override sets different `container_name`s and `ports: !override ["8443:443","8080:80"]`, then run the installer with `-ServerAddress localhost`; tear down with `docker compose down -v --rmi local`.
Not tested: agent-dispatched collection end-to-end (no agent online); frontend session-revocation redirect in a real browser (API side verified).

## Progress Log
- [x] Server-side session revocation (2026-11-09):
  - Problem found in testing: auth was JWT-only, so deactivation / password change / reset / role change didn't affect already-issued sessions (up to 60 min)
  - `migrations/add_users_token_version.sql` (applied live): `users.token_version`. Login JWT carries it as `tv`
  - `auth_utils.get_current_user`: for non-agent tokens, re-reads the users row every request (`run_in_threadpool`); 401 `SESSION_REVOKED` if missing / inactive / `tv` mismatch; role/initials/username taken from DB. Tokens without `tv` = version 0, so pre-upgrade sessions survive the deploy. Agent tokens (`role: agent`, no user id) are skipped, still limited to `/api/agent/*`
  - Bumps: change-password (re-issues the caller's cookie via `main._issue_session_cookie`), completed reset, deactivation (so reactivation doesn't revive old sessions)
  - Frontend `AuthContext.jsx`: global `fetch` wrapper logs out on 401 with detail `SESSION_REVOKED` / `Could not validate credentials` (not on other 401s like `CURRENT_PASSWORD_INCORRECT`); `MyAccount` restarts the expiry timer after a password change
  - Verified 19 API scenarios live; frontend wrapper builds but was not exercised in a browser
- Also fixed (same session): Grype DB created 0700 by root-run `grype db update` (installers now `chmod -R a+rX`); backend always sets `GRYPE_DB_AUTO_UPDATE=false`/`GRYPE_DB_VALIDATE_AGE=false` (UI scans failed once the read-only DB was >5 days old); agent bundle zips (`_DIR_BUNDLES` in `agent_routes.py`) now streamed via `FileResponse`, built in a threadpool under a per-bundle lock, rebuilt when sources change
- [x] Fresh-clone installability (2026-11-09):
  - `install.ps1` / `install.sh`: .env with random secrets + server address, build, Grype DB via `docker compose run ... grype db update`, start, print first-boot admin login. Use `docker compose logs` (service names), not container names
  - Committed `backend/data/mitre-attack.json` and ClamAV sigs; `.gitattributes` (LF for container files, CRLF for .bat/.ps1); `backend/initdb/02-seed-data.sh` loads `seed_data/` on fresh volumes; Postgres healthcheck over TCP (`-h 127.0.0.1`)
  - Backend image now includes Linux grype 0.117.0 / syft 1.51.0 (`ORCA_GRYPE_EXE`/`ORCA_SYFT_EXE`); in-container vuln scan previously had no Linux binary at all
  - `DEPLOY.md` rewritten around the installer; README/ADMIN_GUIDE install sections updated; API docs fixed (login sets HttpOnly cookie, no `access_token` in body)
- [x] Commit backlog + docs refresh (2026-11-09):
  - Committed the uncommitted Sept/Nov work as 3 commits (account management; agent-dispatched collection; seed data). `backend/main.py` was split by hunk between the first two
  - `.gitignore`: added `backend/bin/syftgrype/grype-db/`. The 3.2 GB `vulnerability.db` can't go to GitHub; operators populate it (`GRYPE_DB_CACHE_DIR=backend/bin/syftgrype/grype-db grype db update`)
  - `docker-compose.yml`: bug fix: `SMTP_*` and `ORCA_BOOTSTRAP_ADMIN_*` were never passed through to `orca-backend`, so setting them in `.env` did nothing. Added passthroughs
  - `backend/schema.sql` regenerated (was stale since 2026-08-25: 52→57 tables, missing `users.email/is_active/last_login`, `enrollment_tokens`, `password_reset_tokens`, `file_fetch_jobs`, `vt_lookups`, `case_assignments`). A fresh install would have failed at login (login selects `is_active`). Verified: schema + all `seed_data/*.sql` load cleanly into a throwaway `postgres:15`
  - Docs: README (features, first-run), ADMIN_GUIDE (DB init rewritten for auto-schema + seed + bootstrap admin, user management, Grype DB, SMTP env vars), USER_GUIDE (enrollment/reset, My Account, RUN ON AGENT), API_REFERENCE (new auth/admin endpoints, `agent_id` on `/api/assets/execute`, `clamav.zip`/`grype-db.zip`)
- [x] Agent-dispatched collection + agent hardening (2026-11-04 → 11-06, commit `6436745`):
  - `main.py` `run_vr_via_agent()`: `/api/assets/execute` takes optional `agent_id`; each technique is dispatched as an `artifact_collection` agent job (300s timeout), rows streamed back, ingested server-side into `evidence`/`artifact_results`
  - `agent/orca_agent.py`: `artifact_collection` job type (VQL with EVTX source conversion + fallback VQL); downloads/extracts `clamav.zip` and `grype-db.zip`
  - `agent_routes.py`: serves `clamav.zip` (whole Windows ClamAV dir; standalone `clamscan.exe` removed, it can't run without its DLLs/sigs) and `grype-db.zip`, both cached in container temp
  - `config.py` `GRYPE_DB_DIR`; vuln scan sets `GRYPE_DB_CACHE_DIR`, and when offline disables auto-update + age validation (grype refuses to run on a >5-day-old DB otherwise)
  - `backend/Dockerfile`: `freshclam` at build time (non-fatal)
  - Mount wait 120s → 900s for large images
  - `agent/install.bat`: explicit `python.exe` discovery, config written via `%~dp0`, installs `requests` from `agent/vendor/` wheels (offline), URL hint no longer suggests `:8000`
  - `EvidenceWindow.jsx`: DRIVE input + "RUN (IN-CONTAINER)" / agent picker + "RUN ON AGENT"
  - Added Arsenal `DriverSetup/`, `deviodrv.sys`, `deviosvc.exe`
- [x] User account management (2026-09-03, commit `89f58c5`):
  - `migrations/add_user_account_management.sql` (applied to live `orca_db`): `users.email/is_active/last_login`, `enrollment_tokens` (7-day), `password_reset_tokens` (1-hour)
  - Admin: `/api/admin/users/invite`, `PATCH /users/{u}`, `/users/{u}/reset-password`, `/users/{u}/toggle-active`. Self: `PATCH /api/auth/me`, `/api/auth/change-password`, `/api/auth/enroll/{token}`, `/api/auth/forgot-password` (works only with SMTP; generic response, no enumeration), `/api/auth/reset-password/{token}`
  - Login: `403 ACCOUNT_DEACTIVATED` only after a correct password; updates `last_login`
  - `backend/email_utils.py`: optional SMTP; with no `SMTP_HOST`, links are shown in the admin UI for hand-off (air-gapped). Links are built from `ORCA_SERVER_URL`
  - Frontend: `auth/EnrollmentPage.jsx`, `auth/ResetPasswordPage.jsx` (routed by pathname in `main.jsx`), `Options/MyAccount.jsx`, reworked `UserManagement.jsx` and `LoginScreen.jsx` (forgot-password mode)
- [x] 2026-08-18 → 2026-09-02 (committed, see `git log d75dc95..5ef2a7a` for details): noexec tmpfs for behavioral samples; evidence-deletion audit trail; full-codebase audit fixes; vendored all tool binaries + Font Awesome + MITRE STIX import for air-gapped; first-boot admin bootstrap (`bootstrap_admin.py`); `schema.sql` auto-applied on fresh Postgres volume; configurable remote staging dir; WinRM transport, evidence starring, IOC editing; agent-based disk mounting; SMB push delivery of packages (then WinRM push); TLS SAN/validity fixes; custom technique create/delete in Artifact Library Editor; per-technique collection monitoring + parallel workers; SSH injection hardening; situational-awareness file browser + VirusTotal lookup/re-check, flagged files, live file pull; full-MFT ingest fix, collection throttling, WinRM auto-enable/disable (only touches state it can confirm), cross-analyst progress visibility
- [x] Documentation (2026-07-14):
  - Read entire codebase (all backend routes, frontend components, DB schema, Docker/nginx/entrypoint config)
  - Generated `README.md` (project root) — feature summary, architecture diagram, tech stack table, quick start, air-gapped deployment, prerequisites, screenshots placeholder
  - Generated `docs/USER_GUIDE.md` — full analyst usage: cases/assets, investigation config, remote deployment, evidence window, MITRE ATT&CK/verdict workflow, memory forensics, ClamAV, Grype, disk mount, IOC, reports, Tools menu, Options menu
  - Generated `docs/ADMIN_GUIDE.md` — full deployment walkthrough, air-gapped install, env var reference, TLS management, DB backup/restore, updating, user management, troubleshooting (all known deployment issues documented)
  - Generated `docs/API_REFERENCE.md` — all backend API endpoints grouped by route file with request/response shapes
  - Updated `CLAUDE.md` current task
- [x] Remote collection trigger — switch default from WinRM to SMB+Task Scheduler (2026-06-18):
  - Reason: target environment does not have WinRM (port 5985) enabled and it's not under our administrative control to enable; SMB+Task Scheduler needs only port 445 + admin credentials — the same prerequisites the original psexec path had, so no new target-side configuration is needed
  - `backend/vr_remote.py`: the single WinRM-only `run_remote_command()` from the prior pass was split into a thin dispatcher plus two private implementations: `_run_remote_command_smb_task()` (new — impacket `dcerpc.v5.tsch`/`transport` over `ncacn_np:{ip}[\pipe\atsvc]`; registers a throwaway scheduled task running `cmd.exe /c <command>`, calls `hSchRpcRun` to trigger it, sleeps 2s, then best-effort `hSchRpcDelete`s the task registration — fire-and-forget because `hSchRpcRun` only dispatches and returns without waiting for the spawned process to exit, and deleting the task registration afterward does not affect the already-launched process) and `_run_remote_command_winrm()` (the prior pass's here-string + `Start-Process` logic, unchanged, now opt-in only). `run_remote_command(..., transport="SMB_TASK")` dispatches on the new `transport` param (`"SMB_TASK"` default, `"WINRM"` opt-in), both returning the same `(returncode, stdout, stderr)` shape
  - `backend/deploy_routes.py`: `_run_remote_trigger()` gained a `transport` param threaded through to `vr_remote.run_remote_command()`; `_deploy_single()` and `/triage`'s `run_one()` accept/forward it and use it to pick user-facing labels ("SMB/Task Scheduler" vs "WinRM") and port hints in error messages; `DeployRequest.transport` and the new `TriageRequest.trigger_transport` both default to `"SMB_TASK"` (the pre-existing `TriageRequest.transport` field, unused by `/triage`, was left alone rather than repurposed, to avoid colliding with its separate meaning on `/triage-execute`); auth/reach error-string matching expanded to cover both WinRM- and SMB_TASK-style failure text (`status_logon_failure`, `smb_task_timeout`, `rpc server is unavailable`, etc.)
  - `backend/agent_routes.py`: `DeployAgentRequest.transport` added (default `"SMB_TASK"`), forwarded to `vr_remote.run_remote_command()`; error matching expanded the same way. VR_EXE split and the analyst-scoped false-success registration check (both from the prior WinRM pass) were explicitly left untouched per user instruction
  - `backend/requirements.txt`: added `impacket==0.12.0`
  - Rebuilt `orca-backend` (`docker compose build orca-backend`) and recreated with `docker compose up -d --no-deps orca-backend` (same `--no-deps` requirement as before, to avoid compose touching the standalone `orca-postgres` container)
  - Verified: image build installed `impacket-0.12.0` cleanly; container logs show clean startup (TLS cert check → LibreOffice prewarm → `Application startup complete` → `Uvicorn running`) with no `ImportError`; `/api/deploy/bulk`, `/api/deploy/triage`, `/api/agent/deploy` all present in the live OpenAPI schema; remaining `psexec.exe` references (`_get_psexec_path()`/`/psexec-status` informational endpoints, `vr_remote.py`'s `_collect_smb_psexec()`) confirmed confined to the unrelated `/triage-execute` artifact-transport and status-check code, none in the bulk-deploy/triage/agent-deploy trigger path
- [x] Remote collection fix — Phase 2 / Option A implementation (2026-06-18):
  - Implements the recommendation from `COLLECTION_AUDIT.md` (Phase 1 diagnosis below) per explicit user instruction "lets just do Option A"
  - `backend/config.py`: split dual-purpose `cfg.VR_EXE` into `VR_EXE_WINDOWS` (binary pushed to/run on remote Windows targets) and `VR_EXE_LOCAL` (binary run inside the container itself) — updated all 9 call sites across `package_builder.py`, `velociraptor_manager.py`, `routes/mitre_routes.py`, `deploy_routes.py`, `main.py`
  - `backend/vr_remote.py`: added `run_remote_command(ip, username, password, domain, command, timeout=60)` — a WinRM-based (`pywinrm`) replacement for the psexec trigger. Fire-and-forget: `command` is embedded in a PowerShell here-string (no quote-escaping needed) and launched via `Start-Process` (no `-Wait`), so the WinRM call returns as soon as the remote process is launched rather than blocking for the full collection duration — mirrors psexec's old `-d` ("don't wait") semantics, since `package_builder.py`'s bootstrap chain runs synchronously once started and could otherwise exceed any reasonable WinRM timeout
  - `backend/deploy_routes.py`: `_run_psexec()` replaced with `_run_remote_trigger()` → `vr_remote.run_remote_command()`; `_deploy_single()` and `/triage`'s `run_one()` now use WinRM; `DeployRequest`/`TriageRequest` carry `domain: Optional[str]`; removed the `psexec.exe`-exists 503 gate from `/bulk`; non-zero remote-trigger exit codes now hard-fail (`ERROR` emit) instead of being logged as a warning and silently continuing — this silent-continue was the original root cause of "200 OK but nothing collects"
  - `backend/agent_routes.py`: `/api/agent/deploy`'s psexec subprocess replaced with `vr_remote.run_remote_command()`; added `domain` field to `DeployAgentRequest`; fixed the false-success scoping bug — the post-deploy registration check now filters `WHERE analyst_id = :analyst_id` (the deploying user) instead of matching any agent that checked in within the last 60s globally
  - `backend/requirements.txt`: added `pywinrm==0.4.3`
  - Rebuilt `orca-backend` image (`docker compose build orca-backend`) and recreated the container with `docker compose up -d --no-deps orca-backend` (`--no-deps` used deliberately to avoid compose touching `orca-postgres`, which is a pre-existing standalone container outside compose's lifecycle — see Architecture Decisions)
  - Verified: container starts clean (no `ImportError` from the new `pywinrm` import), `/api/deploy/bulk`, `/api/deploy/triage`, and `/api/agent/deploy` all present in the live OpenAPI schema, no remaining references to `psexec.exe`/`_run_psexec` in the trigger path (only the informational `/psexec-status` endpoints and the still-valid `SMB_PSEXEC` transport option for the separate triage-execute feature remain, both unrelated to this fix)
  - Not in scope / left as-is: `impacket` and `paramiko` are still not installed, so the `SMB_TASK` and `SSH` transport options on the triage-execute feature remain non-functional if selected (pre-existing, noted in `COLLECTION_AUDIT.md`, not part of Option A); `main.py`'s `/api/assets/remote-execute` route still calls a non-existent `vr_remote.run_remote_collection` (pre-existing dead code, unrelated to the reported bug)
- [x] Remote collection diagnosis — Phase 1 (2026-06-18):
  - Symptom: `POST /api/deploy/bulk` ("Deploy to Host") returns 200 but never actually collects, since containerization
  - Root cause #1: `deploy_routes.py`, `agent_routes.py`'s `/deploy`, and `vr_remote.py`'s `_collect_smb_psexec` all shell out to `bin/psexec.exe` (a Windows PE) directly from the Linux container — fails consistently under Docker Desktop/WSL2 interop (`UtilGetPpid` errors), returns a non-zero return code that's logged as a warning and swallowed rather than treated as fatal
  - Root cause #2: `cfg.VR_EXE` (`backend/config.py`) picks the binary extension from the *container's* `platform.system()` (Linux) instead of the *target's* OS, so `package_builder.py` silently fails to bundle `velociraptor.exe` into the deployed ZIP even when delivery works
  - Secondary bug found: `agent_routes.py`'s `/api/agent/deploy` post-deploy "success" check polls for *any* `agent_registrations` row with a recent heartbeat, not scoped to the IP being deployed — can report false `SUCCESS`
  - Confirmed already container-safe and reusable: `vr_remote.py`'s `WINRM` and `SMB_TASK` transports (pure-Python `pywinrm`/`impacket`, no local Windows exec) — currently only wired to the separate `/api/deploy/triage-execute` feature, not to bulk MITRE-technique collection
  - Full findings + 3 proposed Phase-2 architectures (A: swap psexec for WinRM/SMB-Task trigger [recommended]; B: make the persistent agent the primary mechanism; C: host-side Windows helper process) written to `COLLECTION_AUDIT.md`
  - **No code changed in Phase 1** — diagnosis only, per explicit user instruction
- [x] Containerization (Steps 1-7): all Docker artifacts built and running
- [x] Detection Coverage tool:
  - `ref_artifact_library.updated_at` column added (ALTER TABLE + backfill)
  - `backend/routes/mitre_routes.py` library update endpoint now sets `updated_at = NOW()`
  - `backend/routes/coverage_routes.py` — `GET /api/coverage` returns countries + custom profiles with per-tcode VQL/YAML/updated_at status
  - Registered in `backend/main.py`
  - `frontend/src/components/Tools/DetectionCoverage.jsx` — summary tiles, sortable list, stacked coverage bars, expandable T-code tables with VQL/YAML/date columns, search filters
  - `frontend/src/App.jsx` — DetectionCoverage import + render case wired in
- [x] Investigation Profile Manager:
  - DB table `investigation_profiles` created in orca_db
  - `backend/routes/profile_routes.py` — CRUD endpoints at `/api/profiles` + `/api/profiles/tcodes/available`
  - Registered in `backend/main.py` via `from routes import ... profile_routes`
  - `frontend/src/components/Tools/InvestigationProfileManager.jsx` — full CRUD UI with T-code picker
  - `frontend/src/App.jsx` — added 'Investigation Profiles' to Tools submenu
  - `frontend/src/components/investigations/InvestigationWorkspace.jsx` — fetches profiles, passes as prop
  - `frontend/src/components/investigations/InvestigationGallery.jsx` — profiles appear in GEOPOLITICAL_FOCUS dropdown under "CUSTOM PROFILES" optgroup; profile selection populates T-codes directly; country logic unchanged
- [x] Codebase Audit — `AUDIT_REPORT.md` written to project root (2026-06-10)
  - 4 Critical, 7 Warning, 9 Info findings
  - All findings fixed (2026-06-10): getAuth bug, HTTP report export, duplicate VR router, dead code, LEAD field mismatch, DB password, JWT secret, frontend .env, binary platform detection, freshclam, npm errors, .dockerignore, alert() calls, .env.example
- [x] TLS Configuration & Certificate Manager (2026-06-10):
  - `backend/routes/network_routes.py` — `GET /api/network/cert-info`, `GET /api/network/detected-identity`, `POST /api/network/regenerate-cert` (admin only; runs openssl, restarts backend via os.execv after 2s)
  - `backend/entrypoint.sh` — auto-generates ECDSA P-256 self-signed cert on first boot if none exists
  - `backend/Dockerfile` — added `openssl` to apt-get
  - `backend/main.py` — registered `network_routes`; uvicorn startup uses explicit SSLContext with `minimum_version = TLSVersion.TLSv1_2`
  - `frontend/nginx.conf` — port 80 → 301 HTTPS redirect; port 443 SSL with TLSv1.2/1.3 + HIGH ciphers
  - `frontend/nginx-entrypoint.sh` — waits for cert to appear in shared volume, starts nginx, watches cert file and calls `nginx -s reload` on change
  - `frontend/Dockerfile` — added `nginx-entrypoint.sh`, exposed port 443
  - `docker-compose.yml` — added `orca-certs` named volume shared between backend (`/app/certs`) and frontend (`/etc/nginx/certs:ro`); frontend ports 80+443; removed individual cert bind mounts
  - `frontend/src/components/Options/NetworkSettings.jsx` — NEW: shows cert expiry/SANs/key type, detects server IP/hostname, admin-only "Regenerate Certificate" with confirm modal and service restart warning
  - `frontend/src/App.jsx` — Options > Network now renders `<NetworkSettings />`
  - Root `.env` + `frontend/.env` — `VITE_API_URL` updated from `http://` to `https://10.11.110.60`

- [x] Global Text Brightness Slider (2026-06-10):
  - `frontend/index.html` — inline anti-flash script in `<head>` reads `orca-text-brightness` from localStorage and sets `--text-brightness` on `:root` before first paint
  - `frontend/src/index.css` — added `:root { --text-brightness: 1; }` as first rule
  - `frontend/src/App.jsx` — root div gains `filter: brightness(var(--text-brightness))`; imported + wired `<GeneralSettings />` for Options > General
  - `frontend/src/components/Options/GeneralSettings.jsx` — NEW: "Text Clarity" slider (0.6–1.4, step 0.01), live update via `document.documentElement.style.setProperty`, persists to `orca-text-brightness`, reset button with hover effect

- [x] Security hardening — Critical + High findings from final.md (2026-06-12):
  - C1: shell=True removed from run_technique.py (5 calls) and mitre_routes.py — arg lists + artifact_name validation
  - C2: JWT_SECRET fallback removed — hard fail at startup if not set
  - C3: DB password moved to .env as ${DB_PASSWORD} — docker-compose.yml no longer hardcodes it
  - C4: CORS allow_origins changed from ["*"] to ["https://10.11.110.60"]
  - C5: report_export.py verify=False gone (file replaced with empty router); velociraptor_manager.py documented as intentional localhost-only
  - H1: Duplicate export handler deleted — report_export.py is now an empty APIRouter shim
  - H2: nginx security headers added (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CSP)
  - H3: PostgreSQL host port bindings removed from docker-compose.yml
  - H4: proxy_ssl_verify enabled in nginx.conf with trusted CA cert
  - H5: slowapi rate limiting added to login endpoint (5/minute)
  - H8: .gitignore created at project root; .env excluded

- [x] Medium findings from final.md (2026-06-12):
  - M1: Cert regeneration grace period increased from 2s → 5s; response now includes `restart_in_seconds`
  - M2: JWT expiry reduced from 480 min (8h) → 60 min
  - M3: `config.py` validates DATABASE_URL, TLS_CERT_PATH, TLS_KEY_PATH at startup; fails hard if missing
  - M4: `report_routes.py` export handler wrapped in try/finally — temp dirs always cleaned up; switched to StreamingResponse (reads bytes before cleanup)
  - M5: `entrypoint.sh` pre-warms LibreOffice on container start — eliminates cold-start PDF latency
  - M6: Frontend Dockerfile updated from `node:18-alpine` → `node:20-alpine`
  - M7: Unused `pct` variable deleted from `GeneralSettings.jsx`

- [x] Full portability — no hardcoded IPs (2026-06-18):
  - Reason: moving ORCA off the fixed build machine (`10.11.110.60`) to a new system with a different IP; previously required a frontend rebuild + multiple file edits every time the server IP changed
  - Root `.env` + `frontend/.env`: `VITE_API_URL` cleared (empty) instead of a hardcoded IP; added `CORS_ORIGINS=https://localhost` (set per-deployment)
  - `frontend/Dockerfile`: `ARG VITE_API_URL` default cleared
  - `frontend/vite.config.js`: dev-only proxy fallback changed from hardcoded IP to `https://localhost:8000` (production build unaffected)
  - `frontend/nginx.conf`: CSP `connect-src` changed from `'self' https://10.11.110.60` to just `'self'` (API calls are now same-origin relative requests)
  - `backend/main.py`: CORS `allow_origins` now reads from `CORS_ORIGINS` env var (comma-separated, default `https://localhost`) instead of the hardcoded IP — preserves the restrictive C4 security fix while making the value deployment-specific
  - `docker-compose.yml`: added `name: orcaweb` at top level; `orca-backend.environment` now passes through `CORS_ORIGINS`
  - `frontend/src/components/VelociraptorModal.jsx`: GUI link hostname now derived from `window.location.hostname` instead of parsing `VITE_API_URL` (which is now empty)
  - `frontend/src/components/AgentDeployModal.jsx`: manual-install command (meant to run on a remote target workstation, so it needs a real absolute URL) now uses `window.location.origin` instead of the empty `VITE_API_URL`
  - All other 16 frontend files using `` `${import.meta.env.VITE_API_URL}/api/...` `` needed no changes — they collapse naturally to relative `/api/...` paths
  - Confirmed already-portable before this change and left untouched: nginx proxies `/api/` to `orca-backend:8000` by Docker service name; backend already binds `uvicorn host="0.0.0.0"`; `backend/entrypoint.sh` already auto-generates the TLS cert on first boot for whatever IP/hostname the container has; `ORCA_SERVER_URL` / `backend/agent_routes.py`'s `_get_orca_base_url()` intentionally stays IP-aware (with an auto-detect fallback) since it's used to build Velociraptor agent packages that must reach the server from other machines
  - New deployment procedure: set `CORS_ORIGINS` (and optionally `ORCA_SERVER_URL`) in root `.env` to match the new host, then `docker compose down` + `docker compose up --build` — no source edits needed
  - Bug fix found during verification: `backend/main.py`'s `/api/auth/login` caught its own deliberately-raised `HTTPException(401)` in a broad `except Exception` and rewrapped it as a 500 — bad credentials returned 500 instead of 401. Fixed by re-raising `HTTPException` before the generic catch-all.

## Last Completed Step
Commit backlog + docs refresh (2026-11-09). See Progress Log.

### Earlier: remote collection pipeline end-to-end verified (2026-07-27)
Remote collection pipeline end-to-end verified working (2026-07-27). Three root-cause fixes applied:
1. `orca-postgres` container had exited (exit 255, ~17 hours); `docker start orca-postgres` restored it.
2. Docker Desktop port forwarding for `orca-frontend` was stale after the backend's crash-loop restart cycles; `docker restart orca-frontend` restored port 443/80 forwarding. **This can recur — if port 443 is unreachable externally, restart the frontend container.**
3. `ORCA_SERVER_URL` was `https://192.168.16.1` (VMware VMnet8 gateway IP — completely unreachable from the VM because VMware's virtual switch does not forward L2 traffic from VMs to the host's own VMnet8 interface IP); changed to `https://10.11.110.60` (the host's main Ethernet IP, reachable via VMware NAT hairpin). Set in `.env` and picked up by `docker compose up -d --no-deps orca-backend`.
Also: `vmnetnat.conf` `resetConnectionOnDestLocalHost` changed from 1 → 0 (allows VM→host TCP on NAT daemon IP 192.168.16.2; effect on main Ethernet IP reachability is indirect); Docker Desktop Backend Block-TCP-Public firewall rules disabled (were blocking VMnet8 traffic before the `ORCA_SERVER_URL` fix made them irrelevant). The ORCA Allow-port-443 firewall rule added earlier remains in place.

## Decisions Made
- `requirements.txt` generated from backend imports: fastapi, uvicorn, sqlalchemy, pydantic, python-jose, passlib, psycopg2-binary, python-multipart, pyyaml, pandas, httpx, aiofiles, python-dotenv
- `backend/package.json` created with `docx` and `sharp` (dependencies of report_gen.js)
- Frontend hardcoded IP replaced with `import.meta.env.VITE_API_URL` across 17 files (now empty by default — see 2026-06-18 portability entry); VelociraptorModal uses `window.location.hostname` for dynamic-port Velociraptor GUI link
- `config.py` updated to accept `DATABASE_URL`, `TLS_CERT_PATH`, `TLS_KEY_PATH` env vars (with ORCA_* fallbacks for backwards compatibility)
- `auth_utils.py` JWT secret now reads from `JWT_SECRET` env var
- `docker-compose.yml` includes postgres service for fresh deployments; existing-container scenario documented in file comments and DEPLOY.md
- `VITE_API_URL` is left empty by default so the frontend uses relative `/api` paths; only set it if proxying to a non-same-origin backend
- `frontend/src/components/investigations/Usecollaboration.js` renamed to `useCollaboration.js` — Windows is case-insensitive but Linux Docker build is not; import was `from './useCollaboration'`
- Remote collection trigger defaults to SMB+Task Scheduler (impacket), not psexec or WinRM — `backend/requirements.txt` includes `impacket==0.12.0` and `pywinrm==0.4.3`; targets need only SMB (port 445) + admin credentials by default for `/api/deploy/bulk`, `/api/deploy/triage`, and `/api/agent/deploy` to work. WinRM (port 5985) remains available as an opt-in fallback via the `transport`/`trigger_transport` request fields (`"WINRM"`), for environments where WinRM is already enabled

## Known Issues / Constraints
- Velociraptor .exe is Windows-only — Linux container should still include it for remote collection orchestration (the .exe runs on remote Windows endpoints, not the server)
- ClamAV has a Linux package (clamav) — use that instead of the Windows binaries
- Node.js must be in the same container as Python backend (report_gen.js subprocess)
- TLS cert is auto-generated by `backend/entrypoint.sh` on first boot into the `orca-certs` Docker volume — no manual cert files needed
- `AUDIT_REPORT.md` findings were fixed 2026-06-10, and a later full-codebase audit was fixed in commit `f6e6d16` (2026-08-20)
- `impacket`, `pywinrm` and `paramiko` are all installed; all `vr_remote.py` transports (WINRM, SMB_TASK, SMB_PSEXEC, SSH) are importable
- `backend/bin/syftgrype/grype-db/` (~3 GB) is gitignored. A fresh clone has no Grype DB, so vuln scans fail until it's populated (see ADMIN_GUIDE)
- `.claude/settings.local.json` is tracked in git (since the initial commit) and contains old test-login passwords in its allowed-command list. Not changed; user to decide whether to untrack it / rotate those passwords
- Git Bash on this machine rewrites `/app/...` args to Windows paths for `docker exec`; use `MSYS_NO_PATHCONV=1`, and relative paths for curl cookie jars
- `backend/schema.sql` must be regenerated after every schema change (`docker exec orca-postgres pg_dump -U postgres -d orca_db --schema-only --no-owner --no-privileges > backend/schema.sql`), since fresh installs are built from it
- If port 443 stops answering externally after backend restarts, `docker restart orca-frontend` (Docker Desktop port-forward goes stale)
