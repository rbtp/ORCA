# ORCA Codebase Audit Report
**Date:** 2026-06-10  
**Scope:** Full codebase — backend routes, frontend components, DB schema, Docker/compose, env config  
**Method:** Static analysis + live DB schema query + container inspection  

---

## CRITICAL — Definitely Broken

### C1 · `getAuth()` ReferenceError on Asset Delete
**File:** `frontend/src/components/investigations/CaseDetail.jsx:177`  
**Evidence:**
```javascript
{ method: 'DELETE', headers: getAuth() }  // line 177
```
`CaseDetail.jsx` defines `getAuthHeaders()` (line 80) but calls `getAuth()` on line 177. `getAuth` is not imported and not defined in this file. Every other call in the file correctly uses `getAuthHeaders()`. The delete-asset flow will throw `ReferenceError: getAuth is not defined` as soon as an analyst clicks the ✕ DEL button on any asset.

---

### C2 · Report Export Self-Call Uses HTTP Against an HTTPS-Only Backend
**File:** `backend/report_export.py:28`  
**Evidence:**
```python
url = f"http://localhost:8000/api/reports/{case_name}"
```
The backend runs exclusively with TLS (`main.py:656-665`, `config.py:14-23`). The export endpoint makes an HTTP self-call to gather report data. An HTTP connection to a TLS-only listener is refused or returns a protocol error. Every DOCX/PDF export triggered from `ReportsView` will fail at this fetch step, producing a 500 response to the user. The fix is to either use the internal HTTPS URL (with cert verification disabled for localhost) or refactor to call the report-data function directly without an HTTP round-trip.

---

### C3 · Velociraptor Router Registered Twice
**File:** `backend/main.py:46-57`  
**Evidence:**
```python
# Line 46-47 — first registration (always succeeds if module exists)
from velociraptor_manager import router as velo_router
app.include_router(velo_router)

# Line 55-57 — second registration in try/except (redundant)
try:
    from velociraptor_manager import router as velo_router
    app.include_router(velo_router)
except Exception as e: ...
```
FastAPI registers all routes from a router when `include_router` is called. Calling it twice with the same router object registers every Velociraptor endpoint twice. This produces duplicate entries in the OpenAPI schema and can cause unexpected routing behavior. The `try/except` block was intended as a graceful fallback but fires on top of a successful first import.

---

### C4 · Non-Existent Backend Endpoint Referenced in Frontend
**File:** `frontend/src/App.jsx:66`  
**Evidence:**
```javascript
const response = await fetch(`${API_BASE}/run-scan`, { method: 'POST', ... });
```
No `POST /api/mitre/run-scan` endpoint exists in any backend route file (confirmed by grepping all files in `backend/routes/` and `backend/main.py`). The function `triggerIOCScan()` is never wired to any UI button (it's defined but not called), so this is currently dead code. However, the `isScanning` state, the function, and all surrounding code remain live in the bundle. If anyone wires a button to it the call will 404.

---

## WARNING — May Cause Issues Under Certain Conditions

### W1 · Dashboard LEAD Field Always Blank (Field Name Mismatch)
**Files:** `backend/routes/mitre_routes.py:723` and `frontend/src/App.jsx:232`  
**Evidence:**
```python
# Backend returns camelCase:
{"name": r['name'], "missionLead": r['mission_lead'], ...}

# Dashboard reads snake_case:
<div>LEAD: {c.mission_lead}</div>   // App.jsx:232
```
The API returns `missionLead` but the dashboard widget reads `c.mission_lead`. JavaScript property access on a missing key returns `undefined`, so every case card on the Dashboard shows `LEAD:` with nothing after it. The `InvestigationWorkspace` path works correctly because it propagates the object directly from the same fetch; only the Dashboard widget is affected.

---

### W2 · Docker Compose PostgreSQL Password Mismatch
**File:** `docker-compose.yml:11,47`  
**Evidence:**
```yaml
orca-postgres:
  environment:
    - POSTGRES_PASSWORD=postgres       # container password

orca-backend:
  environment:
    - DATABASE_URL=postgresql://postgres:password@orca-postgres:5432/orca_db
    #                                        ^^^^^^^^ different password
```
A fresh deployment (`docker compose up`) creates the postgres container with password `postgres`, but the backend DATABASE_URL uses password `password`. The backend will fail to authenticate and crash-loop. The existing standalone `orca-postgres` container was created with `POSTGRES_PASSWORD=password`, which is why the current running instance works. If anyone runs a clean deployment or rebuilds the postgres service, the backend will fail to start. The `.env.example` uses `postgres` for consistency; the `docker-compose.yml` DATABASE_URL needs to match.

---

### W3 · JWT Secret Is the Placeholder Default
**Files:** `.env:1`, `docker-compose.yml:12`  
**Evidence:**
```
# .env
JWT_SECRET=orca-secret-change-me

# docker-compose.yml
JWT_SECRET=${JWT_SECRET:-orca-secret-change-me}   # same fallback
```
The JWT signing secret has never been rotated from the placeholder. Any token can be forged by anyone who knows the secret (it's the default in the codebase). There is a second hardcoded fallback in `backend/auth_utils.py` as well. For a forensic investigation platform handling sensitive case data, this is a meaningful exposure on any network-accessible deployment.

---

### W4 · `frontend/.env` Contains the Old Pre-Nginx Direct-to-Backend URL
**File:** `frontend/.env`  
**Evidence:**
```
VITE_API_URL=https://10.11.110.60:8000    # direct to TLS backend — wrong
VITE_BACKEND_URL=https://10.11.110.60:8000  # orphaned, never used in any component
```
Docker builds correctly use the root `.env` (`VITE_API_URL=http://10.11.110.60`) passed as a build arg, so production containers are fine. But any developer who runs `npm run build` or `npm run dev` from inside the `frontend/` directory directly uses `frontend/.env` instead, which points at the self-signed HTTPS backend. Browsers block XHR to self-signed endpoints even after manual cert acceptance — every API call silently fails. `VITE_BACKEND_URL` is completely unused (no component references it); it's a stale artifact from before the nginx migration.

---

### W5 · Windows-Only Binaries Cannot Execute Inside the Linux Backend Container
**Files:** `backend/config.py:40-55`, `docker-compose.yml:18`  
**Evidence:**
```python
VR_EXE  = os.path.join(_BASE, "bin", "velociraptor.exe")
SYFT_EXE = os.path.join(_BASE, "bin", "syftgrype", "syft.exe")
GRYPE_EXE = os.path.join(_BASE, "bin", "syftgrype", "grype.exe")
AIM_CLI  = os.path.join(_BASE, "bin", "arsenal", "aim_cli.exe")
```
```yaml
volumes:
  - ./backend/bin:/app/bin:ro    # Windows .exe files mounted into Linux container
```
Confirmed in the running container: `/app/bin/velociraptor.exe`, `/app/bin/syftgrype/syft.exe`, `/app/bin/syftgrype/grype.exe`, and `/app/bin/arsenal/aim_cli.exe` exist but are Windows PE binaries. The Linux container cannot execute them. Any backend operation that spawns these processes — Grype/Syft vulnerability scans, server-side Velociraptor queries, AIM disk mounting — will fail with `exec format error`. The `arsenal/` directory does contain a Linux `aim_cli` binary; its path just isn't used by default.

---

### W6 · `freshclam` Run at Docker Build Time (Stale Signatures + Slow Builds)
**File:** `backend/Dockerfile:19`  
**Evidence:**
```dockerfile
RUN mkdir -p /var/lib/clamav && freshclam || true
```
ClamAV signature updates are baked into the image at build time. Signatures are out of date from the moment the image is built. The `|| true` suppresses failures, so the build succeeds even if `freshclam` fails (e.g., no network, rate-limited). AV scan results will silently use stale signatures. The correct pattern for production is to run `freshclam` as a sidecar or scheduled daemon at container startup, not at build time.

---

### W7 · npm Errors Silently Swallowed in Backend Dockerfile
**File:** `backend/Dockerfile:15`  
**Evidence:**
```dockerfile
RUN npm install 2>/dev/null || true
```
Both stdout and stderr from `npm install` are discarded and the command always succeeds. If `package.json` is malformed, a dependency fails to install, or npm encounters a network error, the build continues silently. `report_gen.js` will then fail at runtime when the missing package is required. The `/dev/null` redirect should be removed; the `|| true` should at minimum be replaced with conditional logging.

---

## INFO — Minor Inconsistencies / Cleanup

### I1 · `triggerIOCScan` / `isScanning` Are Dead Code
**File:** `frontend/src/App.jsx:30,62-81`  
`isScanning` state and `triggerIOCScan()` function are defined but no component ever calls the function or reads the state. The `isScanning` variable occupies a React state slot unnecessarily.

---

### I2 · Options → General and Options → Network Are Unimplemented Stubs
**File:** `frontend/src/App.jsx:374`  
```javascript
activeOptionNav === 'User Management' ? <UserManagement /> : renderStaging(activeOptionNav.toUpperCase())
```
Both `General` and `Network` options in the Options menu render `SYSTEM_STAGING: GENERAL_MODULE_OFFLINE` / `NETWORK_MODULE_OFFLINE`. These are the only two nav items with no backing component. Intentional or incomplete — flagging for review.

---

### I3 · `VITE_BACKEND_URL` Is Defined But Never Consumed
**File:** `frontend/.env:2`  
`VITE_BACKEND_URL=https://10.11.110.60:8000` — no component in `frontend/src/**` references `import.meta.env.VITE_BACKEND_URL`. Stale from a prior migration iteration.

---

### I4 · CORS Policy Allows All Origins
**File:** `backend/main.py:30-35`  
```python
CORSMiddleware(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
```
Appropriate for development but should be restricted to the known frontend origin for any internet-facing deployment.

---

### I5 · Duplicate `case_name` / `name` Field Handling Is a Hidden Fragility
**Files:** `InvestigationWorkspace.jsx:113`, `InvestigationGallery.jsx:220`  
The backend returns `name` for cases; the frontend has defensive `|| name` fallbacks throughout. When these diverge (e.g., a new code path that only checks `case_name`), bugs appear silently. The Dashboard widget at `App.jsx:232` already demonstrates this — it reads `c.name` correctly for the case title but `c.mission_lead` (wrong) for the lead.

---

### I6 · `backend/Dockerfile` Has No `.dockerignore`
No `.dockerignore` exists in the `backend/` directory. The `COPY . .` line copies everything, including:
- `backend/.env` (if it exists with real secrets)
- `backend/__pycache__/`
- `.git` fragments that leak into the image
- All `bin/` `.exe` files (already mounted as a volume, making the COPY redundant for those)

A `.dockerignore` should exclude `.env`, `__pycache__`, `*.pyc`, `sandbox_*`, and `bin/` (since bin is volume-mounted).

---

### I7 · Notes v1 and v2 Endpoints Both Exist with No Deprecation Path
**File:** `backend/routes/mitre_routes.py`  
`GET/POST /cases/{case_name}/notes` (v1, lines ~1356) and `GET/POST /cases/{case_name}/notes/v2` (lines ~2428) both exist. The frontend uses v2. The v1 endpoints remain in the route table, adding surface area without purpose.

---

### I8 · `ArtifactLibraryEditor` Uses `alert()` for Error Feedback
**File:** `frontend/src/components/Tools/ArtifactLibraryEditor.jsx:83,87`  
```javascript
alert("CRITICAL_ERR: TECHNIQUE_DATA_UNREACHABLE");
alert("ERR: COMMIT_FAILED");
```
Browser `alert()` blocks the main thread and looks unprofessional. All other components in the codebase use inline error state. Minor but inconsistent.

---

### I9 · `backend/.env.example` Uses Different Password from Active `docker-compose.yml`
**File:** `backend/.env.example:1`  
```
DATABASE_URL=postgresql://postgres:postgres@orca-postgres:5432/orca_db
```
The `.env.example` uses password `postgres` but the active `docker-compose.yml` uses `password`. A new contributor following `.env.example` will also have a broken DB connection.

---

## DB Schema — All Tables Present
The agent's initial finding about missing tables was incorrect. All 47 tables referenced in backend code are confirmed present in `orca_db`:
`agent_jobs`, `agent_registrations`, `artifact_results`, `asset_evidence`, `assets`, `case_notes`, `cases`, `clam_results`, `discovered_iocs`, `evidence`, `investigation_profiles`, `ioc_scans`, `memory_results`, `mft_entries`, `mount_sessions`, `network_links`, `package_tokens`, `ref_artifact_library`, `ref_ioc_library`, `tcode_notes`, `threat_attribution`, `users`, `vuln_results`, and all MITRE reference tables.

---

## Summary

| Severity | # | Highlights |
|----------|---|-----------|
| CRITICAL | 4 | Asset delete crashes (ReferenceError), report export always fails (HTTP vs HTTPS), duplicate VR router, dead endpoint |
| WARNING  | 7 | DB password mismatch breaks fresh deploys, LEAD field blank on dashboard, weak JWT secret, stale frontend .env, Windows binaries can't run in Linux, stale AV sigs baked at build time, silent npm errors |
| INFO     | 9 | Dead code, unimplemented stubs, orphaned env vars, open CORS, no .dockerignore, dual notes API |

**Most impactful to fix first:**
1. **C1** — `getAuth()` bug breaks asset deletion right now
2. **C2** — Report export is broken for every user
3. **C3** — Duplicate router (1-line fix, no risk)
4. **W1** — Dashboard LEAD field (1-line field name fix)
5. **W2** — Fresh deploy DB password mismatch (blocks any new installation)
