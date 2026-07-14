# ORCA Production Readiness Review
**Date:** 2026-06-10  
**Scope:** Full codebase audit — security, conflicts, bloat, deployment

---

## CRITICAL — Block Production

### C1 · Command Injection via `shell=True`
**Files:** `backend/run_technique.py` (lines ~173, 194, 210, 227, 240), `backend/routes/mitre_routes.py` (~line 1086)  
**Issue:** Subprocess calls use `shell=True` with f-string commands that include `artifact_name`. That value is extracted from user-supplied YAML with a naive `.split()` — no sanitisation. Semicolons, pipes, backticks, `$()` in an artifact name means arbitrary command execution on the host.
```python
# CURRENT — dangerous
cmd = f'"{vr_exe}" artifacts collect "{artifact_name}" --format jsonl'
subprocess.run(cmd, shell=True, ...)

# FIX — use argument list, no shell
subprocess.run([vr_exe, "artifacts", "collect", artifact_name, "--format", "jsonl"], ...)
```
**Fix every `shell=True` call.** Validate `artifact_name` is `[A-Za-z0-9._/-]` only before use.

---

### C2 · Hardcoded JWT Secret Fallback
**File:** `backend/auth_utils.py` line 10  
```python
SECRET_KEY = os.environ.get("JWT_SECRET", "SUPER_SECRET_ORCA_KEY_CHANGE_ME_LATER")
```
If `JWT_SECRET` is not set in the environment, the application silently uses a known string. Anyone aware of this default can forge valid JWTs and impersonate any user including admins.  
**Fix:** Remove the fallback entirely. Fail hard at startup if `JWT_SECRET` is missing.
```python
SECRET_KEY = os.environ.get("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("FATAL: JWT_SECRET environment variable is not set")
```

---

### C3 · Hardcoded Database Password
**File:** `docker-compose.yml` lines 11, 46–49  
```yaml
DATABASE_URL=postgresql://postgres:password@orca-postgres:5432/orca_db
POSTGRES_PASSWORD=password
```
Weak credential, committed to version control, in plain text. Anyone with repo access has the DB password.  
**Fix:** Move to `.env` file (not committed), use a strong random password, reference via `${DB_PASSWORD}` in compose.

---

### C4 · Open CORS Policy
**File:** `backend/main.py` lines ~30–35  
```python
CORSMiddleware(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
```
Accepts cross-origin requests from any domain. Since auth tokens are in `localStorage` (not HttpOnly cookies), a malicious page that tricks an analyst into visiting it can make authenticated API calls.  
**Fix:** Lock to the specific frontend origin(s):
```python
allow_origins=["https://10.11.110.60", "https://your-domain"]
```

---

### C5 · SSL Verification Disabled in Internal HTTP Calls
**Files:** `backend/report_export.py` line 31, `backend/velociraptor_manager.py` ~line 192, `backend/agent/orca_agent.py` multiple locations  
```python
httpx.AsyncClient(verify=False)
```
Disables certificate validation for internal HTTPS calls, allowing silent MITM. Even on an internal network this is avoidable — the self-signed cert is already available in the `orca-certs` volume.  
**Fix:** Pass the CA cert path to the client:
```python
httpx.AsyncClient(verify="/app/certs/orca.crt")
```

---

### C6 · Plaintext Tokens in localStorage
**File:** `frontend/src/context/AuthContext.jsx`  
```javascript
localStorage.setItem('orca_token', data.access_token)
```
`localStorage` is readable by any JavaScript on the page. An XSS vulnerability anywhere in the app would immediately yield the JWT.  
**Fix (full):** Switch to `HttpOnly; Secure; SameSite=Strict` cookies set by the backend on login. The frontend then makes credentialed requests without ever touching the token in JS.  
**Fix (minimal, if cookies aren't feasible):** Add `Content-Security-Policy` headers to severely restrict what JS can run (see C8 below), making XSS much harder to exploit.

---

## HIGH — Fix Before Launch

### H1 · Duplicate Export Endpoints (Dead Code + Conflict Risk)
**Files:** `backend/report_routes.py` (`POST /{case_name}/export`, router prefix `/api/reports`) and `backend/report_export.py` (`POST /api/reports/{case_name}/export`)  
Both register the identical URL. FastAPI uses `report_routes.py` because it is registered first in `main.py` (line 39 vs 41). `report_export.py`'s handler is **never called** but is maintained, creating a maintenance trap — future changes to `report_export.py` have no effect and will cause confusion.  
**Fix:** Delete the export handler from `report_export.py` (lines 71–128) or consolidate into a single file.

---

### H2 · No Security Headers on nginx
**File:** `frontend/nginx.conf`  
Missing headers that defend against clickjacking, MIME sniffing, and protocol downgrade:
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com;" always;
```
Add to the `server { listen 443 ssl; ... }` block.

---

### H3 · PostgreSQL Ports Exposed to Host
**File:** `docker-compose.yml` lines 52–54  
```yaml
ports:
  - "5432:5432"
  - "5433:5432"
```
Postgres is directly reachable from the host network. Only the backend service needs DB access, and they share a Docker network — no host port binding is needed.  
**Fix:** Remove both `ports` entries from `orca-postgres`. If local tooling (pgAdmin, psql) needs access, bind to `127.0.0.1` only: `127.0.0.1:5432:5432`.

---

### H4 · `nginx proxy_ssl_verify off`
**File:** `frontend/nginx.conf` line ~26  
nginx → backend proxy skips certificate validation. Makes the TLS between nginx and the backend meaningless.  
**Fix:** Mount the CA cert and verify:
```nginx
proxy_ssl_verify on;
proxy_ssl_trusted_certificate /etc/nginx/certs/orca.crt;
```

---

### H5 · No Rate Limiting on Login Endpoint
**File:** `backend/main.py` — `POST /api/auth/login`  
No brute-force protection. An attacker can try unlimited passwords with no throttle.  
**Fix:** Use `slowapi` (FastAPI rate limiting):
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, ...):
```

---

### H6 · Path Traversal in Artifact Result Paths
**File:** `backend/main.py` line ~239  
```python
output_root = os.path.join(DATA_ROOT, case_row.case_name.replace(" ", "_"), run_id)
```
`case_name` comes from the database, but if it ever contains `../` the output path escapes `DATA_ROOT`.  
**Fix:**
```python
safe_name = re.sub(r'[^A-Za-z0-9_\-]', '_', case_row.case_name)
output_root = os.path.join(DATA_ROOT, safe_name, run_id)
assert os.path.abspath(output_root).startswith(os.path.abspath(DATA_ROOT))
```

---

### H7 · Backend Image is 4.57 GB
**File:** `backend/Dockerfile`  
LibreOffice was added for PDF conversion. It inflates the image from ~400 MB to ~4.6 GB, dramatically increasing build time, push/pull time, and attack surface.  
**Options (choose one):**
- **Sidecar container:** run LibreOffice in a separate `gotenberg` or `unoconv` container; call it over HTTP. Keeps the backend image small.
- **On-demand install:** install LibreOffice only when PDF is first requested (not practical in Docker).
- **Accept the size** if deployment constraints allow it.  
Recommended: use [Gotenberg](https://gotenberg.dev/) as a sidecar — it handles docx-to-pdf via LibreOffice over a stable REST API and is maintained specifically for this purpose.

---

### H8 · `.env` Contains Real Secrets and Should Not Be Committed
**File:** `.env` (project root)  
The file contains the actual `JWT_SECRET` value. If this repository is or ever becomes accessible to others (git push, backup, transfer), the secret is compromised.  
**Fix:**
1. Add `.env` to `.gitignore` immediately
2. Use `.env.example` (no real values) for developer onboarding
3. If it has been committed, rotate `JWT_SECRET`

---

## MEDIUM — Fix Soon

### M1 · `os.execv` Backend Restart in Certificate Endpoint
**File:** `backend/routes/network_routes.py` lines ~121–122  
Regenerating a certificate causes the backend to restart itself with `os.execv`. Any in-flight requests are dropped. No graceful shutdown. In production under a process supervisor (systemd, Docker restart policy), this works — but it kills active analyst sessions without warning.  
**Fix:** Return a warning to the UI that a restart is happening, give a grace period (e.g. 5s), then restart. Or delegate restarts to the container orchestrator.

---

### M2 · Token Expiry Too Long
**File:** `backend/auth_utils.py` line ~12  
```python
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours
```
A stolen JWT is valid for 8 hours. Standard practice for sensitive tools is 15–60 minutes with silent refresh.  
**Fix:** Reduce to 60 minutes; add a refresh-token endpoint.

---

### M3 · No Startup Validation of Required Environment Variables
**File:** `backend/config.py`  
Missing env vars silently fall back to defaults (e.g. `JWT_SECRET`, `DATABASE_URL`). A misconfigured deployment starts, appears healthy, but uses wrong credentials.  
**Fix:** Add a startup check:
```python
REQUIRED = ["JWT_SECRET", "DATABASE_URL", "TLS_CERT_PATH", "TLS_KEY_PATH"]
for var in REQUIRED:
    if not os.environ.get(var):
        raise RuntimeError(f"Missing required env var: {var}")
```

---

### M4 · Temporary Files Not Cleaned on Error
**File:** `backend/report_routes.py` — `export_report` handler  
`tempfile.mkdtemp()` is used but there is no `finally` block or `shutil.rmtree` on error paths. Under load or repeated export failures, temp directories accumulate.  
**Fix:** Wrap the entire handler body in `try/finally: shutil.rmtree(tmp_dir, ignore_errors=True)`.

---

### M5 · LibreOffice First-Run Latency
**File:** `backend/report_routes.py`  
`soffice --headless` takes 5–15 seconds on cold start as LibreOffice initialises its user profile. Subsequent calls are faster but the first PDF export after container restart will appear to hang.  
**Fix:** Pre-warm LibreOffice at container startup (convert a trivial dummy file in `entrypoint.sh`) so the profile is already initialised when the first real request arrives.

---

### M6 · Node 18 Below Vite's Stated Minimum
**File:** `frontend/Dockerfile`  
Vite 7 logs: *"You are using Node.js 18.20.8. Vite requires Node.js version 20.19+ or 22.12+"*. Builds succeed today but may break on a future Vite patch.  
**Fix:** `FROM node:20-alpine AS builder`

---

### M7 · Unused Variable in GeneralSettings
**File:** `frontend/src/components/Options/GeneralSettings.jsx` line 21  
```javascript
const pct = Math.round(((brightness - 0.6) / 1.9) * 100);
```
Declared but never referenced. Dead code.  
**Fix:** Delete the line.

---

### M8 · `sys.path` Manipulation in main.py
**File:** `backend/main.py` lines ~18–19  
```python
sys.path.append(os.path.abspath(...))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
```
Fragile import resolution. Module loading order depends on path insertion order at runtime.  
**Fix:** Use a proper package layout with `__init__.py` files and relative imports; remove `sys.path` hacks.

---

## INFORMATIONAL

### I1 · No Health Check Endpoints
Neither backend nor Docker Compose defines health checks. Docker restart policy can't distinguish a crashed app from a slow one.  
**Add to backend:**
```python
@app.get("/api/health")
async def health():
    return {"status": "ok"}
```
**Add to docker-compose:**
```yaml
healthcheck:
  test: ["CMD", "curl", "-kf", "https://localhost:8000/api/health"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### I2 · No API Versioning
All routes are under `/api/...` with no version segment. Future breaking changes will require coordinated frontend+backend deployments with no migration path.  
**Recommendation:** Adopt `/api/v1/...` now before external consumers exist.

### I3 · TLS 1.2 Still Allowed
`ssl_protocols TLSv1.2 TLSv1.3` in nginx. TLS 1.2 is acceptable for now but is being sunset by major standards bodies. Consider restricting to TLS 1.3 only if all clients support it.

### I4 · ClamAV Signatures Updated at Container Start
`freshclam` runs in `entrypoint.sh` on every boot. On slow networks or outage this adds startup latency and may fail silently. For production, run freshclam on a schedule (cron/systemd timer) rather than at startup.

### I5 · Self-Signed Certificate — Browser Warnings
Users must click through a browser security warning on every new device/browser. For internal production use, integrate with an internal CA or use a subdomain with a trusted cert (Let's Encrypt via ACME). The cert management UI built in this project is a good foundation for this.

### I6 · Structured Logging Not Configured
`access_log=True` in uvicorn but log format is unstructured. For production observability, switch to JSON logging with correlation IDs, user identifiers, and request durations.

---

## Quick-Fix Checklist

| # | File | Action |
|---|------|--------|
| C1 | run_technique.py, mitre_routes.py | Replace `shell=True` + f-string with arg list |
| C2 | auth_utils.py | Remove JWT_SECRET default; fail hard |
| C3 | docker-compose.yml | Move DB password to `.env`; use strong value |
| C4 | main.py | Replace `allow_origins=["*"]` with specific origins |
| C5 | report_export.py, velociraptor_manager.py | Pass CA cert to `httpx.AsyncClient` |
| H1 | report_export.py | Delete duplicate export handler (lines 71–128) |
| H2 | nginx.conf | Add HSTS, X-Frame-Options, CSP, X-Content-Type-Options |
| H3 | docker-compose.yml | Remove postgres port bindings |
| H4 | nginx.conf | Enable `proxy_ssl_verify on` |
| H5 | main.py | Add `slowapi` rate limiting to `/api/auth/login` |
| H8 | .gitignore | Add `.env`; rotate JWT_SECRET |
| M3 | config.py | Add startup env var validation |
| M4 | report_routes.py | Wrap export handler in try/finally for temp cleanup |
| M5 | entrypoint.sh | Pre-warm LibreOffice on startup |
| M6 | frontend/Dockerfile | `FROM node:20-alpine` |
| M7 | GeneralSettings.jsx | Delete unused `pct` variable |
