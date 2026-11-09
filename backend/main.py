import os
import sys
import json
import logging
import subprocess
import asyncio
from datetime import datetime

# Confirmed live 2026-08-28: nothing in the app previously called
# logging.basicConfig(), so every module-level logger.info()/.warning() call
# across the whole backend was silently dropped in production (root logger
# defaults to WARNING) -- .info() calls disappeared entirely, only .warning()+
# ever reached the container's stdout. uvicorn's own request-access logging
# was unaffected since it configures its own loggers independently.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
from fastapi import FastAPI, HTTPException, BackgroundTasks, status, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import uvicorn
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional, Any, Union

# --- AUTH IMPORTS ---
from auth_utils import verify_password, create_access_token, get_current_user, hash_password
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from core.database_manager import db
from routes import mitre_routes, ioc, admin, profile_routes, coverage_routes, network_routes, behavioral_routes
import vr_remote
from agent_routes import router as agent_router, dispatch_and_wait
from config import cfg
from report_routes import router as report_router

app = FastAPI(title="ORCAWEB")


def _rate_limit_key(request: Request) -> str:
    # Every request arrives through nginx (see frontend/nginx.conf), which
    # sets X-Real-IP to the actual client address. slowapi's default
    # get_remote_address reads request.client.host directly -- behind the
    # proxy that's always nginx's own container IP, so every real client
    # collapsed into one shared rate-limit bucket: one user's failed logins
    # (or one attacker) could exhaust the "5/minute" limit for everyone at
    # once. Falls back to get_remote_address for direct/non-proxied requests.
    return request.headers.get("x-real-ip") or get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "https://localhost").split(",") if o.strip()]
if "*" in cors_origins:
    # allow_credentials=True + a literal wildcard origin makes Starlette
    # reflect any request's Origin header back with credentials allowed --
    # a full credentialed-CORS bypass letting any site make authenticated
    # requests as a logged-in user. Not the shipped default, but nothing
    # else stops an operator from setting this as a quick "just make CORS
    # work" fix -- fail loudly at startup instead of silently exposing it.
    raise RuntimeError(
        "FATAL: CORS_ORIGINS may not contain '*' because allow_credentials=True is set -- "
        "list the exact origin(s) that should be allowed instead (comma-separated)."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(admin.router)
app.include_router(agent_router)
app.include_router(report_router)
from report_export import export_router
app.include_router(export_router)
from ingest_routes import router as ingest_router
app.include_router(ingest_router)
from deploy_routes import router as deploy_router
app.include_router(deploy_router)
from velociraptor_manager import router as velo_router
app.include_router(velo_router)


@app.on_event("startup")
async def _auto_import_mitre_attack_data():
    # Air-gapped/fresh-install convenience: if an operator has dropped a
    # MITRE ATT&CK STIX bundle at cfg.MITRE_ATTACK_JSON (or pointed
    # ORCA_MITRE_ATTACK_JSON elsewhere), load it automatically the first
    # time the MITRE tables are empty. Never blocks/fails startup -- see
    # mitre_import.auto_import_if_empty's own error handling.
    from mitre_import import auto_import_if_empty
    await asyncio.get_event_loop().run_in_executor(
        None, auto_import_if_empty, db.engine, cfg.MITRE_ATTACK_JSON
    )


@app.on_event("startup")
async def _auto_bootstrap_first_admin():
    # A fresh database has zero rows in `users` and no seed data -- and the
    # only endpoint that creates one (admin.py's create_user) requires an
    # existing admin to call it, which is impossible on a truly fresh
    # install. Creates exactly one admin account the first time `users` is
    # found empty; never touches it again after that. See
    # bootstrap_admin.auto_bootstrap_if_empty's own error handling.
    from bootstrap_admin import auto_bootstrap_if_empty
    await asyncio.get_event_loop().run_in_executor(None, auto_bootstrap_if_empty, db.engine)


@app.on_event("startup")
async def _start_vt_worker():
    # Fire-and-forget background task, not awaited -- runs for the lifetime of
    # the process. No-ops immediately (logs once, returns) if VT_API_KEY isn't
    # configured, so this is always safe to start. See vt_worker.py.
    import vt_worker
    asyncio.create_task(vt_worker.run_forever())


VR_EXE_LOCAL   = cfg.VR_EXE_LOCAL    # executed in-container (run_technique.py against locally mounted evidence)
VR_EXE_WINDOWS = cfg.VR_EXE_WINDOWS  # pushed to / executed on remote Windows targets
DATA_ROOT = cfg.DATA_ROOT
SYFT_EXE  = cfg.SYFT_EXE
GRYPE_EXE = cfg.GRYPE_EXE


# --- MODELS ---
class LoginRequest(BaseModel):
    username: str
    password: str

class AssetActionRequest(BaseModel):
    action: str
    asset_id: Optional[Union[str, int]] = None
    tsource: Optional[str] = "C:/"
    # When set, collection runs on this agent (any drive letter it can see --
    # a locally attached physical disk, or anything it mounted via Arsenal)
    # instead of in-container. See run_vr_via_agent().
    agent_id: Optional[str] = None

class RemoteExecuteRequest(BaseModel):
    asset_id:        Union[str, int]
    ip:              str
    transport:       str
    username:        str
    password:        str
    domain:          Optional[str] = None
    tsource:         Optional[str] = "C:"
    cleanup:         Optional[bool] = True
    remap_mounted:   Optional[str] = None
    remap_original:  Optional[str] = "C"

class VulnScanRequest(BaseModel):
    asset_id:    Union[str, int]
    scan_path:   str
    offline:     Optional[bool] = False

class MountRequest(BaseModel):
    asset_id:     Union[str, int]
    agent_id:     str
    image_path:   str
    drive_letter: Optional[str] = None
    provider:     Optional[str] = "auto"
    readonly:     Optional[bool] = True

# --- AUTH ENDPOINTS ---
# Fixed dummy hash for the unknown-username timing-safety check below --
# computed once (bcrypt hashing is deliberately slow) rather than per request.
_DUMMY_PASSWORD_HASH = hash_password(os.urandom(16).hex())

@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, response: Response, login_data: LoginRequest):
    """Verifies user credentials and sets an HttpOnly session cookie."""
    try:
        with db.engine.connect() as conn:
            query = text("SELECT id, username, password_hash, initials, role, is_active FROM users WHERE username = :u")
            user_record = conn.execute(query, {"u": login_data.username}).fetchone()

        if not user_record:
            # Still pay bcrypt's verify cost against a fixed dummy hash so an
            # unknown username takes the same time to reject as a known
            # username with a wrong password -- otherwise this early return
            # is a reliable timing side-channel for enumerating valid
            # usernames even though the error body itself is identical.
            verify_password(login_data.password, _DUMMY_PASSWORD_HASH)
            raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

        db_id, db_username, db_password_hash, db_initials, db_role, db_is_active = user_record

        if not verify_password(login_data.password, db_password_hash):
            raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

        if not db_is_active:
            # Deliberately after the password check, not before -- an
            # attacker probing for deactivated-but-guessable accounts
            # shouldn't be able to distinguish "wrong password" from
            # "account disabled" without already knowing the password.
            raise HTTPException(status_code=403, detail="ACCOUNT_DEACTIVATED")

        from datetime import timedelta as _td
        import time as _time
        token_data = {"sub": db_username, "id": db_id, "role": db_role, "initials": db_initials}
        token = create_access_token(data=token_data)
        expires_at = int(_time.time()) + (60 * 60)  # 60-minute expiry in unix seconds

        with db.engine.begin() as conn:
            conn.execute(text("UPDATE users SET last_login = NOW() WHERE id = :id"), {"id": db_id})

        response.set_cookie(
            key="orca_token",
            value=token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=3600,
            path="/",
        )
        return {
            "user": {"username": db_username, "initials": db_initials, "role": db_role, "id": db_id},
            "expires_at": expires_at,
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[!] LOGIN_ERROR: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error during Authentication")


@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Returns the current user's profile from the validated session cookie,
    enriched with the fields that only live in the DB (the JWT itself is
    deliberately kept small -- email/last_login aren't worth re-issuing
    every token for)."""
    email, last_login = None, None
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT email, last_login FROM users WHERE id = :id"
        ), {"id": current_user["id"]}).fetchone()
        if row:
            email, last_login = row
    return {
        "user": {
            "username":   current_user["sub"],
            "role":       current_user["role"],
            "initials":   current_user["initials"],
            "id":         current_user["id"],
            "email":      email,
            "last_login": last_login.isoformat() if last_login else None,
        },
        "expires_at": current_user.get("exp"),
    }


class UpdateMeRequest(BaseModel):
    initials: Optional[str] = None
    email: Optional[str] = None


@app.patch("/api/auth/me")
async def update_me(body: UpdateMeRequest, current_user: dict = Depends(get_current_user)):
    """Self-service profile edit -- initials and email only. Role and
    username are admin-only (routes/admin.py), never self-service: a user
    escalating their own role, or an analyst becoming unrecognizable to
    the rest of the team by renaming themselves, are both things only an
    admin should be able to do."""
    fields, params = [], {"id": current_user["id"]}
    if body.initials is not None:
        initials = body.initials.strip().upper()
        if not initials or len(initials) > 5:
            raise HTTPException(status_code=400, detail="INITIALS_MUST_BE_1_TO_5_CHARS")
        fields.append("initials = :initials")
        params["initials"] = initials
    if body.email is not None:
        fields.append("email = :email")
        params["email"] = body.email.strip() or None
    if not fields:
        raise HTTPException(status_code=400, detail="NO_FIELDS_TO_UPDATE")

    with db.engine.begin() as conn:
        conn.execute(text(f"UPDATE users SET {', '.join(fields)} WHERE id = :id"), params)  # nosec B608 — fields built from a fixed allowlist above, values parameterized
    return {"status": "OK"}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/auth/change-password")
@limiter.limit("5/minute")
async def change_password(request: Request, body: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    """Self-service password change -- requires the current password,
    unlike an admin-initiated or token-based reset, since the caller is
    already proving who they are via an active session, not recovering
    access to one."""
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="PASSWORD_TOO_SHORT")

    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT password_hash FROM users WHERE id = :id"
        ), {"id": current_user["id"]}).fetchone()
    if not row or not verify_password(body.current_password, row[0]):
        raise HTTPException(status_code=401, detail="CURRENT_PASSWORD_INCORRECT")

    with db.engine.begin() as conn:
        conn.execute(text(
            "UPDATE users SET password_hash = :p WHERE id = :id"
        ), {"p": hash_password(body.new_password), "id": current_user["id"]})
    return {"status": "OK"}


@app.post("/api/auth/logout")
async def logout(response: Response):
    """Clears the session cookie."""
    response.delete_cookie(key="orca_token", httponly=True, secure=True, samesite="strict", path="/")
    return {"ok": True}


# --- ENROLLMENT & PASSWORD RESET (public — no session required, gated by
# single-use, expiring tokens instead) -----------------------------------

def _get_orca_base_url(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-Proto")
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("host")
    if forwarded and host:
        return f"{forwarded}://{host}".rstrip("/")
    return str(request.base_url).rstrip("/")


@app.get("/api/auth/enroll/{token}")
@limiter.limit("20/minute")
async def get_enrollment(request: Request, token: str):
    """Validates an enrollment token and returns the account details an
    admin already chose (username/initials/role) for display on the
    enrollment form -- the invitee only ever supplies a password."""
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT username, initials, role, email FROM enrollment_tokens
            WHERE token = :t AND used_at IS NULL AND expires_at > NOW()
        """), {"t": token}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="INVALID_OR_EXPIRED_INVITE")
    return dict(row)


class CompleteEnrollmentRequest(BaseModel):
    password: str


@app.post("/api/auth/enroll/{token}")
@limiter.limit("10/minute")
async def complete_enrollment(request: Request, token: str, body: CompleteEnrollmentRequest):
    """Completes enrollment: the invitee sets their own password (an admin
    never learns it, unlike the old create-user flow), the real `users`
    row is created from the details stored on the token at invite time,
    and the token is consumed."""
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="PASSWORD_TOO_SHORT")

    with db.engine.begin() as conn:
        row = conn.execute(text("""
            SELECT username, initials, role, email FROM enrollment_tokens
            WHERE token = :t AND used_at IS NULL AND expires_at > NOW()
            FOR UPDATE
        """), {"t": token}).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="INVALID_OR_EXPIRED_INVITE")

        exists = conn.execute(text(
            "SELECT 1 FROM users WHERE username = :u"
        ), {"u": row["username"]}).first()
        if exists:
            raise HTTPException(status_code=409, detail="USERNAME_ALREADY_ENROLLED")

        conn.execute(text("""
            INSERT INTO users (username, password_hash, initials, role, email, is_active)
            VALUES (:u, :p, :i, :r, :e, TRUE)
        """), {
            "u": row["username"], "p": hash_password(body.password),
            "i": row["initials"], "r": row["role"], "e": row["email"],
        })
        conn.execute(text(
            "UPDATE enrollment_tokens SET used_at = NOW() WHERE token = :t"
        ), {"t": token})

    return {"status": "ENROLLED", "username": row["username"]}


class ForgotPasswordRequest(BaseModel):
    username_or_email: str


@app.post("/api/auth/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest):
    """Self-service reset request. Only actually works when SMTP is
    configured -- with no way to deliver the link, self-service is a dead
    end and the honest answer is "ask your admin," not a generated link
    with nowhere to go. Always returns the same generic message regardless
    of whether the account exists, so this can't be used to enumerate
    valid usernames/emails."""
    import email_utils

    GENERIC_MSG = "If that account exists, a password reset link has been sent."

    if not email_utils.SMTP_CONFIGURED:
        return {
            "status": "OK",
            "message": "Self-service password reset isn't available on this instance. Contact your administrator.",
        }

    with db.engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, email FROM users
            WHERE (username = :q OR email = :q) AND is_active = TRUE
        """), {"q": body.username_or_email.strip()}).mappings().first()

        if row and row["email"]:
            from datetime import timedelta as _td
            token_row = conn.execute(text("""
                INSERT INTO password_reset_tokens (user_id, expires_at)
                VALUES (:uid, NOW() + INTERVAL '1 hour')
                RETURNING token
            """), {"uid": row["id"]}).fetchone()
            base_url = _get_orca_base_url(request)
            link = f"{base_url}/reset-password/{token_row[0]}"
            email_utils.send_email(
                row["email"], "ORCA password reset",
                f"A password reset was requested for your ORCA account.\n\n"
                f"Reset your password: {link}\n\n"
                f"This link expires in 1 hour. If you didn't request this, ignore this email.",
            )
        # else: silently do nothing -- same generic response either way

    return {"status": "OK", "message": GENERIC_MSG}


@app.get("/api/auth/reset-password/{token}")
@limiter.limit("20/minute")
async def get_reset_token(request: Request, token: str):
    """Validates a reset token (admin-initiated or self-service — same
    table, same shape) before the frontend shows the "set new password"
    form."""
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT u.username FROM password_reset_tokens t
            JOIN users u ON u.id = t.user_id
            WHERE t.token = :t AND t.used_at IS NULL AND t.expires_at > NOW()
        """), {"t": token}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="INVALID_OR_EXPIRED_TOKEN")
    return dict(row)


class CompleteResetRequest(BaseModel):
    password: str


@app.post("/api/auth/reset-password/{token}")
@limiter.limit("10/minute")
async def complete_reset(request: Request, token: str, body: CompleteResetRequest):
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="PASSWORD_TOO_SHORT")

    with db.engine.begin() as conn:
        row = conn.execute(text("""
            SELECT user_id FROM password_reset_tokens
            WHERE token = :t AND used_at IS NULL AND expires_at > NOW()
            FOR UPDATE
        """), {"t": token}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="INVALID_OR_EXPIRED_TOKEN")

        conn.execute(text(
            "UPDATE users SET password_hash = :p WHERE id = :id"
        ), {"p": hash_password(body.password), "id": row[0]})
        conn.execute(text(
            "UPDATE password_reset_tokens SET used_at = NOW() WHERE token = :t"
        ), {"t": token})

    return {"status": "OK"}

# --- VELOCIRAPTOR ORCHESTRATION ---
def run_vr_orchestrator(target_list, tsource, output_root, asset_id):
    import logging
    import json
    import threading

    backend_dir   = os.path.dirname(os.path.abspath(__file__))
    worker_script = os.path.join(backend_dir, 'run_technique.py')

    def make_job(item):
        return {
            "t_code":        item['t_code'],
            "asset_id":      asset_id,
            "output_root":   output_root,
            "tsource":       tsource,
            "vr_exe":        VR_EXE_LOCAL,
            "custom_vql":    item.get('custom_vql') or '',
            "surgical_yaml": item.get('surgical_yaml') or '',
            "db_url":        cfg.DB_URL,
        }

    def drain_stdout(proc, lines):
        # Continuously read stdout in its own thread instead of only calling
        # proc.stdout.read() after poll() shows the process exited. Without
        # this, a worker that writes more than the OS pipe buffer (~64KB)
        # before exiting blocks on that write since nothing is reading --
        # the child never exits, poll() never returns, and this job sits
        # wedged forever with no error and no way out short of an operator
        # manually killing the process.
        try:
            for line in iter(proc.stdout.readline, b''):
                lines.append(line)
        except Exception:
            pass

    import time
    max_workers = cfg.VR_MAX_WORKERS
    active = {}
    queue  = list(target_list)

    while queue or active:
        while queue and len(active) < max_workers:
            item   = queue.pop(0)
            t_code = item['t_code']
            job    = make_job(item)
            try:
                proc = subprocess.Popen(
                    [sys.executable, worker_script],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=0x08000000 if os.name == 'nt' else 0
                )
                proc.stdin.write(json.dumps(job).encode('utf-8'))
                proc.stdin.close()
                out_lines = []
                drain_thread = threading.Thread(target=drain_stdout, args=(proc, out_lines), daemon=True)
                drain_thread.start()
                active[proc.pid] = (proc, t_code, out_lines, drain_thread)
                logging.info(f"[VR] {t_code}: worker spawned (pid {proc.pid})")
            except Exception as e:
                logging.error(f"[VR] {t_code}: spawn failed — {e}")

        time.sleep(0.5)
        done_pids = []
        for pid, (proc, t_code, out_lines, drain_thread) in active.items():
            ret = proc.poll()
            if ret is not None:
                drain_thread.join(timeout=2)
                for line in out_lines:
                    line_str = line.decode('utf-8', errors='replace').rstrip('\n')
                    if line_str.strip():
                        logging.info(line_str)
                done_pids.append(pid)
        for pid in done_pids:
            del active[pid]


async def run_vr_via_agent(target_list, tsource, agent_id, asset_id):
    """Agent-dispatched counterpart to run_vr_orchestrator() above -- runs
    each technique's collection on `agent_id` (reaching any drive letter
    that agent can see: a locally attached physical disk, or anything it
    mounted via Arsenal) instead of in-container, via the existing agent
    job queue (dispatch_and_wait, same mechanism /api/assets/mount uses).
    Writes to the same evidence/artifact_results tables run_technique.py's
    normalize()/write_no_artifacts() write to -- that happens here, in the
    backend process, since the agent itself has no DB access of its own;
    the agent only streams back raw rows (see orca_agent.py's
    _run_artifact_collection).
    """
    for item in target_list:
        t_code = item["t_code"]
        try:
            lines = await dispatch_and_wait(agent_id, "artifact_collection", {
                "t_code":        t_code,
                "tsource":       tsource,
                "custom_vql":    item.get("custom_vql") or "",
                "surgical_yaml": item.get("surgical_yaml") or "",
            }, timeout=300.0)
        except Exception as e:
            print(f"[VR_AGENT] {t_code}: dispatch failed -- {e}")
            continue

        raw_rows, fallback_used = [], False
        for raw_line in lines:
            try:
                evt = json.loads(raw_line)
            except Exception:
                continue
            if evt.get("type") == "row":
                raw_rows.append(evt["data"]["row"])
            elif evt.get("type") == "done":
                fallback_used = evt["data"].get("fallback_used", False)
            elif evt.get("type") == "error":
                print(f"[VR_AGENT] {t_code}: agent error -- {evt['data'].get('message')}")

        clean_rows = []
        for raw in raw_rows:
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            if "_Source" in obj and len(obj) == 1:
                continue
            clean = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in obj.items()}
            if fallback_used:
                clean["_orca_fallback"] = True
                clean["_orca_fallback_note"] = "Primary query returned 0 hits — broad EventID collection for analyst review"
            clean_rows.append(clean)

        with db.engine.connect() as conn:
            if clean_rows:
                msg = (
                    f"Broad Collection (Fallback): {len(clean_rows)} entries — primary query returned 0 hits. Review for relevance."
                    if fallback_used else
                    f"Forensic Hit: {len(clean_rows)} system entries found via {t_code}"
                )
                conn.execute(text("""
                    INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                    VALUES (:aid, :t, 'Evidence Found', :s, TRUE)
                    ON CONFLICT (asset_id, t_code)
                    DO UPDATE SET verdict = 'Evidence Found', evidence_summary = EXCLUDED.evidence_summary, evidence_imported = TRUE
                """), {"aid": asset_id, "t": t_code, "s": json.dumps({"message": msg})})
                for row in clean_rows:
                    display_name = row.get("Name") or row.get("EventID") or row.get("ID") or t_code
                    display_path = row.get("Key") or row.get("OSPath") or row.get("FullPath") or "System"
                    conn.execute(text("""
                        INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                        VALUES (:aid, :t, :fname, :fpath, :raw)
                    """), {"aid": asset_id, "t": t_code, "fname": display_name, "fpath": display_path, "raw": json.dumps(row)})
                print(f"[VR_AGENT] {t_code}: ingested {len(clean_rows)} rows{' [FALLBACK]' if fallback_used else ''}")
            else:
                conn.execute(text("""
                    INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                    VALUES (:aid, :t, 'NO_ARTIFACTS', :s, FALSE)
                    ON CONFLICT (asset_id, t_code)
                    DO UPDATE SET verdict = 'NO_ARTIFACTS', evidence_summary = EXCLUDED.evidence_summary
                """), {"aid": asset_id, "t": t_code, "s": json.dumps({"message": "Collection executed — no artifacts found on this host for this technique. Manual evidence upload recommended."})})
                print(f"[VR_AGENT] {t_code}: NO_ARTIFACTS")
            conn.commit()


@app.post("/api/assets/execute")
async def execute_asset_action(
    request: AssetActionRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    try:
        asset_id = int(request.asset_id)
        with db.engine.connect() as conn:
            intel_rows = conn.execute(text("""
                SELECT DISTINCT mt.t_code
                FROM assets a
                JOIN cases c ON c.name = a.case_name
                JOIN threat_attribution ta ON UPPER(ta.attribution) = UPPER(c.focus_country)
                JOIN mitre_actors ma ON ma.name = ta.group_name
                JOIN mitre_relationships mr ON mr.source_ref = ma.stix_id
                JOIN mitre_techniques mt ON mt.stix_id = mr.target_ref
                JOIN ref_artifact_library ref ON ref.t_code = mt.t_code
                WHERE a.id = :asset_id
                  AND mr.relationship_type = 'uses'
                  AND NOT COALESCE(mt.is_deprecated, FALSE)
                  AND NOT COALESCE(mt.is_revoked, FALSE)
                  AND (
                      mt.platforms IS NULL
                      OR mt.platforms = '[]'::jsonb
                      OR mt.platforms @> to_jsonb(ARRAY[a.os]::text[])
                  )
                  AND (ref.custom_vql IS NOT NULL OR ref.surgical_yaml IS NOT NULL)
                ORDER BY mt.t_code
            """), {"asset_id": asset_id}).fetchall()

            case_row = conn.execute(text(
                "SELECT case_name FROM assets WHERE id = :id"
            ), {"id": asset_id}).fetchone()

        if not intel_rows:
            raise HTTPException(status_code=404, detail=f"No techniques found for asset {asset_id} — check case country and asset OS")

        t_codes = [r.t_code for r in intel_rows]
        with db.engine.connect() as conn:
            lib_rows = conn.execute(text(
                "SELECT t_code, custom_vql, surgical_yaml FROM ref_artifact_library WHERE t_code = ANY(:codes)"
            ), {"codes": t_codes}).fetchall()
        lib_map = {r.t_code: r for r in lib_rows}

        target_list = [{
            "t_code":        r.t_code,
            "orca_name":     r.t_code,
            "custom_vql":    lib_map[r.t_code].custom_vql if r.t_code in lib_map else '',
            "surgical_yaml": lib_map[r.t_code].surgical_yaml if r.t_code in lib_map else '',
        } for r in intel_rows]
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_root = os.path.join(DATA_ROOT, case_row.case_name.replace(" ", "_"), run_id)
        os.makedirs(output_root, exist_ok=True)

        if request.agent_id:
            # Runs on the agent instead of in-container -- reaches any
            # drive letter that agent can see (a locally attached physical
            # disk, or anything mounted via Arsenal), not just what's
            # bind-mounted into this container. In addition to the
            # existing in-container path above, not a replacement for it.
            asyncio.create_task(run_vr_via_agent(target_list, request.tsource, request.agent_id, asset_id))
        else:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, run_vr_orchestrator, target_list, request.tsource, output_root, asset_id)

        return {"status": "initiated", "target_count": len(target_list), "run_id": run_id}

    except Exception as e:
        print(f"[ERROR] execute_asset_action asset_id={request.asset_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/assets/vuln-scan")
@limiter.limit("5/minute")
async def vuln_scan(
    request: Request,
    payload: VulnScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """SSE stream — runs Syft then Grype, saves SBOM + results, stores in vuln_results."""
    asset_id  = int(payload.asset_id)
    scan_path = payload.scan_path
    offline   = payload.offline

    async def generate():
        import json as _json

        def sse(type_, data):
            return f"data: {_json.dumps({'type': type_, 'data': data})}\n\n"

        try:
            out_dir = os.path.join(DATA_ROOT, f"asset_{asset_id}", "vuln")
            os.makedirs(out_dir, exist_ok=True)
            sbom_path  = os.path.join(out_dir, "syft_sbom.json")
            vuln_path  = os.path.join(out_dir, "grype_results.json")

            yield sse("log", f"SYFT: scanning {scan_path} ...")
            syft_cmd = [
                SYFT_EXE, scan_path,
                "-o", f"cyclonedx-json={sbom_path}",
                "-v",
            ]
            syft_proc = await asyncio.create_subprocess_exec(
                *syft_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            syft_pkg_count = 0
            async for raw in syft_proc.stderr:
                line = raw.decode(errors="replace").strip()
                if not line:
                    continue
                low = line.lower()
                if "cataloging" in low or "catalog" in low:
                    syft_pkg_count += 1
                    if syft_pkg_count % 10 == 0:
                        yield sse("log", f"SYFT: catalogued {syft_pkg_count} items...")
                elif "error" in low or "warn" in low:
                    yield sse("log", f"SYFT: {line}")
                elif "indexed" in low or "parsed" in low or "package" in low:
                    yield sse("log", f"SYFT: {line}")

            await syft_proc.wait()
            if syft_proc.returncode != 0:
                yield sse("error", f"SYFT_ERROR: exit code {syft_proc.returncode}")
                yield sse("done", "VULN_SCAN_FAILED")
                return
            yield sse("log", f"SYFT: SBOM complete — {syft_pkg_count} items catalogued → {sbom_path}")

            yield sse("log", "GRYPE: loading SBOM and querying vulnerability database...")
            grype_cmd = [
                GRYPE_EXE, f"sbom:{sbom_path}",
                "-o", "json",
                "--file", vuln_path,
                "-v",
            ]
            grype_env = os.environ.copy()
            # Grype's own default cache dir is empty inside this container
            # (some per-user home directory) -- without this it finds no
            # DB at all and refuses to run, regardless of the offline flag.
            grype_env["GRYPE_DB_CACHE_DIR"] = cfg.GRYPE_DB_DIR
            if offline:
                grype_cmd.append("--only-fixed")
                # Without these, grype still tries to reach the internet to
                # check for a newer DB on every run (slow/hangs offline),
                # and -- confirmed live -- outright REFUSES to run at all
                # once the bundled DB is older than its default 5-day
                # max-allowed-built-age, erroring instead of just warning.
                # An offline kit's DB is only ever going to get older from
                # the moment it's built, so this isn't optional for an
                # offline deployment to keep working past its first few days.
                grype_env["GRYPE_DB_AUTO_UPDATE"] = "false"
                grype_env["GRYPE_DB_VALIDATE_AGE"] = "false"

            grype_proc = await asyncio.create_subprocess_exec(
                *grype_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=grype_env,
            )

            async for raw in grype_proc.stderr:
                line = raw.decode(errors="replace").strip()
                if not line:
                    continue
                low = line.lower()
                if "error" in low or "warn" in low:
                    yield sse("log", f"GRYPE: {line}")
                elif any(k in low for k in ["loading", "scanning", "match", "vulnerabilit", "db", "update"]):
                    yield sse("log", f"GRYPE: {line}")

            await grype_proc.wait()
            if grype_proc.returncode not in (0, 1):
                yield sse("error", f"GRYPE_ERROR: exit code {grype_proc.returncode}")
                yield sse("done", "VULN_SCAN_FAILED")
                return
            yield sse("log", "GRYPE: scan complete")

            with open(vuln_path, "r", encoding="utf-8") as f:
                grype_data = _json.load(f)

            matches = grype_data.get("matches", [])
            yield sse("log", f"GRYPE: {len(matches)} vulnerabilities found")

            with db.engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS vuln_results (
                        id          SERIAL PRIMARY KEY,
                        asset_id    INTEGER NOT NULL,
                        cve_id      VARCHAR(50),
                        severity    VARCHAR(20),
                        package     VARCHAR(255),
                        version     VARCHAR(100),
                        fix_version VARCHAR(100),
                        fix_state   VARCHAR(50),
                        sbom_path   TEXT,
                        vuln_path   TEXT,
                        scanned_at  TIMESTAMP DEFAULT NOW()
                    )
                """))
                seen: dict = {}
                for match in matches:
                    vuln = match.get("vulnerability", {})
                    pkg  = match.get("artifact", {})
                    key  = (vuln.get("id", ""), pkg.get("name", ""), pkg.get("version", ""))
                    if key not in seen:
                        seen[key] = match
                deduped = list(seen.values())
                yield sse("log", f"GRYPE: {len(matches)} raw matches → {len(deduped)} unique after dedup")

                conn.execute(text("DELETE FROM vuln_results WHERE asset_id = :id"), {"id": asset_id})

                for match in deduped:
                    vuln    = match.get("vulnerability", {})
                    pkg     = match.get("artifact", {})
                    fix     = vuln.get("fix", {})
                    conn.execute(text("""
                        INSERT INTO vuln_results
                            (asset_id, cve_id, severity, package, version, fix_version, fix_state, sbom_path, vuln_path)
                        VALUES
                            (:asset_id, :cve_id, :severity, :package, :version, :fix_version, :fix_state, :sbom_path, :vuln_path)
                    """), {
                        "asset_id":    asset_id,
                        "cve_id":      vuln.get("id", ""),
                        "severity":    vuln.get("severity", "Unknown"),
                        "package":     pkg.get("name", ""),
                        "version":     pkg.get("version", ""),
                        "fix_version": fix.get("versions", [""])[0] if fix.get("versions") else "",
                        "fix_state":   fix.get("state", ""),
                        "sbom_path":   sbom_path,
                        "vuln_path":   vuln_path,
                    })
                conn.commit()

            from collections import Counter
            sev_counts = Counter(
                m.get("vulnerability", {}).get("severity", "Unknown") for m in deduped
            )
            yield sse("summary", {
                "total":    len(deduped),
                "critical": sev_counts.get("Critical", 0),
                "high":     sev_counts.get("High", 0),
                "medium":   sev_counts.get("Medium", 0),
                "low":      sev_counts.get("Low", 0),
                "sbom_path": sbom_path,
                "vuln_path": vuln_path,
            })
            yield sse("done", "VULN_SCAN_COMPLETE")

        except Exception as e:
            yield sse("error", f"VULN_SCAN_ERROR: {e}")
            yield sse("done", "VULN_SCAN_FAILED")

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/assets/{asset_id}/vuln-results")
async def get_vuln_results(
    asset_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Fetch stored vuln results for an asset."""
    try:
        with db.engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT cve_id, severity, package, version, fix_version, fix_state, scanned_at
                FROM vuln_results WHERE asset_id = :id
                ORDER BY
                    CASE severity
                        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5
                    END, cve_id
            """), {"id": asset_id}).fetchall()
        return [dict(r._mapping) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


def _extract_job_result(lines: list) -> dict:
    """dispatch_and_wait() returns the raw NDJSON lines an agent streamed via
    _stream_line() -- pull out the terminal event's data. Mount/dismount jobs
    already do their aim_cli output parsing agent-side (orca_agent.py's own
    _parse_aim_output), so this just unwraps what it already structured."""
    for line in lines:
        try:
            evt = json.loads(line)
        except Exception:
            continue
        if evt.get("type") == "error":
            raise HTTPException(status_code=500, detail=str(evt.get("data")))
        if evt.get("type") == "done":
            return evt.get("data") or {}
    raise HTTPException(status_code=500, detail="Agent job completed with no result")


def _ensure_mount_table():
    with db.engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS mount_sessions (
                id              SERIAL PRIMARY KEY,
                asset_id        INTEGER NOT NULL,
                agent_id        VARCHAR(64),
                image_path      TEXT NOT NULL,
                device_number   VARCHAR(20),
                drive_letter    VARCHAR(5),
                physical_drive  VARCHAR(50),
                provider        VARCHAR(20),
                status          VARCHAR(20) DEFAULT 'MOUNTED',
                mounted_at      TIMESTAMP DEFAULT NOW(),
                dismounted_at   TIMESTAMP
            )
        """))
        # Table may already exist from before agent_id was added (this whole
        # function only ever CREATE TABLE IF NOT EXISTS, so an existing table
        # wouldn't otherwise pick up new columns).
        conn.execute(text("ALTER TABLE mount_sessions ADD COLUMN IF NOT EXISTS agent_id VARCHAR(64)"))
        conn.commit()


@app.post("/api/assets/mount")
async def mount_image(
    request: MountRequest,
    current_user: dict = Depends(get_current_user)
):
    """Mount a disk image via an ORCA agent's aim_cli and record the session.

    Dispatched to an agent rather than run locally -- Arsenal Image Mounter
    is Windows-only with no Linux equivalent, so this container can never
    run it directly. The agent can be the same Windows host Docker runs on
    (for evidence reachable from there, e.g. a UNC path) or any other
    Windows machine with custody of the image; either way it's just another
    registered agent from this endpoint's point of view."""
    _ensure_mount_table()
    asset_id = int(request.asset_id)

    provider = request.provider
    if provider == "auto":
        ext = os.path.splitext(request.image_path)[1].lower()
        provider = {
            ".e01": "LibEwf", ".ex01": "LibEwf", ".s01": "LibEwf",
            ".vmdk": "DiscUtils", ".vhd": "DiscUtils", ".vhdx": "DiscUtils",
            ".qcow": "LibQcow", ".qcow2": "LibQcow",
        }.get(ext, "None")

    try:
        # dispatch_and_wait()'s default (120s) is tuned for quick jobs --
        # mounting a large disk image (DiscUtils parsing/onlining a
        # multi-GB VHDX, say) can legitimately take longer than that, and
        # the job itself was still running fine server-side; only the
        # caller's wait gave up early.
        lines = await dispatch_and_wait(request.agent_id, "mount", {
            "image_path": request.image_path,
            "provider": provider,
            "readonly": request.readonly,
        }, timeout=900.0)
        result = _extract_job_result(lines)

        parsed = {
            "device_number":  result.get("device_number"),
            "physical_drive": result.get("physical_drive"),
            "drive_letter":   result.get("drive_letter"),
        }
        output = result.get("output", "")
        drive_letter = parsed["drive_letter"] or request.drive_letter

        with db.engine.connect() as conn:
            row = conn.execute(text("""
                INSERT INTO mount_sessions
                    (asset_id, agent_id, image_path, device_number, drive_letter, physical_drive, provider, status)
                VALUES (:asset_id, :agent_id, :image_path, :device_number, :drive_letter, :physical_drive, :provider, 'MOUNTED')
                RETURNING id
            """), {
                "asset_id":       asset_id,
                "agent_id":       request.agent_id,
                "image_path":     request.image_path,
                "device_number":  parsed["device_number"],
                "drive_letter":   drive_letter,
                "physical_drive": parsed["physical_drive"],
                "provider":       provider,
            })
            mount_id = row.fetchone()[0]

            conn.execute(text("""
                UPDATE assets SET analysis_mode = 'DEAD_DISK_LOCAL' WHERE id = :id
            """), {"id": asset_id})
            conn.commit()

        return {
            "status":         "MOUNTED",
            "mount_id":       mount_id,
            "device_number":  parsed["device_number"],
            "drive_letter":   drive_letter,
            "physical_drive": parsed["physical_drive"],
            "provider":       provider,
            "output":         output,
        }

    except HTTPException:
        raise
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/assets/dismount")
async def dismount_image(
    asset_id: int,
    mount_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Dismount a mounted image by mount session ID, via the same ORCA agent
    that mounted it -- device_number is only meaningful on that specific
    Windows host, so it's read from the stored session rather than trusted
    from the caller."""
    _ensure_mount_table()

    # Atomically claim the mount session by flipping it to a transient
    # DISMOUNTING status in the same statement as the MOUNTED check --
    # two concurrent dismount calls for the same mount_id can no longer
    # both pass a separate read-then-write and both run the AIM CLI /
    # both mark it DISMOUNTED.
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            UPDATE mount_sessions SET status = 'DISMOUNTING'
            WHERE id = :mount_id AND asset_id = :asset_id AND status = 'MOUNTED'
            RETURNING device_number, agent_id
        """), {"mount_id": mount_id, "asset_id": asset_id}).fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Mount session not found or already dismounted")

    device_number, agent_id = row
    if not agent_id:
        # Session predates agent_id being tracked (mounted before this
        # feature existed) -- there's no way to know which host to dispatch
        # to, and the underlying image is long gone anyway. Let the operator
        # clear the stale row rather than silently no-op a "successful" dismount.
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE mount_sessions SET status = 'MOUNTED' WHERE id = :mount_id
            """), {"mount_id": mount_id})
            conn.commit()
        raise HTTPException(
            status_code=409,
            detail="This mount session has no recorded agent (mounted before agent-based mounting existed) "
                   "and can't be dismounted through this endpoint.",
        )

    try:
        lines = await dispatch_and_wait(agent_id, "dismount", {"device_number": device_number})
        result = _extract_job_result(lines)
        output = result.get("output", "")

        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE mount_sessions
                SET status = 'DISMOUNTED', dismounted_at = NOW()
                WHERE id = :mount_id
            """), {"mount_id": mount_id})
            conn.commit()

        return {"status": "DISMOUNTED", "output": output}

    except HTTPException:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE mount_sessions SET status = 'MOUNTED' WHERE id = :mount_id AND status = 'DISMOUNTING'
            """), {"mount_id": mount_id})
            conn.commit()
        raise
    except TimeoutError as e:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE mount_sessions SET status = 'MOUNTED' WHERE id = :mount_id AND status = 'DISMOUNTING'
            """), {"mount_id": mount_id})
            conn.commit()
        raise HTTPException(status_code=504, detail=str(e))
    except Exception as e:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE mount_sessions SET status = 'MOUNTED' WHERE id = :mount_id AND status = 'DISMOUNTING'
            """), {"mount_id": mount_id})
            conn.commit()
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/assets/{asset_id}/mounts")
async def get_mounts(
    asset_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get mount sessions for an asset."""
    _ensure_mount_table()
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id, agent_id, image_path, device_number, drive_letter, physical_drive,
                   provider, status, mounted_at, dismounted_at
            FROM mount_sessions WHERE asset_id = :id
            ORDER BY mounted_at DESC
        """), {"id": asset_id}).fetchall()
    return [dict(r._mapping) for r in rows]


app.include_router(mitre_routes.router)
app.include_router(ioc.router)
app.include_router(profile_routes.router)
app.include_router(coverage_routes.router)
app.include_router(network_routes.router)
app.include_router(behavioral_routes.router)

# Clean up temp behavioral analysis files older than 1 hour on startup
behavioral_routes.cleanup_old_temp_files()

if __name__ == "__main__":
    import ssl as _ssl
    ssl_cert = cfg.SSL_CERTFILE
    ssl_key  = cfg.SSL_KEYFILE

    if not (ssl_cert and os.path.exists(ssl_cert)):
        print(f"[ORCA] FATAL: TLS cert not found at {ssl_cert}")
        sys.exit(1)
    if not (ssl_key and os.path.exists(ssl_key)):
        print(f"[ORCA] FATAL: TLS key not found at {ssl_key}")
        sys.exit(1)

    print(f"[ORCA] TLS enabled — cert: {ssl_cert}")

    # Build SSL context with explicit TLS 1.2+ minimum
    ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    ssl_ctx.load_cert_chain(ssl_cert, ssl_key)

    config = uvicorn.Config(
        app, host="0.0.0.0", port=8000,  # nosec B104 — intentional Docker container binding; nginx controls external access
        ssl_certfile=ssl_cert, ssl_keyfile=ssl_key,
        access_log=True,
    )
    config.load()
    config.ssl.minimum_version = _ssl.TLSVersion.TLSv1_2
    server = uvicorn.Server(config)
    server.run()