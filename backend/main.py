import os
import sys
import json
import subprocess
import asyncio
from datetime import datetime
from fastapi import FastAPI, HTTPException, BackgroundTasks, status, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import uvicorn
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional, Any, Union

# --- AUTH IMPORTS ---
from auth_utils import verify_password, create_access_token, get_current_user
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from core.database_manager import db
from routes import mitre_routes, ioc, admin, profile_routes, coverage_routes, network_routes
import vr_remote
from agent_routes import router as agent_router
from config import cfg
from report_routes import router as report_router

app = FastAPI(title="ORCAWEB")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "https://localhost").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
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

VR_EXE_LOCAL   = cfg.VR_EXE_LOCAL    # executed in-container (run_technique.py against locally mounted evidence)
VR_EXE_WINDOWS = cfg.VR_EXE_WINDOWS  # pushed to / executed on remote Windows targets
DATA_ROOT = cfg.DATA_ROOT
SYFT_EXE  = cfg.SYFT_EXE
GRYPE_EXE = cfg.GRYPE_EXE
AIM_CLI   = cfg.AIM_CLI


# --- MODELS ---
class LoginRequest(BaseModel):
    username: str
    password: str

class AssetActionRequest(BaseModel):
    action: str
    asset_id: Optional[Union[str, int]] = None
    tsource: Optional[str] = "C:/"

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
    image_path:   str
    drive_letter: Optional[str] = None
    provider:     Optional[str] = "auto"
    readonly:     Optional[bool] = True

# --- AUTH ENDPOINTS ---
@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, login_data: LoginRequest):
    """Verifies user credentials and returns a JWT."""
    try:
        with db.engine.connect() as conn:
            query = text("SELECT id, username, password_hash, initials, role FROM users WHERE username = :u")
            user_record = conn.execute(query, {"u": login_data.username}).fetchone()

        if not user_record:
            raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

        db_id, db_username, db_password_hash, db_initials, db_role = user_record

        if not verify_password(login_data.password, db_password_hash):
            raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

        token = create_access_token(data={
            "sub":      db_username,
            "id":       db_id,
            "role":     db_role,
            "initials": db_initials,
        })

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "username": db_username,
                "initials": db_initials,
                "role":     db_role,
                "id":       db_id,
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[!] LOGIN_ERROR: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error during Authentication")

# --- VELOCIRAPTOR ORCHESTRATION ---
def run_vr_orchestrator(target_list, tsource, output_root, asset_id):
    import logging
    import json

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
                active[proc.pid] = (proc, t_code)
                logging.info(f"[VR] {t_code}: worker spawned (pid {proc.pid})")
            except Exception as e:
                logging.error(f"[VR] {t_code}: spawn failed — {e}")

        time.sleep(0.5)
        done_pids = []
        for pid, (proc, t_code) in active.items():
            ret = proc.poll()
            if ret is not None:
                output = proc.stdout.read().decode('utf-8', errors='replace')
                for line in output.splitlines():
                    if line.strip():
                        logging.info(line)
                done_pids.append(pid)
        for pid in done_pids:
            del active[pid]


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

        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, run_vr_orchestrator, target_list, request.tsource, output_root, asset_id)

        return {"status": "initiated", "target_count": len(target_list), "run_id": run_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/assets/remote-execute")
async def remote_execute(
    request: RemoteExecuteRequest,
    current_user: dict = Depends(get_current_user)
):
    """SSE stream — pushes VR to remote asset, collects, pulls results back."""
    return StreamingResponse(
        vr_remote.run_remote_collection(
            asset_id       = int(request.asset_id),
            ip             = request.ip,
            transport      = request.transport,
            username       = request.username,
            password       = request.password,
            domain         = request.domain,
            tsource        = request.tsource,
            cleanup        = request.cleanup,
            remap_mounted  = request.remap_mounted,
            remap_original = request.remap_original,
            vr_exe         = VR_EXE_WINDOWS,
            data_root      = DATA_ROOT,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/assets/vuln-scan")
async def vuln_scan(
    request: VulnScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """SSE stream — runs Syft then Grype, saves SBOM + results, stores in vuln_results."""
    asset_id  = int(request.asset_id)
    scan_path = request.scan_path
    offline   = request.offline

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
            if offline:
                grype_cmd.append("--only-fixed")

            grype_proc = await asyncio.create_subprocess_exec(
                *grype_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
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
        raise HTTPException(status_code=500, detail=str(e))


def _parse_aim_output(output: str) -> dict:
    """Parse aim_cli stdout into structured dict."""
    result = {"device_number": None, "physical_drive": None, "drive_letter": None}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Device number"):
            result["device_number"] = line.split()[-1]
        elif line.startswith("Device is"):
            result["physical_drive"] = line.split()[-1]
        elif "Drive letter" in line or (len(line) == 2 and line[1] == ":"):
            result["drive_letter"] = line.replace("Drive letter:", "").replace(":", "").strip()
    return result


def _ensure_mount_table():
    with db.engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS mount_sessions (
                id              SERIAL PRIMARY KEY,
                asset_id        INTEGER NOT NULL,
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
        conn.commit()


@app.post("/api/assets/mount")
async def mount_image(
    request: MountRequest,
    current_user: dict = Depends(get_current_user)
):
    """Mount a disk image via aim_cli and record the session."""
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

    cmd = [AIM_CLI, "--mount"]
    if request.readonly:
        cmd.append("--readonly")
    cmd += [f"--filename={request.image_path}", f"--provider={provider}"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=os.path.dirname(AIM_CLI),
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors="replace")

        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"AIM_MOUNT_FAILED: {output}")

        parsed = _parse_aim_output(output)
        drive_letter = parsed["drive_letter"] or request.drive_letter

        with db.engine.connect() as conn:
            row = conn.execute(text("""
                INSERT INTO mount_sessions
                    (asset_id, image_path, device_number, drive_letter, physical_drive, provider, status)
                VALUES (:asset_id, :image_path, :device_number, :drive_letter, :physical_drive, :provider, 'MOUNTED')
                RETURNING id
            """), {
                "asset_id":       asset_id,
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/assets/dismount")
async def dismount_image(
    asset_id: int,
    mount_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Dismount a mounted image by mount session ID."""
    _ensure_mount_table()

    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT device_number FROM mount_sessions
            WHERE id = :mount_id AND asset_id = :asset_id AND status = 'MOUNTED'
        """), {"mount_id": mount_id, "asset_id": asset_id}).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Mount session not found or already dismounted")

    device_number = row[0]
    cmd = [AIM_CLI, f"--dismount={device_number}", "--force"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=os.path.dirname(AIM_CLI),
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors="replace")

        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"AIM_DISMOUNT_FAILED: {output}")

        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE mount_sessions
                SET status = 'DISMOUNTED', dismounted_at = NOW()
                WHERE id = :mount_id
            """), {"mount_id": mount_id})
            conn.commit()

        return {"status": "DISMOUNTED", "output": output}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/assets/{asset_id}/mounts")
async def get_mounts(
    asset_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get mount sessions for an asset."""
    _ensure_mount_table()
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id, image_path, device_number, drive_letter, physical_drive,
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
        app, host="0.0.0.0", port=8000,
        ssl_certfile=ssl_cert, ssl_keyfile=ssl_key,
        access_log=True,
    )
    config.load()
    config.ssl.minimum_version = _ssl.TLSVersion.TLSv1_2
    server = uvicorn.Server(config)
    server.run()