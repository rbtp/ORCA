import asyncio
import base64
import hashlib
import json
import os
import socket
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import text

from datetime import timedelta
from auth_utils import get_current_user, create_access_token
from config import cfg
from core.database_manager import db
import vr_remote

router = APIRouter(prefix="/api/agent")

# In-memory state — shared across the process lifetime
_job_queues: Dict[str, asyncio.Queue] = {}      # agent_id -> Queue of job dicts
_job_streams: Dict[str, List[str]] = {}          # job_id -> list of raw JSON lines
_job_subscribers: Dict[str, List[asyncio.Queue]] = {}  # job_id -> list of SSE subscriber queues


def _get_folder_sync_paths() -> list:
    """Return Windows paths for all investigation/asset local dirs.
    Uses CASES_DIR env var to convert container paths to Windows paths for analyst machines."""
    cases_dir = os.environ.get("CASES_DIR", "").strip()
    if not cases_dir:
        return []
    windows_base = cases_dir.replace("/", "\\").rstrip("\\")
    paths = []
    try:
        with db.engine.connect() as conn:
            for table in ("cases", "assets"):
                rows = conn.execute(text(
                    f"SELECT local_dir FROM {table} WHERE local_dir IS NOT NULL"  # nosec B608
                )).fetchall()
                for (local_dir,) in rows:
                    if local_dir and local_dir.startswith("/app/cases/"):
                        rel = local_dir[len("/app/cases/"):]
                        paths.append(windows_base + "\\" + rel.replace("/", "\\"))
    except Exception:
        pass
    return paths


class RegisterRequest(BaseModel):
    hostname: str
    capabilities: List[str]


class DispatchRequest(BaseModel):
    agent_id: str
    job_type: str
    params: Dict[str, Any]


class CompleteRequest(BaseModel):
    status: str
    summary: Dict[str, Any]


@router.post("/register")
async def register_agent(
    body: RegisterRequest,
    current_user: dict = Depends(get_current_user)
):
    username = current_user.get("sub", "")
    user_id = current_user.get("id")

    raw = body.hostname + username
    agent_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    with db.engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO agent_registrations (agent_id, hostname, analyst_id, capabilities, last_seen)
            VALUES (:agent_id, :hostname, :analyst_id, CAST(:caps AS jsonb), NOW())
            ON CONFLICT (agent_id) DO UPDATE
                SET hostname = EXCLUDED.hostname,
                    capabilities = CAST(EXCLUDED.capabilities AS jsonb),
                    last_seen = NOW()
        """), {
            "agent_id": agent_id,
            "hostname": body.hostname,
            "analyst_id": user_id,
            "caps": json.dumps(body.capabilities),
        })
        conn.commit()

    if agent_id not in _job_queues:
        _job_queues[agent_id] = asyncio.Queue()

    return {"agent_id": agent_id}


@router.delete("/{agent_id}")
async def delete_agent(agent_id: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="ADMIN_PRIVILEGES_REQUIRED")
    with db.engine.connect() as conn:
        conn.execute(text("DELETE FROM agent_jobs WHERE agent_id = :id"), {"id": agent_id})
        conn.execute(text("DELETE FROM agent_registrations WHERE agent_id = :id"), {"id": agent_id})
        conn.commit()
    _job_queues.pop(agent_id, None)
    _job_streams.pop(agent_id, None)
    return {"ok": True}


@router.get("/list")
async def list_agents(current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT ar.agent_id, ar.hostname,
                   u.username AS analyst,
                   ar.last_seen, ar.capabilities,
                   CASE WHEN ar.last_seen > NOW() - INTERVAL '90 seconds'
                        THEN 'ONLINE' ELSE 'OFFLINE' END AS status
            FROM agent_registrations ar
            LEFT JOIN users u ON u.id = ar.analyst_id
            ORDER BY ar.last_seen DESC
        """)).fetchall()
    return [dict(r._mapping) for r in rows]


@router.post("/dispatch")
async def dispatch_job(
    body: DispatchRequest,
    current_user: dict = Depends(get_current_user)
):
    job_id = uuid.uuid4().hex[:24]

    with db.engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO agent_jobs (job_id, agent_id, job_type, params, status)
            VALUES (:job_id, :agent_id, :job_type, CAST(:params AS jsonb), 'PENDING')
        """), {
            "job_id": job_id,
            "agent_id": body.agent_id,
            "job_type": body.job_type,
            "params": json.dumps(body.params),
        })
        conn.commit()

    if body.agent_id not in _job_queues:
        _job_queues[body.agent_id] = asyncio.Queue()

    await _job_queues[body.agent_id].put({
        "job_id": job_id,
        "job_type": body.job_type,
        "params": body.params,
    })

    return {"job_id": job_id}


@router.get("/jobs/{job_id}/stream")
async def stream_job_results(
    job_id: str,
    current_user: dict = Depends(get_current_user)
):
    # Check if job already finished so we can close immediately after replay
    already_done = False
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT status FROM agent_jobs WHERE job_id = :id"
        ), {"id": job_id}).fetchone()
        if row and row[0] in ("SUCCESS", "ERROR"):
            already_done = True

    sub_queue: asyncio.Queue = asyncio.Queue()
    if job_id not in _job_subscribers:
        _job_subscribers[job_id] = []
    _job_subscribers[job_id].append(sub_queue)

    existing = list(_job_streams.get(job_id, []))

    async def event_stream():
        try:
            for line in existing:
                yield f"data: {line}\n\n"

            if already_done:
                return

            while True:
                try:
                    item = await asyncio.wait_for(sub_queue.get(), timeout=30.0)
                    if item is None:
                        break
                    yield f"data: {item}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            if job_id in _job_subscribers and sub_queue in _job_subscribers[job_id]:
                _job_subscribers[job_id].remove(sub_queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/{agent_id}/jobs")
async def poll_jobs(
    agent_id: str,
    current_user: dict = Depends(get_current_user)
):
    # Agent tokens are self-authenticating; analyst tokens must own this agent
    if current_user.get("role") != "agent":
        with db.engine.connect() as conn:
            row = conn.execute(text(
                "SELECT analyst_id FROM agent_registrations WHERE agent_id = :id"
            ), {"id": agent_id}).fetchone()
        if not row or str(row[0]) != str(current_user.get("id")):
            from fastapi import HTTPException as _HTTPException
            raise _HTTPException(status_code=403, detail="AGENT_ACCESS_DENIED")

    with db.engine.connect() as conn:
        conn.execute(text(
            "UPDATE agent_registrations SET last_seen = NOW() WHERE agent_id = :id"
        ), {"id": agent_id})
        conn.commit()

    if agent_id not in _job_queues:
        _job_queues[agent_id] = asyncio.Queue()

    # Real analysis job takes priority — check queue without blocking first
    try:
        job = _job_queues[agent_id].get_nowait()
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE agent_jobs SET status = 'RUNNING', started_at = NOW()
                WHERE job_id = :job_id
            """), {"job_id": job["job_id"]})
            conn.commit()
        return job
    except asyncio.QueueEmpty:
        pass

    # Inject folder structure sync on every checkin (idempotent on the agent side)
    sync_paths = _get_folder_sync_paths()
    if sync_paths:
        return {
            "job_id": uuid.uuid4().hex[:24],
            "job_type": "folder_sync",
            "params": {"paths": sync_paths},
        }

    # Nothing queued — long-poll up to 30s for new analysis jobs
    try:
        job = await asyncio.wait_for(_job_queues[agent_id].get(), timeout=30.0)
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE agent_jobs SET status = 'RUNNING', started_at = NOW()
                WHERE job_id = :job_id
            """), {"job_id": job["job_id"]})
            conn.commit()
        return job
    except asyncio.TimeoutError:
        return None


@router.post("/{agent_id}/jobs/{job_id}/stream")
async def receive_job_stream(
    agent_id: str,
    job_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    body = await request.body()
    raw = body.decode(errors="replace")

    if job_id not in _job_streams:
        _job_streams[job_id] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        _job_streams[job_id].append(line)
        if job_id in _job_subscribers:
            for q in _job_subscribers[job_id]:
                await q.put(line)

    return {"ok": True}


@router.post("/{agent_id}/jobs/{job_id}/complete")
async def complete_job(
    agent_id: str,
    job_id: str,
    body: CompleteRequest,
    current_user: dict = Depends(get_current_user)
):
    with db.engine.connect() as conn:
        conn.execute(text("""
            UPDATE agent_jobs
            SET status = :status, completed_at = NOW(), summary = CAST(:summary AS jsonb)
            WHERE job_id = :job_id
        """), {
            "status": body.status,
            "summary": json.dumps(body.summary),
            "job_id": job_id,
        })
        conn.commit()

    if job_id in _job_subscribers:
        for q in _job_subscribers[job_id]:
            await q.put(None)

    return {"ok": True}


async def dispatch_and_wait(agent_id: str, job_type: str, params: dict, timeout: float = 120.0) -> list:
    """Dispatch a job to an agent, block until complete, return accumulated stream lines."""
    job_id = uuid.uuid4().hex[:24]

    with db.engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO agent_jobs (job_id, agent_id, job_type, params, status)
            VALUES (:job_id, :agent_id, :job_type, CAST(:params AS jsonb), 'PENDING')
        """), {
            "job_id":   job_id,
            "agent_id": agent_id,
            "job_type": job_type,
            "params":   json.dumps(params),
        })
        conn.commit()

    if agent_id not in _job_queues:
        _job_queues[agent_id] = asyncio.Queue()
    if job_id not in _job_streams:
        _job_streams[job_id] = []

    done_q: asyncio.Queue = asyncio.Queue()
    _job_subscribers.setdefault(job_id, []).append(done_q)

    await _job_queues[agent_id].put({"job_id": job_id, "job_type": job_type, "params": params})

    try:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = max(deadline - loop.time(), 0.5)
            item = await asyncio.wait_for(done_q.get(), timeout=remaining)
            if item is None:
                break
    except asyncio.TimeoutError:
        raise TimeoutError(f"Agent did not complete job within {int(timeout)}s")
    finally:
        subs = _job_subscribers.get(job_id, [])
        if done_q in subs:
            subs.remove(done_q)

    return list(_job_streams.get(job_id, []))


# ── Agent deployment ────────────────────────────────────────────────────────────

def _get_orca_base_url() -> str:
    configured = os.environ.get("ORCA_SERVER_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    ssl_cert = getattr(cfg, "SSL_CERTFILE", None)
    protocol = "https" if ssl_cert and os.path.exists(ssl_cert) else "http"
    return f"{protocol}://{ip}:8000"


def _get_psexec_path() -> Path:
    configured = getattr(cfg, "PSEXEC_PATH", None)
    if configured and Path(configured).exists():
        return Path(configured)
    return Path(__file__).parent / "bin" / "psexec.exe"


class DeployAgentRequest(BaseModel):
    ip: str
    username: str
    password: str
    domain: Optional[str] = None
    transport: str = "SMB_TASK"  # "SMB_TASK" (default, port 445 only) or "WINRM" (opt-in fallback, needs port 5985)


_AGENT_BIN_MAP = {
    "velociraptor.exe": "velociraptor.exe",
    "clamscan.exe":     os.path.join("clamav", "clamscan.exe"),
    "grype.exe":        os.path.join("syftgrype", "grype.exe"),
    "syft.exe":         os.path.join("syftgrype", "syft.exe"),
}

@router.get("/download/bin/{filename}")
async def download_binary(filename: str, current_user: dict = Depends(get_current_user)):
    if filename not in _AGENT_BIN_MAP:
        raise HTTPException(404, f"Binary not available for agent deployment: {filename}")
    bin_root = Path(__file__).parent / "bin"
    file_path = bin_root / _AGENT_BIN_MAP[filename]
    if not file_path.exists():
        raise HTTPException(404, f"{filename} not present on server")
    return Response(
        content=file_path.read_bytes(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/download/orca_agent.py")
async def download_orca_agent():
    agent_path = Path(__file__).parent.parent / "agent" / "orca_agent.py"
    if not agent_path.exists():
        raise HTTPException(404, "Agent script not found on server")
    return Response(
        content=agent_path.read_bytes(),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=orca_agent.py"},
    )


@router.get("/deploy/psexec-status")
async def deploy_psexec_status(current_user: dict = Depends(get_current_user)):
    p = _get_psexec_path()
    return {"available": p.exists(), "path": str(p)}


@router.post("/deploy")
async def deploy_agent(
    body: DeployAgentRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    orca_url = _get_orca_base_url()

    # Generate a dedicated long-lived agent token — independent of the deploying user's session
    agent_token = create_access_token(
        data={
            "sub": f"agent@{body.ip}",
            "role": "agent",
            "id": None,
            "initials": "AG",
        },
        expires_delta=timedelta(days=365),
    )

    config_obj = {
        "server_url": orca_url,
        "token": agent_token,
        "bin_dir": "./bin",
        "poll_interval": 5,
    }
    config_b64 = base64.b64encode(json.dumps(config_obj).encode()).decode()

    ps_script = (
        "$d='C:\\ORCA_Agent';"
        "New-Item -ItemType Directory -Force $d | Out-Null;"
        "New-Item -ItemType Directory -Force \"$d\\bin\" | Out-Null;"
        # Disable cert validation only for this download (self-signed server cert)
        "Add-Type -TypeDefinition '"
        "using System.Net;using System.Security.Cryptography.X509Certificates;"
        "public class SC:ICertificatePolicy{"
        "public bool CheckValidationResult(ServicePoint s,X509Certificate c,WebRequest r,int e){return true;}"
        "}';"
        "[System.Net.ServicePointManager]::CertificatePolicy=New-Object SC;"
    )
    ps_script += (
        f"(New-Object Net.WebClient).DownloadFile("
        f"'{orca_url}/api/agent/download/orca_agent.py',"
        f"'C:\\ORCA_Agent\\orca_agent.py');"
    )
    ps_script += (
        f"[IO.File]::WriteAllText('C:\\ORCA_Agent\\config.json',"
        f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{config_b64}')));"
    )
    ps_script += (
        "pip install requests --quiet 2>$null;"
        "schtasks /delete /tn ORCA_Agent /f 2>$null;"
        "schtasks /create /tn ORCA_Agent"
        " /tr 'python C:\\ORCA_Agent\\orca_agent.py'"
        " /sc ONSTART /ru SYSTEM /f;"
        "Start-Process python"
        " -ArgumentList 'C:\\ORCA_Agent\\orca_agent.py'"
        " -WindowStyle Hidden"
    )

    deploy_analyst_id = current_user.get("id")

    async def generate():
        def sse(type_, data):
            return f"data: {json.dumps({'type': type_, 'data': data})}\n\n"

        transport = (body.transport or "SMB_TASK").upper()
        transport_label = "WinRM" if transport == "WINRM" else "SMB/Task Scheduler"
        yield sse("log", f"Connecting to {body.ip} as {body.username} ({transport_label})...")

        # ps_script uses only single-quoted PS string literals, so it is safe to
        # embed verbatim inside a double-quoted -Command argument.
        command = f'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{ps_script}"'

        yield sse("log", "Triggering deployment script on target (this may take 30-60s)...")

        try:
            rc, stdout, err = await asyncio.wait_for(
                vr_remote.run_remote_command(body.ip, body.username, body.password, body.domain, command, timeout=60, transport=transport),
                timeout=120,
            )
        except asyncio.TimeoutError:
            yield sse("error", "Deployment timed out after 120s — target may be slow")
            yield sse("done", "FAILED")
            return

        err_lower = err.lower()
        if any(e in err_lower for e in ["access is denied", "authentication failed", "unauthorized", "logon failure",
                                         "user name or password is incorrect", "status_logon_failure"]):
            yield sse("error", f"Authentication failed — check credentials: {err[:200]}")
            yield sse("done", "FAILED")
            return
        if any(e in err_lower for e in ["network path was not found", "winrm_timeout", "smb_task_timeout",
                                         "connection refused", "could not find", "rpc server is unavailable"]):
            port_hint = "WinRM (5985)" if transport == "WINRM" else "SMB (445)"
            yield sse("error", f"Host unreachable or {port_hint} not enabled: {err[:200]}")
            yield sse("done", "FAILED")
            return
        if rc != 0:
            yield sse("error", f"Remote trigger failed (exit {rc}): {err[:300]}")
            yield sse("done", "FAILED")
            return

        yield sse("log", "Agent files deployed — waiting for registration (up to 45s)...")

        for i in range(9):
            await asyncio.sleep(5)
            with db.engine.connect() as conn:
                row = conn.execute(text("""
                    SELECT agent_id, hostname FROM agent_registrations
                    WHERE last_seen > NOW() - INTERVAL '60 seconds'
                      AND analyst_id = :analyst_id
                    ORDER BY last_seen DESC LIMIT 1
                """), {"analyst_id": deploy_analyst_id}).fetchone()
            if row:
                yield sse("log", f"Agent online: {row[1]} ({row[0]})")
                yield sse("done", "SUCCESS")
                return
            yield sse("log", f"Waiting... ({(i+1)*5}s)")

        yield sse("log", "Agent deployed but not yet visible — check AGENT_FLEET in 60s")
        yield sse("done", "SUCCESS")

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
