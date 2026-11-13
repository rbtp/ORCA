import asyncio
import base64
import hashlib
import json
import os
import socket
import tempfile
import threading
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy import text

from datetime import timedelta
from auth_utils import get_current_user, create_access_token, user_can_access_case
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

    # The bootstrap token minted at deploy time (role=agent, no agent_id — it
    # can't know its own agent_id yet, since that's only computed here from
    # the hostname it just reported) is only ever meant for this one /register
    # call. From here on the agent switches to this freshly-scoped token,
    # which ties role=agent to this specific agent_id — without that binding,
    # any deployed agent's token could poll/stream/complete jobs for every
    # OTHER agent too, since role=agent alone used to be enough.
    scoped_token = create_access_token(
        data={
            "sub": current_user.get("sub"),
            "role": "agent",
            "id": None,
            "initials": "AG",
            "agent_id": agent_id,
        },
        expires_delta=timedelta(days=365),
    )

    return {"agent_id": agent_id, "token": scoped_token}


@router.delete("/{agent_id}")
async def delete_agent(agent_id: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="ADMIN_PRIVILEGES_REQUIRED")
    with db.engine.connect() as conn:
        # _job_streams/_job_subscribers are keyed by job_id, not agent_id (see
        # the type comments at the top of this file) -- need this agent's own
        # job_ids before deleting the rows to actually clean those up; popping
        # `agent_id` out of a job_id-keyed dict was always a no-op.
        job_ids = [r[0] for r in conn.execute(
            text("SELECT job_id FROM agent_jobs WHERE agent_id = :id"), {"id": agent_id}
        ).fetchall()]
        conn.execute(text("DELETE FROM agent_jobs WHERE agent_id = :id"), {"id": agent_id})
        conn.execute(text("DELETE FROM agent_registrations WHERE agent_id = :id"), {"id": agent_id})
        conn.commit()
    _job_queues.pop(agent_id, None)
    for jid in job_ids:
        _job_streams.pop(jid, None)
        _job_subscribers.pop(jid, None)
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
    # Any analyst may use any online agent (shared fleet infrastructure --
    # matches /agent/list being open to all authenticated users), but the
    # ASSET this job analyzes must belong to a case they're actually
    # assigned to. All three dispatchers (memory/clamav/grype) send
    # params.asset_id; a job_type that doesn't include one has nothing to
    # check against and is left open, same as an unassigned case.
    asset_id = body.params.get("asset_id")
    if asset_id is not None:
        with db.engine.connect() as conn:
            asset_row = conn.execute(
                text("SELECT case_name FROM assets WHERE id = :id"), {"id": asset_id}
            ).fetchone()
        if asset_row and not user_can_access_case(current_user, asset_row[0]):
            raise HTTPException(status_code=403, detail="Not assigned to this investigation")

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
    # Check if job already finished so we can close immediately after replay,
    # and -- same reasoning as /dispatch above -- confirm the caller is
    # actually assigned to whatever case this job's asset belongs to before
    # handing them its live output.
    already_done = False
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT status, params->>'asset_id' AS asset_id FROM agent_jobs WHERE job_id = :id"
        ), {"id": job_id}).fetchone()
        if row:
            if row[0] in ("SUCCESS", "ERROR"):
                already_done = True
            if row[1] is not None:
                asset_row = conn.execute(
                    text("SELECT case_name FROM assets WHERE id = :id"), {"id": row[1]}
                ).fetchone()
                if asset_row and not user_can_access_case(current_user, asset_row[0]):
                    raise HTTPException(status_code=403, detail="Not assigned to this investigation")

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


def _require_agent_ownership(agent_id: str, current_user: dict):
    """Agent tokens are self-authenticating, but only for the specific
    agent_id they were scoped to at /register time; analyst tokens must own
    this agent. Shared by every endpoint an agent calls about its own jobs
    (poll/stream/complete) so a compromised agent token can't touch another
    agent's queue or forge its job results."""
    if current_user.get("role") == "agent":
        if str(current_user.get("agent_id")) != str(agent_id):
            raise HTTPException(status_code=403, detail="AGENT_ACCESS_DENIED")
    else:
        with db.engine.connect() as conn:
            row = conn.execute(text(
                "SELECT analyst_id FROM agent_registrations WHERE agent_id = :id"
            ), {"id": agent_id}).fetchone()
        if not row or str(row[0]) != str(current_user.get("id")):
            raise HTTPException(status_code=403, detail="AGENT_ACCESS_DENIED")


@router.get("/{agent_id}/jobs")
async def poll_jobs(
    agent_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    _require_agent_ownership(agent_id, current_user)

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
        sync_job_id = uuid.uuid4().hex[:24]
        with db.engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO agent_jobs (job_id, agent_id, job_type, params, status, started_at)
                VALUES (:job_id, :agent_id, 'folder_sync', CAST(:params AS jsonb), 'RUNNING', NOW())
            """), {
                "job_id": sync_job_id,
                "agent_id": agent_id,
                "params": json.dumps({"paths": sync_paths}),
            })
            conn.commit()
        return {
            "job_id": sync_job_id,
            "job_type": "folder_sync",
            "params": {"paths": sync_paths},
        }

    # Nothing queued — long-poll up to 30s for new analysis jobs. Polled
    # rather than `await wait_for(queue.get())`: that kept waiting after the
    # agent had gone (restarted, network drop) and then took the next job off
    # the queue for a connection nobody was reading -- the job was lost and
    # its caller timed out. Only take a job while the agent is still there.
    q = _job_queues[agent_id]
    loop = asyncio.get_event_loop()
    deadline = loop.time() + 30.0
    while loop.time() < deadline:
        if await request.is_disconnected():
            return None
        try:
            job = q.get_nowait()
        except asyncio.QueueEmpty:
            await asyncio.sleep(0.5)
            continue
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE agent_jobs SET status = 'RUNNING', started_at = NOW()
                WHERE job_id = :job_id
            """), {"job_id": job["job_id"]})
            conn.commit()
        return job
    return None


@router.post("/{agent_id}/jobs/{job_id}/stream")
async def receive_job_stream(
    agent_id: str,
    job_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    _require_agent_ownership(agent_id, current_user)

    body = await request.body()
    raw = body.decode(errors="replace")

    if job_id not in _job_streams:
        _job_streams[job_id] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if '"type": "progress"' in line:
            # Only the latest progress event is kept for replay: a scan of a
            # whole disk sends thousands of them.
            stream = _job_streams[job_id]
            if stream and '"type": "progress"' in stream[-1]:
                stream[-1] = line
            else:
                stream.append(line)
        else:
            _job_streams[job_id].append(line)
        if '"type": "done"' in line:
            # Saved here, server-side, so a long scan's results are kept even
            # if nobody has the Evidence Window open when it finishes.
            try:
                await run_in_threadpool(_persist_scan_result, job_id, line)
            except Exception as e:
                print(f"[AGENT] could not save results of job {job_id}: {e}")
        if job_id in _job_subscribers:
            for q in _job_subscribers[job_id]:
                await q.put(line)

    return {"ok": True, "cancel": job_id in _cancel_requests}


_cancel_requests: set = set()


def _persist_scan_result(job_id: str, line: str):
    """Stores a finished agent ClamAV / Grype job's results the same way the
    server-side scans do (clam_results / vuln_results), per asset."""
    with db.engine.connect() as conn:
        row = conn.execute(text("SELECT job_type, params FROM agent_jobs WHERE job_id = :id"), {"id": job_id}).fetchone()
    if not row or row[0] not in ("clamav", "grype"):
        return
    params = row[1] or {}
    asset_id = params.get("asset_id")
    if asset_id is None:
        return
    import collection_state
    if collection_state.is_deleted(asset_id):
        return   # asset/case deleted while the scan ran: don't leave orphan rows
    data = (json.loads(line).get("data") or {})
    with db.engine.begin() as conn:
        if row[0] == "clamav":
            conn.execute(text("""
                INSERT INTO clam_results (asset_id, scan_path, scanned, infected, threats, threat_details)
                VALUES (:aid, :path, :scanned, :infected, CAST(:threats AS jsonb), CAST(:details AS jsonb))
                ON CONFLICT (asset_id) DO UPDATE
                SET scan_path = EXCLUDED.scan_path, scanned = EXCLUDED.scanned,
                    infected = EXCLUDED.infected, threats = EXCLUDED.threats,
                    threat_details = EXCLUDED.threat_details, scanned_at = NOW()
            """), {"aid": int(asset_id), "path": params.get("scan_path"), "scanned": int(data.get("scanned_files") or 0),
                   "infected": int(data.get("infected_files") or 0), "threats": json.dumps(data.get("threats") or []),
                   "details": json.dumps(data.get("threat_details") or {})})
        else:
            conn.execute(text("DELETE FROM vuln_results WHERE asset_id = :id"), {"id": int(asset_id)})
            rows = []
            for m in data.get("vulnerabilities") or []:
                v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
                fix = v.get("fix") or {}
                rows.append({"asset_id": int(asset_id), "cve_id": (v.get("id") or "")[:50],
                             "severity": (v.get("severity") or "Unknown")[:20], "package": (a.get("name") or "")[:255],
                             "version": (a.get("version") or "")[:100],
                             "fix_version": ((fix.get("versions") or [""])[0] or "")[:100],
                             "fix_state": (fix.get("state") or "")[:50],
                             "sbom_path": f"agent:{params.get('scan_path')}", "vuln_path": None})
            if rows:
                conn.execute(text("""
                    INSERT INTO vuln_results
                        (asset_id, cve_id, severity, package, version, fix_version, fix_state, sbom_path, vuln_path)
                    VALUES (:asset_id, :cve_id, :severity, :package, :version, :fix_version, :fix_state, :sbom_path, :vuln_path)
                """), rows)


def _job_access(job_id: str, current_user: dict):
    """The job row, after checking the caller may see that job's asset."""
    if current_user.get("role") == "agent":
        raise HTTPException(status_code=403, detail="Not available to agent tokens")
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT job_id, job_type, status, params->>'asset_id' FROM agent_jobs WHERE job_id = :id"
        ), {"id": job_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No such job")
        if row[3] is not None:
            asset_row = conn.execute(text("SELECT case_name FROM assets WHERE id = :id"), {"id": int(row[3])}).fetchone()
            if asset_row and not user_can_access_case(current_user, asset_row[0]):
                raise HTTPException(status_code=403, detail="Not assigned to this investigation")
    return row


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, current_user: dict = Depends(get_current_user)):
    """STOP for a running agent scan: the agent is told on its next progress
    update (every few seconds) and stops its scanner."""
    row = _job_access(job_id, current_user)
    if row[2] not in ("PENDING", "RUNNING"):
        return {"ok": True, "status": row[2]}
    _cancel_requests.add(job_id)
    return {"ok": True, "status": "CANCELLING"}


@router.get("/jobs/active")
async def active_job(asset_id: int, job_type: str, current_user: dict = Depends(get_current_user)):
    """The scan of this type still running for this asset, if any, so a
    reopened Evidence Window can re-attach to its progress."""
    if current_user.get("role") == "agent":
        raise HTTPException(status_code=403, detail="Not available to agent tokens")
    with db.engine.connect() as conn:
        asset_row = conn.execute(text("SELECT case_name FROM assets WHERE id = :id"), {"id": asset_id}).fetchone()
        if asset_row and not user_can_access_case(current_user, asset_row[0]):
            raise HTTPException(status_code=403, detail="Not assigned to this investigation")
        rows = conn.execute(text("""
            SELECT j.job_id, j.agent_id, j.params->>'scan_path', j.created_at, ar.hostname
            FROM agent_jobs j LEFT JOIN agent_registrations ar ON ar.agent_id = j.agent_id
            WHERE j.job_type = :t AND j.params->>'asset_id' = :aid AND j.status IN ('PENDING', 'RUNNING')
            ORDER BY j.created_at DESC LIMIT 5
        """), {"t": job_type, "aid": str(asset_id)}).fetchall()
    # Only jobs this server process is still receiving (a restart loses them).
    for r in rows:
        if r[0] in _job_streams and r[0] not in _cancel_requests:
            return {"job_id": r[0], "agent_id": r[1], "scan_path": r[2], "started": str(r[3]), "hostname": r[4]}
    return None


@router.post("/{agent_id}/jobs/{job_id}/complete")
async def complete_job(
    agent_id: str,
    job_id: str,
    body: CompleteRequest,
    current_user: dict = Depends(get_current_user)
):
    _require_agent_ownership(agent_id, current_user)

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

    _cancel_requests.discard(job_id)
    if job_id in _job_subscribers:
        for q in _job_subscribers[job_id]:
            await q.put(None)

    return {"ok": True}


class BrowseRequest(BaseModel):
    path: str = ""
    asset_id: Optional[int] = None


@router.post("/{agent_id}/browse")
async def browse_agent(agent_id: str, body: BrowseRequest, current_user: dict = Depends(get_current_user)):
    """Lists a folder on the agent's computer (empty path = its drives) for the
    BROWSE dialogs (image path, ClamAV target, vuln-scan path)."""
    if current_user.get("role") == "agent":
        raise HTTPException(status_code=403, detail="Not available to agent tokens")
    if body.asset_id is not None:
        with db.engine.connect() as conn:
            asset_row = conn.execute(
                text("SELECT case_name FROM assets WHERE id = :id"), {"id": body.asset_id}
            ).fetchone()
        if asset_row and not user_can_access_case(current_user, asset_row[0]):
            raise HTTPException(status_code=403, detail="Not assigned to this investigation")
    with db.engine.connect() as conn:
        online = conn.execute(text("""
            SELECT 1 FROM agent_registrations
            WHERE agent_id = :a AND last_seen > NOW() - INTERVAL '90 seconds'
        """), {"a": agent_id}).fetchone()
    if not online:
        raise HTTPException(status_code=409, detail="That agent is offline")
    job_ref = {}
    try:
        lines = await dispatch_and_wait(agent_id, "list_dir", {"path": body.path}, timeout=30.0, job_ref=job_ref)
    except TimeoutError:
        raise HTTPException(status_code=504, detail="The agent did not answer within 30s (offline or busy?)")
    finally:
        _job_streams.pop(job_ref.get("job_id"), None)
    for line in lines:
        try:
            evt = json.loads(line)
        except Exception:
            continue
        data = evt.get("data") or {}
        if evt.get("type") == "error":
            raise HTTPException(status_code=422, detail=str(data.get("message")))
        if evt.get("type") == "done":
            return data
    raise HTTPException(status_code=502, detail="Agent returned no listing (agent version too old? Reinstall/update the agent)")


async def dispatch_and_wait(agent_id: str, job_type: str, params: dict, timeout: float = 120.0,
                            job_ref: Optional[dict] = None) -> list:
    """Dispatch a job to an agent, block until complete, return accumulated stream lines.
    job_ref, if given, receives the job_id (so the caller can free its buffered stream)."""
    job_id = uuid.uuid4().hex[:24]
    if job_ref is not None:
        job_ref["job_id"] = job_id

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
        # Without this, a job that times out here stays PENDING/RUNNING in
        # agent_jobs forever -- nothing else ever marks it terminal, since
        # the agent that would normally call /complete may never check in
        # again (offline, crashed, network partition).
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE agent_jobs SET status = 'TIMEOUT', completed_at = NOW()
                WHERE job_id = :job_id AND status IN ('PENDING', 'RUNNING')
            """), {"job_id": job_id})
            conn.commit()
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


class DeployAgentRequest(BaseModel):
    ip: str
    username: str
    password: str
    domain: Optional[str] = None
    transport: str = "SMB_TASK"  # "SMB_TASK" (default, port 445 only) or "WINRM" (opt-in fallback, needs port 5985)


_AGENT_BIN_MAP = {
    "velociraptor.exe": "velociraptor.exe",
    # clamscan.exe deliberately NOT listed as a standalone download here --
    # on Windows it dynamically links against libclamav.dll and a dozen
    # other DLLs sitting next to it, and needs main.cvd/daily.cld (its
    # signature database) to do anything at all. Downloading just the one
    # .exe (what this used to do) would fail to even launch on the agent,
    # or silently run with zero signatures if it somehow did. Served as
    # clamav.zip instead -- see _DIR_BUNDLES below, same reasoning
    # as arsenal.zip.
    "grype.exe":        os.path.join("syftgrype", "grype.exe"),
    "syft.exe":         os.path.join("syftgrype", "syft.exe"),
}

# Arsenal Image Mounter isn't a single-file binary -- aim_cli.exe needs its
# whole directory of dependent DLLs (~300MB across 800+ files) alongside it,
# so it's committed to git as individual files (backend/bin/arsenal/) rather
# than one archive, since a single pre-built zip would exceed GitHub's 100MB
# per-file limit. Zipped on first request and cached in /tmp (bin/ is a
# read-only mount in the container) for orca_agent.py to download as one file.
_ZIP_BUILD_LOCKS: dict = {}


def _cached_dir_zip(src_dir: Path, cache_name: str, compression: int, exclude_tmp: bool = False) -> Path:
    """Zip src_dir into the container's temp dir (bin/ is a read-only mount)
    and reuse it until any source file changes. Blocking: call it via
    run_in_threadpool, never directly from an async handler -- zipping the
    multi-GB Grype DB would otherwise freeze the whole backend.

    - Rebuilt when any source file is newer than the cached zip, so a
      refreshed Grype DB / ClamAV signatures reach agents without a
      container recreate.
    - One lock per cache file: concurrent first downloads wait for a single
      build instead of racing on the same .building file.
    """
    if not src_dir.is_dir():
        raise HTTPException(404, f"{src_dir.name}/ not present on server")
    cache = Path(tempfile.gettempdir()) / cache_name
    lock = _ZIP_BUILD_LOCKS.setdefault(cache_name, threading.Lock())

    def wanted(f: Path) -> bool:
        if not f.is_file():
            return False
        return not (exclude_tmp and any(part.startswith("tmp.") for part in f.relative_to(src_dir).parts))

    with lock:
        files = [f for f in src_dir.rglob("*") if wanted(f)]
        newest = max((f.stat().st_mtime for f in files), default=0)
        if cache.exists() and cache.stat().st_mtime >= newest:
            return cache
        tmp_path = cache.with_suffix(".building")
        with zipfile.ZipFile(tmp_path, "w", compression) as zf:
            for f in files:
                zf.write(f, f.relative_to(src_dir))
        os.replace(tmp_path, cache)
        return cache


_BIN_ROOT = Path(__file__).parent / "bin"

# Directory bundles served to agents as single zips:
#  - arsenal.zip: aim_cli.exe needs its whole directory of DLLs (~300MB, 800+
#    files). Committed as individual files because one pre-built zip would
#    exceed GitHub's 100MB per-file limit.
#  - clamav.zip: clamscan.exe needs its DLLs plus main.cvd/daily.cvd. tmp.*
#    are freshclam's scratch dirs, not needed to run clamscan.
#  - grype-db.zip: Grype refuses to run without a vulnerability DB (see
#    _run_grype in orca_agent.py). ZIP_STORED: already a compact multi-GB
#    binary DB, compressing it would just burn time.
_DIR_BUNDLES = {
    "arsenal.zip":  (_BIN_ROOT / "arsenal",                "orca_arsenal_cache.zip",  zipfile.ZIP_DEFLATED, False),
    "clamav.zip":   (_BIN_ROOT / "clamav",                 "orca_clamav_cache.zip",   zipfile.ZIP_STORED,   True),
    "grype-db.zip": (_BIN_ROOT / "syftgrype" / "grype-db", "orca_grype_db_cache.zip", zipfile.ZIP_STORED,   False),
}


@router.get("/download/bin/{filename}")
async def download_binary(filename: str, current_user: dict = Depends(get_current_user)):
    # FileResponse streams from disk -- never read multi-GB files into memory.
    if filename in _DIR_BUNDLES:
        src_dir, cache_name, compression, exclude_tmp = _DIR_BUNDLES[filename]
        zip_path = await run_in_threadpool(_cached_dir_zip, src_dir, cache_name, compression, exclude_tmp)
        return FileResponse(zip_path, media_type="application/octet-stream", filename=filename)
    if filename not in _AGENT_BIN_MAP:
        raise HTTPException(404, f"Binary not available for agent deployment: {filename}")
    file_path = _BIN_ROOT / _AGENT_BIN_MAP[filename]
    if not file_path.exists():
        raise HTTPException(404, f"{filename} not present on server")
    return FileResponse(file_path, media_type="application/octet-stream", filename=filename)


@router.get("/download/orca_agent.py")
async def download_orca_agent():
    agent_path = Path(__file__).parent / "agent" / "orca_agent.py"
    if not agent_path.exists():
        raise HTTPException(404, "Agent script not found on server")
    return Response(
        content=agent_path.read_bytes(),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=orca_agent.py"},
    )


@router.post("/mint-install-token")
async def mint_install_token(current_user: dict = Depends(get_current_user)):
    """
    For installs the SMB/WinRM deploy flow can't reach -- the Docker host
    itself (no self-SMB), or any machine you'd rather set up by hand. Mints
    the same kind of long-lived agent-scoped token /deploy generates, but
    just hands it back instead of pushing anything anywhere; the frontend
    turns it into a copy-paste install command (or pairs it with agent/install.bat).
    """
    orca_url = _get_orca_base_url()
    token = create_access_token(
        data={
            "sub": f"agent-manual@{current_user.get('sub', 'unknown')}",
            "role": "agent",
            "id": None,
            "initials": "AG",
        },
        expires_delta=timedelta(days=365),
    )
    return {"server_url": orca_url, "token": token}


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
