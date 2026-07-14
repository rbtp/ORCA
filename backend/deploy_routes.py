"""
deploy_routes.py — SMB+Task Scheduler-triggered bulk remote deployment
Place in backend/ alongside main.py, ingest_routes.py, etc.
Triggers the deploy package via SMB + Task Scheduler RPC by default, with
WinRM available as an opt-in fallback (vr_remote.run_remote_command) — not
psexec.exe, which is a Windows PE and cannot execute from this Linux
container. SMB+Task Scheduler needs only port 445 + admin credentials (the
same prerequisites the original psexec path had); WinRM needs port 5985
enabled on the target, which isn't always possible. See COLLECTION_AUDIT.md
for the full diagnosis.
"""

import asyncio
import json
import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import text

from auth_utils import get_current_user
from config import cfg
from core.database_manager import db
from package_builder import build_package, build_triage_package

import vr_remote

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/deploy", tags=["deploy"])

_build_executor = ThreadPoolExecutor(max_workers=20)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_orca_base_url() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    port = 8000
    protocol = "https" if (cfg.SSL_CERTFILE and os.path.exists(cfg.SSL_CERTFILE)) else "http"
    return f"{protocol}://{ip}:{port}"


def _get_psexec_path() -> Path:
    configured = getattr(cfg, 'PSEXEC_PATH', None)
    if configured and Path(configured).exists():
        return Path(configured)
    return Path(__file__).parent / 'bin' / 'psexec.exe'


def _get_asset(asset_id: int) -> Optional[dict]:
    session = db.Session()
    try:
        row = session.execute(
            text("SELECT id, hostname, ip, case_name FROM assets WHERE id = :id"),
            {"id": asset_id}
        ).mappings().first()
        return dict(row) if row else None
    finally:
        session.close()


def _get_asset_full(asset_id: int) -> Optional[dict]:
    session = db.Session()
    try:
        row = session.execute(
            text("SELECT id, hostname, ip, case_name FROM assets WHERE id = :id"),
            {"id": asset_id}
        ).mappings().first()
        return dict(row) if row else None
    finally:
        session.close()


async def _run_remote_trigger(ip: str, username: str, password: str, command: str, domain: Optional[str] = None, transport: str = "SMB_TASK") -> tuple[int, str, str]:
    """Trigger a deploy command on the remote target via SMB+Task Scheduler (default) or WinRM (see vr_remote.run_remote_command)."""
    return await vr_remote.run_remote_command(ip, username, password, domain, command, timeout=60, transport=transport)


# ── Per-asset collection deployment ───────────────────────────────────────────

async def _deploy_single(
    asset_id: int,
    user_id: int,
    username: str,
    password: str,
    domain: Optional[str],
    queue: asyncio.Queue,
    transport: str = "SMB_TASK",
):
    async def emit(phase: str, message: str, error: str = None):
        await queue.put({
            'asset_id': asset_id,
            'phase': phase,
            'message': message,
            'error': error,
            'ts': datetime.utcnow().isoformat(),
        })

    asset = _get_asset(asset_id)
    if not asset:
        await emit('ERROR', f'Asset {asset_id} not found', 'ASSET_NOT_FOUND')
        return

    hostname = asset.get('hostname', str(asset_id))
    ip = (asset.get('ip') or '').strip()

    if not ip:
        await emit('ERROR', f'{hostname}: No IP address configured', 'NO_IP')
        return

    await emit('DEPLOYING', f'{hostname}: Building collection package...')
    try:
        loop = asyncio.get_event_loop()
        orca_url = _get_orca_base_url()
        pkg = await loop.run_in_executor(
            _build_executor,
            lambda: build_package(asset_id=asset_id, user_id=user_id, orca_url=orca_url)
        )
        oneliner = pkg.get('oneliner', '')
    except Exception as e:
        await emit('ERROR', f'{hostname}: Package build failed', str(e))
        return

    if not oneliner:
        await emit('ERROR', f'{hostname}: Package built but no deploy command returned', 'NO_ONELINER')
        return

    transport_label = 'WinRM' if transport.upper() == 'WINRM' else 'SMB/Task Scheduler'
    await emit('CONNECTING', f'{hostname} ({ip}): Establishing {transport_label} session...')
    await asyncio.sleep(0.2)
    await emit('AUTHENTICATING', f'{hostname}: Authenticating as {username}...')

    returncode, stdout, stderr = await _run_remote_trigger(ip, username, password, oneliner, domain, transport)
    stderr_lower = stderr.lower()

    auth_errors  = ['access is denied', 'authentication failed', 'unauthorized', 'logon failure',
                     'the user name or password is incorrect', 'status_logon_failure']
    reach_errors = ['network path was not found', 'could not find', 'winrm_timeout', 'smb_task_timeout',
                     'target machine actively refused', 'no route to host', 'connection refused',
                     'name or service not known', 'rpc server is unavailable']

    if any(e in stderr_lower for e in auth_errors):
        await emit('ERROR', f'{hostname}: Authentication failed — check credentials', stderr[:300])
        return

    if any(e in stderr_lower for e in reach_errors):
        port_hint = 'WinRM (5985)' if transport.upper() == 'WINRM' else 'SMB (445)'
        await emit('ERROR', f'{hostname}: Host unreachable or {port_hint} not enabled', stderr[:300])
        return

    if returncode == -1:
        await emit('ERROR', f'{hostname}: {stderr[:200]}', stderr[:300])
        return

    if returncode != 0:
        await emit('ERROR', f'{hostname}: Remote trigger failed (exit {returncode})', stderr[:300])
        return

    await emit('EXECUTING', f'{hostname}: Agent launched via {transport_label}')
    await asyncio.sleep(0.3)
    await emit('COLLECTING', f'{hostname}: Collection running — monitor progress in PKG panel')


# ── Routes ─────────────────────────────────────────────────────────────────────

class DeployRequest(BaseModel):
    asset_ids: List[int]
    username: str
    password: str
    domain: Optional[str] = None
    transport: str = "SMB_TASK"  # "SMB_TASK" (default, port 445 only) or "WINRM" (opt-in fallback, needs port 5985)


@router.post("/bulk")
async def deploy_bulk(req: DeployRequest, current_user=Depends(get_current_user)):
    if not req.asset_ids:
        raise HTTPException(400, "No assets selected")
    if not req.username or not req.password:
        raise HTTPException(400, "Credentials required")

    user_id = current_user.get("id", 0)

    async def event_stream():
        queue: asyncio.Queue = asyncio.Queue()
        sentinel = object()

        async def run_all():
            tasks = [
                _deploy_single(aid, user_id, req.username, req.password, req.domain, queue, req.transport)
                for aid in req.asset_ids
            ]
            await asyncio.gather(*tasks)
            await queue.put(sentinel)

        asyncio.create_task(run_all())

        while True:
            item = await queue.get()
            if item is sentinel:
                break
            yield json.dumps(item) + '\n'

    return StreamingResponse(event_stream(), media_type="application/x-ndjson")


@router.get("/psexec-status")
async def psexec_status(current_user=Depends(get_current_user)):
    psexec = _get_psexec_path()
    return {"available": psexec.exists(), "path": str(psexec)}


# ── Triage Collection ──────────────────────────────────────────────────────────

# Triage category names exposed to the UI
TRIAGE_CATEGORY_NAMES = [
    "Event Logs", "Prefetch", "MFT", "Registry", "Browser Artifacts",
    "LNK / Jump Lists", "Scheduled Tasks", "WMI Persistence",
    "SRUM", "Amcache", "Recycle Bin", "USB Artifacts",
]


class TriageRequest(BaseModel):
    asset_ids: List[int]
    username: str
    password: str
    categories: List[str]
    transport: str = "SMB_PSEXEC"  # artifact-collection transport (unused by this route — see /triage-execute)
    trigger_transport: str = "SMB_TASK"  # "SMB_TASK" (default, port 445 only) or "WINRM" (opt-in fallback, needs port 5985)
    domain: Optional[str] = None
    cleanup: bool = True


@router.get("/triage-categories")
async def get_triage_categories(current_user=Depends(get_current_user)):
    return {"categories": TRIAGE_CATEGORY_NAMES}


@router.post("/triage-execute")
async def triage_execute(request: Request, current_user=Depends(get_current_user)):
    body = await request.json()

    async def event_stream():
        async for chunk in vr_remote.run_triage_collection(
            asset_id=int(body["asset_id"]),
            ip=body["ip"],
            transport=body.get("transport", "WINRM"),
            username=body["username"],
            password=body.get("password", ""),
            categories=body.get("categories", TRIAGE_CATEGORY_NAMES),
            domain=body.get("domain"),
            cleanup=body.get("cleanup", True),
            vr_exe=getattr(cfg, 'VR_EXE_WINDOWS', None),
            data_root=getattr(cfg, 'DATA_ROOT', 'data'),
        ):
            yield chunk

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.post("/triage")
async def deploy_triage(req: TriageRequest, current_user=Depends(get_current_user)):
    if not req.asset_ids:
        raise HTTPException(400, "No assets selected")
    if not req.username or not req.password:
        raise HTTPException(400, "Credentials required")
    if not req.categories:
        raise HTTPException(400, "No triage categories selected")

    user_id = current_user.get("id", 0)

    async def event_stream():
        queue: asyncio.Queue = asyncio.Queue()
        sentinel = object()

        async def run_one(asset_id: int):
            async def emit(phase, message, error=None):
                await queue.put(json.dumps({
                    'asset_id': asset_id, 'phase': phase,
                    'message': message, 'error': error,
                }) + '\n')

            asset = _get_asset_full(asset_id)
            ip = (asset or {}).get('ip', '')
            if not asset or not ip:
                await emit('ERROR', f'Asset {asset_id}: missing or no IP', 'NO_IP')
                return

            hostname = asset.get('hostname', str(asset_id))
            await emit('STAGING', f'{hostname}: Building triage package...')
            try:
                loop = asyncio.get_event_loop()
                orca_url = _get_orca_base_url()
                pkg = await loop.run_in_executor(
                    _build_executor,
                    lambda: build_triage_package(
                        asset_id=asset_id,
                        user_id=user_id,
                        orca_url=orca_url,
                        categories=req.categories,
                    )
                )
                oneliner = pkg.get('oneliner', '')
            except Exception as e:
                await emit('ERROR', f'{hostname}: Package build failed — {e}', str(e))
                return

            trigger_label = 'WinRM' if req.trigger_transport.upper() == 'WINRM' else 'SMB/Task Scheduler'
            await emit('CONNECTING', f'{hostname} ({ip}): Deploying via {trigger_label}...')
            returncode, stdout, stderr = await _run_remote_trigger(ip, req.username, req.password, oneliner, req.domain, req.trigger_transport)
            stderr_lower = stderr.lower()

            if any(e in stderr_lower for e in ['access is denied', 'authentication failed', 'unauthorized', 'logon failure',
                                                'the user name or password is incorrect', 'status_logon_failure']):
                await emit('ERROR', f'{hostname}: Authentication failed', stderr[:300])
                return
            if any(e in stderr_lower for e in ['network path was not found', 'could not find', 'winrm_timeout', 'smb_task_timeout',
                                                'connection refused', 'rpc server is unavailable']):
                await emit('ERROR', f'{hostname}: Host unreachable', stderr[:300])
                return
            if returncode == -1:
                await emit('ERROR', f'{hostname}: {stderr[:200]}', stderr[:300])
                return
            if returncode != 0:
                await emit('ERROR', f'{hostname}: Remote trigger failed (exit {returncode})', stderr[:300])
                return

            await emit('COLLECTING', f'{hostname}: Triage agent launched — {pkg["technique_count"]} categories running')

        async def run_all():
            tasks = [run_one(aid) for aid in req.asset_ids]
            await asyncio.gather(*tasks)
            await queue.put(sentinel)

        asyncio.create_task(run_all())

        while True:
            item = await queue.get()
            if item is sentinel:
                break
            yield item

    return StreamingResponse(event_stream(), media_type="application/x-ndjson")