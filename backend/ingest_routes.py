"""
ingest_routes.py
Handles:
  POST /api/assets/{asset_id}/package           — generate + return download link + one-liner
  GET  /api/packages/{token}/bootstrap          — serve bootstrap PS1 (no JWT)
  GET  /api/packages/{token}/{filename}         — serve the ZIP file (no JWT)
  POST /api/ingest/remote/{asset_id}/start      — agent check-in notification
  POST /api/ingest/remote/{asset_id}/{t_code}   — receive JSONL evidence
  POST /api/ingest/remote/{asset_id}/status     — per-technique heartbeat
  POST /api/ingest/remote/{asset_id}/complete   — agent signals completion, auto-revokes token
  GET  /api/ingest/remote/{asset_id}/progress   — poll progress for UI
  DELETE /api/packages/{token}                  — manual revoke a token
"""

import json
import logging
import os
import zipfile
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, Depends, Header
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import text

from core.database_manager import db
from auth_utils import get_current_user
from config import cfg
from package_builder import (
    build_package,
    validate_package_token,
    increment_received,
    revoke_token,
    generate_bootstrap_ps1,
)
from evidence_normalizer import normalize_and_ingest

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_orca_base_url(request: Request) -> str:
    import socket
    forwarded = request.headers.get("X-Forwarded-Proto")
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("host")
    if forwarded and host:
        return f"{forwarded}://{host}".rstrip("/")
    base = str(request.base_url).rstrip("/")
    if "localhost" in base or "127.0.0.1" in base:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            lan_ip = s.getsockname()[0]
            s.close()
            port = request.url.port or 8000
            protocol = "https" if (cfg.SSL_CERTFILE and os.path.exists(cfg.SSL_CERTFILE)) else "http"
            return f"{protocol}://{lan_ip}:{port}"
        except Exception:
            pass
    return base


def _seed_technique_status(asset_id: int, t_code: str):
    with db.engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO artifact_results (asset_id, t_code, technique_status)
            VALUES (:asset_id, :t_code, 'UNCLAIMED')
            ON CONFLICT (asset_id, t_code) DO NOTHING
        """), {"asset_id": asset_id, "t_code": t_code})


def _write_technique_verdict(asset_id: int, t_code: str, verdict: str, evidence_imported: bool = False):
    with db.engine.begin() as conn:
        conn.execute(text("""
            UPDATE artifact_results
            SET verdict = :verdict,
                evidence_imported = :evidence_imported
            WHERE asset_id = :asset_id AND t_code = :t_code
        """), {
            "verdict": verdict,
            "evidence_imported": evidence_imported,
            "asset_id": asset_id,
            "t_code": t_code,
        })


def _upsert_technique_run_log(asset_id: int, t_code: str, status: str, detail: str = "", hostname: str = ""):
    entry = json.dumps({"status": status, "detail": detail, "hostname": hostname, "ts": datetime.utcnow().isoformat()})
    with db.engine.begin() as conn:
        conn.execute(text("""
            UPDATE artifact_results
            SET evidence_summary = :entry
            WHERE asset_id = :asset_id AND t_code = :t_code
        """), {"entry": entry, "asset_id": asset_id, "t_code": t_code})


# ── Generate package ──────────────────────────────────────────────────────────

@router.post("/api/assets/{asset_id}/package")
async def generate_package(asset_id: int, request: Request, current_user=Depends(get_current_user)):
    orca_url = _get_orca_base_url(request)
    try:
        result = build_package(
            asset_id=asset_id,
            user_id=current_user["id"],
            orca_url=orca_url,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Package build failed for asset %d", asset_id)
        raise HTTPException(status_code=500, detail=f"Package build failed: {e}")


# ── Bootstrap PS1 ─────────────────────────────────────────────────────────────

@router.get("/api/packages/{token}/bootstrap")
async def download_bootstrap(token: str):
    """
    Serve a minimal bootstrap PS1 with token baked in.
    No JWT required — token is single-asset scoped and auto-revokes on completion.
    One-liner on target: powershell -ExecutionPolicy Bypass -c "iex (iwr 'URL').Content"
    """
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT token, asset_id FROM package_tokens
            WHERE token = :token
              AND revoked = FALSE
              AND expires_at > NOW()
        """), {"token": token}).mappings().fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Token not found or expired")

    packages_root = Path(cfg.DATA_ROOT) / "packages"
    matching = list(packages_root.glob(f"orca_pkg_{token[:8]}_*.zip")) or \
               list(packages_root.glob(f"orca_triage_{token[:8]}_*.zip"))
    if not matching:
        raise HTTPException(status_code=404, detail="Package ZIP not found — regenerate package")

    zip_name = matching[0].name

    # Read orca_url from the config embedded in the ZIP at build time
    orca_url = None
    with zipfile.ZipFile(matching[0], "r") as z:
        if "orca_config.json" in z.namelist():
            config = json.loads(z.read("orca_config.json"))
            orca_url = config.get("orca_url")

    if not orca_url:
        raise HTTPException(status_code=500, detail="Could not determine ORCA URL from package")

    bootstrap_ps1 = generate_bootstrap_ps1(
        token=token,
        asset_id=row["asset_id"],
        orca_url=orca_url,
        zip_name=zip_name,
    )

    return PlainTextResponse(content=bootstrap_ps1, media_type="text/plain")


# ── Serve ZIP ─────────────────────────────────────────────────────────────────

@router.get("/api/packages/{token}/{filename}")
async def download_package(token: str, filename: str):
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT token, asset_id FROM package_tokens
            WHERE token = :token
              AND revoked = FALSE
              AND expires_at > NOW()
        """), {"token": token}).mappings().fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Package not found or expired")

    zip_path = Path(cfg.DATA_ROOT) / "packages" / filename
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="Package file not found — may have been cleaned up")

    return FileResponse(
        path=str(zip_path),
        media_type="application/zip",
        filename=filename,
    )


# ── Agent check-in ────────────────────────────────────────────────────────────

class StartPayload(BaseModel):
    hostname: str
    technique_count: int
    case_name: str


@router.post("/api/ingest/remote/{asset_id}/start")
async def agent_start(
    asset_id: int,
    payload: StartPayload,
    x_orca_token: str = Header(..., alias="X-ORCA-Token"),
):
    token_row = validate_package_token(x_orca_token, asset_id)
    if not token_row:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

    with db.engine.begin() as conn:
        conn.execute(text("""
            UPDATE assets SET hostname = :hostname WHERE id = :asset_id
        """), {"hostname": payload.hostname, "asset_id": asset_id})

    logger.info("Remote agent checked in: asset=%d host=%s techniques=%d",
                asset_id, payload.hostname, payload.technique_count)

    return {"status": "ok", "message": f"Ready. Expecting {payload.technique_count} techniques."}


# ── Per-technique heartbeat ───────────────────────────────────────────────────

class StatusPayload(BaseModel):
    t_code: str
    status: str
    detail: str = ""
    hostname: str = ""


@router.post("/api/ingest/remote/{asset_id}/status")
async def technique_status(
    asset_id: int,
    payload: StatusPayload,
    x_orca_token: str = Header(..., alias="X-ORCA-Token"),
):
    token_row = validate_package_token(x_orca_token, asset_id)
    if not token_row:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

    _seed_technique_status(asset_id, payload.t_code)
    _upsert_technique_run_log(asset_id, payload.t_code, payload.status, payload.detail, payload.hostname)

    logger.info("Remote status: asset=%d t_code=%s status=%s", asset_id, payload.t_code, payload.status)
    return {"status": "ok"}


# ── Evidence ingest ───────────────────────────────────────────────────────────

@router.post("/api/ingest/remote/{asset_id}/{t_code}")
async def ingest_remote_evidence(
    asset_id: int,
    t_code: str,
    request: Request,
    x_orca_token: str = Header(..., alias="X-ORCA-Token"),
    x_mode: str = Header("primary", alias="X-Mode"),
    x_hostname: str = Header("", alias="X-Hostname"),
):
    token_row = validate_package_token(x_orca_token, asset_id)
    if not token_row:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

    body = await request.body()
    body_str = body.decode("utf-8", errors="replace").strip()

    _seed_technique_status(asset_id, t_code)

    if not body_str or x_mode == "no_artifacts":
        _write_technique_verdict(asset_id, t_code, "NO_ARTIFACTS", evidence_imported=False)
        _upsert_technique_run_log(asset_id, t_code, "NO_ARTIFACTS", hostname=x_hostname)
        increment_received(x_orca_token)
        logger.info("Remote ingest NO_ARTIFACTS: asset=%d t_code=%s", asset_id, t_code)
        return {"status": "ok", "rows": 0, "verdict": "NO_ARTIFACTS"}

    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(body_str)
        tmp_path = tmp.name

    is_fallback = x_mode in ("fallback", "fallback_complete")

    try:
        rows_written = normalize_and_ingest(
            file_path=tmp_path,
            asset_id=asset_id,
            t_code=t_code,
            is_fallback=is_fallback,
        )
    finally:
        os.unlink(tmp_path)

    if rows_written > 0:
        with db.engine.begin() as conn:
            conn.execute(text("""
                UPDATE artifact_results
                SET evidence_imported = TRUE,
                    is_fallback = :is_fallback
                WHERE asset_id = :asset_id AND t_code = :t_code
            """), {"is_fallback": is_fallback, "asset_id": asset_id, "t_code": t_code})

    _upsert_technique_run_log(
        asset_id, t_code,
        "FALLBACK_COMPLETE" if is_fallback else "COMPLETE",
        detail=f"{rows_written} rows",
        hostname=x_hostname,
    )
    increment_received(x_orca_token)

    logger.info("Remote ingest: asset=%d t_code=%s rows=%d mode=%s", asset_id, t_code, rows_written, x_mode)
    return {"status": "ok", "rows": rows_written, "is_fallback": is_fallback}


# ── Agent completion + auto-revoke ────────────────────────────────────────────

@router.post("/api/ingest/remote/{asset_id}/complete")
async def agent_complete(
    asset_id: int,
    x_orca_token: str = Header(..., alias="X-ORCA-Token"),
):
    """
    Called by the PS1 agent just before self-delete.
    Revokes the token so it cannot be reused.
    Returns 200 even if already revoked — agent does not need to retry.
    """
    token_row = validate_package_token(x_orca_token, asset_id)
    if not token_row:
        return {"status": "ok", "message": "Token already inactive"}

    revoke_token(x_orca_token)
    logger.info("Agent self-reported complete, token auto-revoked: asset=%d token=%s",
                asset_id, x_orca_token[:8])
    return {"status": "ok", "message": "Token revoked. Collection complete."}


# ── Progress poll ─────────────────────────────────────────────────────────────

@router.get("/api/ingest/remote/{asset_id}/progress")
async def remote_progress(
    asset_id: int,
    current_user=Depends(get_current_user),
):
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT
                t_code,
                technique_status,
                verdict,
                evidence_imported,
                evidence_summary
            FROM artifact_results
            WHERE asset_id = :asset_id
            ORDER BY t_code
        """), {"asset_id": asset_id}).mappings().fetchall()

        token_row = conn.execute(text("""
            SELECT technique_count, techniques_received, completed_at, expires_at
            FROM package_tokens
            WHERE asset_id = :asset_id
              AND revoked = FALSE
              AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
        """), {"asset_id": asset_id}).mappings().fetchone()

    techniques = [dict(r) for r in rows]
    total = len(techniques)
    with_evidence = sum(1 for t in techniques if t["evidence_imported"])
    no_artifacts = sum(1 for t in techniques if t["verdict"] == "NO_ARTIFACTS")
    pending = total - with_evidence - no_artifacts

    return {
        "asset_id": asset_id,
        "total": total,
        "with_evidence": with_evidence,
        "no_artifacts": no_artifacts,
        "pending": pending,
        "techniques": techniques,
        "package_active": bool(token_row),
        "package_info": dict(token_row) if token_row else None,
    }


# ── Manual revoke ─────────────────────────────────────────────────────────────

@router.delete("/api/packages/{token}")
async def revoke_package(token: str, current_user=Depends(get_current_user)):
    with db.engine.begin() as conn:
        result = conn.execute(text("""
            UPDATE package_tokens
            SET revoked = TRUE, revoked_at = NOW()
            WHERE token = :token
            RETURNING asset_id
        """), {"token": token})
        row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Token not found")

    logger.info("Package token manually revoked: %s by user %d", token[:8], current_user["id"])
    return {"status": "revoked", "token": token}