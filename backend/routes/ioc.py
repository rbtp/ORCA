import asyncio
import json
import logging
import threading
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from core.database_manager import db
from pydantic import BaseModel
from typing import Optional

from auth_utils import get_current_user

router = APIRouter(prefix="/api/ioc", tags=["ioc"])
logger = logging.getLogger(__name__)


# ── Models ─────────────────────────────────────────────────────────────────────

class AddIOCRequest(BaseModel):
    value: str
    ioc_type: str
    case_name: str
    hostname: str
    t_code: str

class LibraryIOCRequest(BaseModel):
    value: str
    indicator_type: str
    description: Optional[str] = ""
    threat_actor: Optional[str] = ""
    severity: Optional[str] = "HIGH"


# ── Library CRUD ───────────────────────────────────────────────────────────────

@router.get("/library")
def list_library_iocs(current_user: dict = Depends(get_current_user)):
    sql = text("""
        SELECT id, indicator_type, value, threat_actor, severity, description, added_at
        FROM public.ref_ioc_library
        ORDER BY added_at DESC
    """)
    try:
        with db.engine.connect() as conn:
            return [dict(r) for r in conn.execute(sql).mappings()]
    except Exception as e:
        logger.error("list_library_iocs failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to load IOC library")

@router.post("/library")
def add_library_ioc(req: LibraryIOCRequest, current_user: dict = Depends(get_current_user)):
    sql = text("""
        INSERT INTO public.ref_ioc_library (indicator_type, value, description, threat_actor, severity)
        VALUES (:indicator_type, :value, :description, :threat_actor, :severity)
        ON CONFLICT (value) DO UPDATE SET
            indicator_type = EXCLUDED.indicator_type,
            description = EXCLUDED.description,
            threat_actor = EXCLUDED.threat_actor,
            severity = EXCLUDED.severity
        RETURNING id, indicator_type, value, threat_actor, severity, description, added_at
    """)
    try:
        with db.engine.begin() as conn:
            result = conn.execute(sql, {
                "indicator_type": req.indicator_type,
                "value": req.value,
                "description": req.description,
                "threat_actor": req.threat_actor,
                "severity": req.severity,
            })
            row = result.mappings().first()
            if row is None:
                raise HTTPException(status_code=500, detail="INSERT returned no row")
            return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("add_library_ioc failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to save IOC")

@router.delete("/library/{ioc_id}")
def delete_library_ioc(ioc_id: int, current_user: dict = Depends(get_current_user)):
    try:
        with db.engine.begin() as conn:
            conn.execute(text("DELETE FROM public.ref_ioc_library WHERE id = :id"), {"id": ioc_id})
        return {"status": "deleted", "id": ioc_id}
    except Exception as e:
        logger.error("delete_library_ioc failed for id=%s: %s", ioc_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete IOC")


# ── Evidence search ────────────────────────────────────────────────────────────

@router.get("/search")
def search_all_evidence(query: str, current_user: dict = Depends(get_current_user)):
    sql = text("""
        SELECT
            c.name as case_origin,
            a.hostname,
            e.t_code,
            e.raw_data->>'Name' as artifact_alias,
            e.raw_data->>'ValueData' as evidence_detail,
            e.raw_data as full_context
        FROM public.cases c
        JOIN public.assets a ON c.name = a.case_name
        JOIN public.evidence e ON a.id = e.asset_id
        WHERE e.raw_data::text ILIKE :term
    """)
    try:
        with db.engine.connect() as conn:
            findings = [dict(r) for r in conn.execute(sql, {"term": f"%{query}%"}).mappings()]
        return {"search_term": query, "total_hits": len(findings), "data": findings}
    except Exception as e:
        logger.error("search_all_evidence failed: %s", e)
        raise HTTPException(status_code=500, detail="Search failed")


# ── IOC correlation — streaming SSE ───────────────────────────────────────────

_HIT_SQL = text("""
    SELECT c.name as case_origin, a.hostname, e.t_code,
           e.raw_data->>'Name' as artifact_alias
    FROM public.cases c
    JOIN public.assets a ON c.name = a.case_name
    JOIN public.evidence e ON a.id = e.asset_id
    WHERE e.raw_data::text ILIKE :term
    LIMIT 50
""")

@router.get("/correlate-stream")
async def correlate_stream(current_user: dict = Depends(get_current_user)):
    """Stream per-IOC correlation results as SSE.

    Runs the blocking DB loop in a daemon thread so the asyncio event loop
    stays free for other requests during the scan.
    """
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _push(obj):
        loop.call_soon_threadsafe(queue.put_nowait, json.dumps(obj))

    def scan_thread():
        try:
            with db.engine.connect() as conn:
                iocs = [dict(r) for r in conn.execute(
                    text("SELECT value FROM public.ref_ioc_library ORDER BY id")
                ).mappings()]

                total = len(iocs)
                _push({"phase": "START", "total": total})

                for i, ioc in enumerate(iocs):
                    hits = [dict(r) for r in conn.execute(
                        _HIT_SQL, {"term": f"%{ioc['value']}%"}
                    ).mappings()]

                    _push({
                        "phase": "IOC_RESULT",
                        "index": i + 1,
                        "total": total,
                        "value": ioc["value"],
                        "hits": [
                            {
                                "case_name": h["case_origin"],
                                "hostname": h["hostname"],
                                "t_code": h["t_code"],
                                "detail": h["artifact_alias"] or "Raw Match",
                            }
                            for h in hits
                        ],
                    })

            _push({"phase": "COMPLETE"})
        except Exception as e:
            logger.error("correlate_stream scan failed: %s", e)
            _push({"phase": "ERROR", "message": "Correlation scan failed"})
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

    threading.Thread(target=scan_thread, daemon=True).start()

    async def generate():
        while True:
            item = await queue.get()
            if item is None:
                break
            yield f"data: {item}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Promote evidence to IOC ────────────────────────────────────────────────────

@router.post("/add")
def add_discovered_ioc(req: AddIOCRequest, current_user: dict = Depends(get_current_user)):
    automated_note = (
        f"Added from {req.case_name} investigation of {req.hostname} "
        f"in Mitre Att&ck code {req.t_code}"
    )
    sql = text("""
        INSERT INTO public.discovered_iocs (ioc_value, ioc_type, case_name, t_code, note)
        VALUES (:val, :type, :case, :tcode, :note)
        ON CONFLICT (ioc_value, case_name) DO UPDATE SET
            ioc_type = excluded.ioc_type,
            t_code = excluded.t_code,
            note = excluded.note
    """)
    try:
        with db.engine.connect() as conn:
            conn.execute(sql, {
                "val": req.value, "type": req.ioc_type,
                "case": req.case_name, "tcode": req.t_code, "note": automated_note,
            })
            conn.commit()
        return {"status": "success", "value": req.value, "note": automated_note}
    except Exception as e:
        logger.error("add_discovered_ioc failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to promote IOC")


# ── Enrichment proxy ───────────────────────────────────────────────────────────

@router.get("/enrich")
def enrich_observable(observable: str, type: str, current_user: dict = Depends(get_current_user)):
    try:
        return {
            "observable": observable,
            "type": type,
            "status": "Ready for API Integration",
            "external_links": [
                f"https://otx.alienvault.com/indicator/{type}/{observable}",
                f"https://www.virustotal.com/gui/search/{observable}",
            ],
        }
    except Exception as e:
        logger.error("enrich_observable failed: %s", e)
        raise HTTPException(status_code=500, detail="Enrichment failed")
