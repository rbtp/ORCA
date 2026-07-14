from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from core.database_manager import db 
from pydantic import BaseModel
from typing import Optional
import httpx  # For the external lookup proxy

# --- AUTH IMPORTS ---
from auth_utils import get_current_user

router = APIRouter(prefix="/api/ioc", tags=["ioc"])

class AddIOCRequest(BaseModel):
    value: str
    ioc_type: str
    case_name: str
    hostname: str
    t_code: str

@router.get("/search")
async def search_all_evidence(query: str, current_user: dict = Depends(get_current_user)):
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
            result = conn.execute(sql, {"term": f"%{query}%"})
            findings = [dict(row) for row in result.mappings()]
            
        return {
            "search_term": query,
            "total_hits": len(findings),
            "data": findings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/add")
async def add_discovered_ioc(req: AddIOCRequest, current_user: dict = Depends(get_current_user)):
    """Promotes a piece of evidence to a permanent IOC with automated context notes."""
    automated_note = f"Added from {req.case_name} investigation of {req.hostname} in Mitre Att&ck code {req.t_code}"
    
    sql = text("""
        INSERT INTO public.discovered_iocs (ioc_value, ioc_type, case_name, t_code, note)
        VALUES (:val, :type, :case, :tcode, :note)
        ON CONFLICT (ioc_value, case_name) DO UPDATE SET note = excluded.note
    """)
    
    try:
        with db.engine.connect() as conn:
            conn.execute(sql, {
                "val": req.value,
                "type": req.ioc_type,
                "case": req.case_name,
                "tcode": req.t_code,
                "note": automated_note
            })
            conn.commit()
        return {"status": "success", "value": req.value, "note": automated_note}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class LibraryIOCRequest(BaseModel):
    value: str
    indicator_type: str
    description: Optional[str] = ""
    threat_actor: Optional[str] = ""
    severity: Optional[str] = "HIGH"

@router.get("/library")
async def list_library_iocs(current_user: dict = Depends(get_current_user)):
    sql = text("""
        SELECT id, indicator_type, value, threat_actor, severity, description, added_at
        FROM public.ref_ioc_library
        ORDER BY added_at DESC
    """)
    try:
        with db.engine.connect() as conn:
            rows = conn.execute(sql).mappings()
            return [dict(r) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/library")
async def add_library_ioc(req: LibraryIOCRequest, current_user: dict = Depends(get_current_user)):
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
        import traceback
        print(f"[IOC_LIBRARY_ERROR] {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/library/{ioc_id}")
async def delete_library_ioc(ioc_id: int, current_user: dict = Depends(get_current_user)):
    sql = text("DELETE FROM public.ref_ioc_library WHERE id = :id")
    try:
        with db.engine.begin() as conn:
            conn.execute(sql, {"id": ioc_id})
        return {"status": "deleted", "id": ioc_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/enrich")
async def enrich_observable(observable: str, type: str, current_user: dict = Depends(get_current_user)):
    """Proxy endpoint for on-demand lookups."""
    try:
        summary = {
            "observable": observable,
            "type": type,
            "status": "Ready for API Integration",
            "external_links": [
                f"https://otx.alienvault.com/indicator/{type}/{observable}",
                f"https://www.virustotal.com/gui/search/{observable}"
            ]
        }
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Enrichment failed: {str(e)}")