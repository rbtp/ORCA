from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from core.database_manager import db
from auth_utils import get_current_user
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/api/profiles", tags=["profiles"])


class ProfileCreateRequest(BaseModel):
    name: str
    tcodes: List[str]


class ProfileUpdateRequest(BaseModel):
    name: str = None
    tcodes: List[str] = None


@router.get("")
async def list_profiles(current_user: dict = Depends(get_current_user)):
    sql = text("SELECT id, name, tcodes, created_at, updated_at FROM investigation_profiles ORDER BY name")
    try:
        with db.engine.connect() as conn:
            rows = conn.execute(sql).mappings()
            return [dict(r) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("")
async def create_profile(req: ProfileCreateRequest, current_user: dict = Depends(get_current_user)):
    sql = text("""
        INSERT INTO investigation_profiles (name, tcodes)
        VALUES (:name, :tcodes)
        RETURNING id, name, tcodes, created_at, updated_at
    """)
    try:
        with db.engine.begin() as conn:
            result = conn.execute(sql, {"name": req.name.strip(), "tcodes": req.tcodes})
            row = result.mappings().first()
            if row is None:
                raise HTTPException(status_code=500, detail="INSERT returned no row")
            return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        if "unique" in str(e).lower():
            raise HTTPException(status_code=409, detail=f"Profile name '{req.name}' already exists")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{profile_id}")
async def update_profile(profile_id: int, req: ProfileUpdateRequest, current_user: dict = Depends(get_current_user)):
    fields = {}
    if req.name is not None:
        fields["name"] = req.name.strip()
    if req.tcodes is not None:
        fields["tcodes"] = req.tcodes

    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    set_clause = ", ".join(f"{k} = :{k}" for k in fields)
    set_clause += ", updated_at = NOW()"
    sql = text(f"""
        UPDATE investigation_profiles SET {set_clause}
        WHERE id = :profile_id
        RETURNING id, name, tcodes, created_at, updated_at
    """)
    try:
        with db.engine.begin() as conn:
            result = conn.execute(sql, {**fields, "profile_id": profile_id})
            row = result.mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="Profile not found")
            return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        if "unique" in str(e).lower():
            raise HTTPException(status_code=409, detail=f"Profile name already exists")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{profile_id}")
async def delete_profile(profile_id: int, current_user: dict = Depends(get_current_user)):
    sql = text("DELETE FROM investigation_profiles WHERE id = :id")
    try:
        with db.engine.begin() as conn:
            conn.execute(sql, {"id": profile_id})
        return {"status": "deleted", "id": profile_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tcodes/available")
async def list_available_tcodes(current_user: dict = Depends(get_current_user)):
    sql = text("SELECT t_code, name FROM ref_artifact_library ORDER BY t_code")
    try:
        with db.engine.connect() as conn:
            rows = conn.execute(sql).mappings()
            return [dict(r) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
