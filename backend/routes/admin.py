# backend/routes/admin.py
from fastapi import APIRouter, Depends, HTTPException
from auth_utils import get_current_user, get_password_hash
from core.database_manager import db
from sqlalchemy import text
from typing import Optional

router = APIRouter(prefix="/api/admin", tags=["Admin"])

@router.get("/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    # Verify the requester is an admin
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="ADMIN_PRIVILEGES_REQUIRED")
    
    try:
        with db.engine.connect() as conn:
            # Use explicit column names for cleaner mapping
            query = text("SELECT username, initials, role FROM users")
            result = conn.execute(query).fetchall()
            
            # Mapping results to a list of dicts safely
            return [
                {
                    "username": row[0], 
                    "initials": row[1], 
                    "role": row[2]
                } for row in result
            ]
    except Exception as e:
        print(f"DATABASE_FETCH_ERROR: {e}")
        raise HTTPException(status_code=500, detail="INTERNAL_REGISTRY_ERROR")

@router.post("/users/create")
async def create_user(user_data: dict, current_user: dict = Depends(get_current_user)):
    # Verify the requester is an admin
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="ADMIN_PRIVILEGES_REQUIRED")
    
    # Check for required fields
    required = ["username", "password", "initials", "role"]
    if not all(k in user_data for k in required):
        raise HTTPException(status_code=400, detail="MISSING_USER_PARAMETERS")

    try:
        hashed_pw = get_password_hash(user_data["password"])
        
        with db.engine.connect() as conn:
            # 1. Check if user already exists
            check = conn.execute(
                text("SELECT 1 FROM users WHERE username = :u"), 
                {"u": user_data["username"]}
            ).fetchone()
            
            if check:
                raise HTTPException(status_code=400, detail="OPERATOR_ALREADY_EXISTS")

            # 2. Insert new user
            conn.execute(text("""
                INSERT INTO users (username, password_hash, initials, role)
                VALUES (:u, :p, :i, :r)
            """), {
                "u": user_data["username"],
                "p": hashed_pw,
                "i": user_data["initials"],
                "r": user_data["role"]
            })
            conn.commit()
            
        return {"status": "USER_CREATED", "operator": user_data["username"]}
        
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"USER_CREATION_FAILURE: {e}")
        raise HTTPException(status_code=500, detail="FAILED_TO_COMMIT_OPERATOR")

@router.delete("/users/{username}")
async def delete_user(username: str, current_user: dict = Depends(get_current_user)):
    # 1. Check Permissions
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="ADMIN_PRIVILEGES_REQUIRED")
    
    # 2. Prevent Self-Deletion (Safety Lock)
    if current_user.get("sub") == username:
        raise HTTPException(status_code=400, detail="CANNOT_DELETE_SELF")

    try:
        with db.engine.connect() as conn:
            # Check if user exists first
            check = conn.execute(
                text("SELECT 1 FROM users WHERE username = :u"), 
                {"u": username}
            ).fetchone()
            
            if not check:
                raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

            conn.execute(text("DELETE FROM users WHERE username = :u"), {"u": username})
            conn.commit()
            
        return {"status": "OPERATOR_PURGED", "target": username}
        
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"USER_DELETION_FAILURE: {e}")
        raise HTTPException(status_code=500, detail="FAILED_TO_PURGE_OPERATOR")

@router.get("/audit-log")
async def get_audit_log(
    case_name: Optional[str] = None,
    asset_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user),
):
    # Verify the requester is an admin
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="ADMIN_PRIVILEGES_REQUIRED")

    query = "SELECT id, ts, username, user_initials, action, case_name, asset_id, asset_hostname, t_code, details FROM audit_log WHERE 1=1"
    params = {}
    if case_name:
        query += " AND case_name = :case_name"
        params["case_name"] = case_name
    if asset_id is not None:
        query += " AND asset_id = :asset_id"
        params["asset_id"] = asset_id
    query += " ORDER BY ts DESC LIMIT 1000"

    try:
        with db.engine.connect() as conn:
            rows = conn.execute(text(query), params).mappings().fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        print(f"AUDIT_LOG_FETCH_ERROR: {e}")
        raise HTTPException(status_code=500, detail="INTERNAL_REGISTRY_ERROR")