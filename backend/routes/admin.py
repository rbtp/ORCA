# backend/routes/admin.py
from fastapi import APIRouter, Depends, HTTPException, Request
from auth_utils import get_current_user, get_password_hash
from core.database_manager import db
from sqlalchemy import text
from typing import Optional
from pydantic import BaseModel
import email_utils

router = APIRouter(prefix="/api/admin", tags=["Admin"])

# "agent" is minted automatically at /api/agent/register for deployed agent
# hosts, never created through this operator-facing form.
_ALLOWED_ROLES = {"admin", "analyst"}


def _get_orca_base_url(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-Proto")
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("host")
    if forwarded and host:
        return f"{forwarded}://{host}".rstrip("/")
    return str(request.base_url).rstrip("/")


def _require_admin(current_user: dict):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="ADMIN_PRIVILEGES_REQUIRED")


@router.get("/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    _require_admin(current_user)

    try:
        with db.engine.connect() as conn:
            query = text("SELECT username, initials, role, email, is_active, last_login FROM users ORDER BY username")
            result = conn.execute(query).fetchall()

            return [
                {
                    "username": row[0],
                    "initials": row[1],
                    "role": row[2],
                    "email": row[3],
                    "is_active": row[4],
                    "last_login": row[5].isoformat() if row[5] else None,
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

    if user_data["role"] not in _ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"INVALID_ROLE — must be one of {sorted(_ALLOWED_ROLES)}")

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

class InviteUserRequest(BaseModel):
    username: str
    initials: str
    role: str
    email: Optional[str] = None


@router.post("/users/invite")
async def invite_user(request: Request, body: InviteUserRequest, current_user: dict = Depends(get_current_user)):
    """Creates a pending invite instead of a real user row -- the invitee
    sets their own password on enrollment, so unlike /users/create no
    admin ever learns it. If an email is given and SMTP is configured the
    link is sent automatically; either way the link is also returned so
    it can be handed off manually (chat, in person) on airgapped
    instances with no mail relay."""
    _require_admin(current_user)

    if body.role not in _ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"INVALID_ROLE — must be one of {sorted(_ALLOWED_ROLES)}")
    initials = body.initials.strip().upper()
    if not initials or len(initials) > 5:
        raise HTTPException(status_code=400, detail="INITIALS_MUST_BE_1_TO_5_CHARS")

    with db.engine.begin() as conn:
        exists = conn.execute(text(
            "SELECT 1 FROM users WHERE username = :u"
        ), {"u": body.username}).first()
        if exists:
            raise HTTPException(status_code=400, detail="OPERATOR_ALREADY_EXISTS")

        pending = conn.execute(text("""
            SELECT 1 FROM enrollment_tokens
            WHERE username = :u AND used_at IS NULL AND expires_at > NOW()
        """), {"u": body.username}).first()
        if pending:
            raise HTTPException(status_code=400, detail="INVITE_ALREADY_PENDING_FOR_USERNAME")

        token_row = conn.execute(text("""
            INSERT INTO enrollment_tokens (username, initials, role, email, created_by, expires_at)
            VALUES (:u, :i, :r, :e, :cb, NOW() + INTERVAL '7 days')
            RETURNING token
        """), {
            "u": body.username, "i": initials, "r": body.role,
            "e": body.email, "cb": current_user.get("id"),
        }).fetchone()

    base_url = _get_orca_base_url(request)
    link = f"{base_url}/enroll/{token_row[0]}"

    emailed = False
    if body.email:
        emailed = email_utils.send_email(
            body.email, "You've been invited to ORCA",
            f"You've been invited to create an ORCA account as '{body.username}'.\n\n"
            f"Complete your enrollment: {link}\n\n"
            f"This link expires in 7 days.",
        )

    return {"status": "INVITED", "username": body.username, "link": link, "emailed": emailed}


class EditUserRequest(BaseModel):
    initials: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None


@router.patch("/users/{username}")
async def edit_user(username: str, body: EditUserRequest, current_user: dict = Depends(get_current_user)):
    _require_admin(current_user)

    fields, params = [], {"u": username}
    if body.initials is not None:
        initials = body.initials.strip().upper()
        if not initials or len(initials) > 5:
            raise HTTPException(status_code=400, detail="INITIALS_MUST_BE_1_TO_5_CHARS")
        fields.append("initials = :initials")
        params["initials"] = initials
    if body.role is not None:
        if body.role not in _ALLOWED_ROLES:
            raise HTTPException(status_code=400, detail=f"INVALID_ROLE — must be one of {sorted(_ALLOWED_ROLES)}")
        if username == current_user.get("sub") and body.role != "admin":
            # An admin demoting themselves could leave the instance with
            # zero admins and no way to promote anyone back -- block it
            # here rather than relying on the operator to notice.
            raise HTTPException(status_code=400, detail="CANNOT_CHANGE_OWN_ROLE")
        fields.append("role = :role")
        params["role"] = body.role
    if body.email is not None:
        fields.append("email = :email")
        params["email"] = body.email.strip() or None
    if not fields:
        raise HTTPException(status_code=400, detail="NO_FIELDS_TO_UPDATE")

    with db.engine.begin() as conn:
        result = conn.execute(text(
            f"UPDATE users SET {', '.join(fields)} WHERE username = :u"  # nosec B608 — fields built from a fixed allowlist above, values parameterized
        ), params)
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    return {"status": "OK", "username": username}


@router.post("/users/{username}/reset-password")
async def admin_reset_password(request: Request, username: str, current_user: dict = Depends(get_current_user)):
    """Admin-initiated reset: generates a one-time link instead of the
    admin choosing a new password directly, so the admin still never
    learns the account's password."""
    _require_admin(current_user)

    with db.engine.begin() as conn:
        row = conn.execute(text(
            "SELECT id, email FROM users WHERE username = :u"
        ), {"u": username}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="USER_NOT_FOUND")
        user_id, user_email = row

        token_row = conn.execute(text("""
            INSERT INTO password_reset_tokens (user_id, created_by, expires_at)
            VALUES (:uid, :cb, NOW() + INTERVAL '1 hour')
            RETURNING token
        """), {"uid": user_id, "cb": current_user.get("id")}).fetchone()

    base_url = _get_orca_base_url(request)
    link = f"{base_url}/reset-password/{token_row[0]}"

    emailed = False
    if user_email:
        emailed = email_utils.send_email(
            user_email, "ORCA password reset",
            f"An administrator initiated a password reset for your ORCA account.\n\n"
            f"Reset your password: {link}\n\n"
            f"This link expires in 1 hour.",
        )

    return {"status": "OK", "username": username, "link": link, "emailed": emailed}


@router.post("/users/{username}/toggle-active")
async def toggle_active(username: str, current_user: dict = Depends(get_current_user)):
    """Soft-disable/re-enable -- deactivated users fail login (see
    /api/auth/login) but their id stays intact for every FK that
    references it (audit_log, case_assignments, etc), unlike a hard
    delete."""
    _require_admin(current_user)

    if username == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="CANNOT_DEACTIVATE_SELF")

    with db.engine.begin() as conn:
        row = conn.execute(text(
            # On deactivation also bump token_version, so sessions that were
            # open at the time stay dead if the account is reactivated later
            # (is_active on the right-hand side is the pre-update value).
            "UPDATE users SET is_active = NOT is_active, "
            "token_version = token_version + CASE WHEN is_active THEN 1 ELSE 0 END "
            "WHERE username = :u RETURNING is_active"
        ), {"u": username}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    return {"status": "OK", "username": username, "is_active": row[0]}


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