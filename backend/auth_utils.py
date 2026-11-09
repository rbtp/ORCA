import os
import logging
from datetime import datetime, timedelta
from typing import Optional
import jwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status, Cookie
from starlette.concurrency import run_in_threadpool

SECRET_KEY = os.environ.get("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("FATAL: JWT_SECRET environment variable is not set")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(str(password))

get_password_hash = hash_password

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ── Auth dependency ───────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    orca_token: Optional[str] = Cookie(None),
) -> dict:
    """
    Resolves the caller's JWT from (in priority order):
      1. orca_token HttpOnly cookie  — browser / SSE (same-origin EventSource)
      2. Authorization: Bearer …    — Python agent polling
      3. ?token= query parameter     — PowerShell WebClient agent download

    Agent tokens (role == "agent") are restricted to /api/agent/* routes.
    """
    token = orca_token

    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        token = request.query_params.get("token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

    if payload.get("role") == "agent":
        # Agent tokens are standalone long-lived credentials (no user id),
        # not user sessions, so the per-user check below doesn't apply.
        if not request.url.path.startswith("/api/agent"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent tokens cannot access this endpoint")
        return payload

    # User session: the JWT alone isn't trusted for account state. The users
    # row is re-read on every request so that deactivation, password
    # change/reset (both bump token_version) and account deletion end
    # existing sessions immediately, and role/initials changes apply without
    # a re-login. Pre-token_version tokens carry no "tv" claim -> version 0.
    user = await run_in_threadpool(_load_session_user, payload.get("id"))
    if (
        user is None
        or not user["is_active"]
        or int(payload.get("tv", 0)) != user["token_version"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SESSION_REVOKED",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload["sub"] = user["username"]
    payload["role"] = user["role"]
    payload["initials"] = user["initials"]
    payload["tv"] = user["token_version"]
    return payload


def _load_session_user(user_id) -> Optional[dict]:
    if user_id is None:
        return None
    # Imported here, not at module top: auth_utils is imported very early
    # by many modules, and the DB manager connects on import.
    from core.database_manager import db
    from sqlalchemy import text
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT username, role, initials, is_active, token_version "
            "FROM users WHERE id = :id"
        ), {"id": user_id}).mappings().first()
    return dict(row) if row else None

# ── Admin guard ───────────────────────────────────────────────────────────────

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="ADMIN_ROLE_REQUIRED")
    return current_user

# ── Case-assignment guard ─────────────────────────────────────────────────────

def user_can_access_case(current_user: dict, case_name: str) -> bool:
    """True if current_user may act on this case's assets (deploy/dispatch/
    package endpoints). Admins always can. A case with no rows in
    case_assignments is unrestricted -- open to every analyst, same as before
    this table existed -- so an existing case nobody has ever assigned stays
    fully working; a case only becomes access-restricted once someone
    deliberately assigns specific people to it.
    """
    if current_user.get("role") == "admin":
        return True
    from core.database_manager import db
    from sqlalchemy import text
    with db.engine.connect() as conn:
        total = conn.execute(text(
            "SELECT COUNT(*) FROM case_assignments WHERE case_name = :name"
        ), {"name": case_name}).scalar()
        if not total:
            return True
        row = conn.execute(text(
            "SELECT 1 FROM case_assignments WHERE case_name = :name AND user_id = :uid"
        ), {"name": case_name, "uid": current_user.get("id")}).first()
        return row is not None
