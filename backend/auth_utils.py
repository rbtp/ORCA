import os
import logging
from datetime import datetime, timedelta
from typing import Optional
import jwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status, Cookie

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

    if payload.get("role") == "agent" and not request.url.path.startswith("/api/agent"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent tokens cannot access this endpoint")

    return payload

# ── Admin guard ───────────────────────────────────────────────────────────────

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="ADMIN_ROLE_REQUIRED")
    return current_user
