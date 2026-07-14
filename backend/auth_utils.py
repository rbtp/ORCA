import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer

# --- CONFIGURATION ---
SECRET_KEY = os.environ.get("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("FATAL: JWT_SECRET environment variable is not set")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# --- PASSWORD HELPERS ---
def hash_password(password: str) -> str:
    """Returns a salted bcrypt hash of the password."""
    return pwd_context.hash(str(password))

# Alias to match the import in admin.py
get_password_hash = hash_password

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain text password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)

# --- JWT HELPERS ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generates a signed JWT token for the user."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Decodes the JWT token and returns the user payload. 
    Used as a dependency for protected routes.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return payload # Returns dict containing username, role, and initials
    except JWTError:
        raise credentials_exception
    
def get_current_user_sse(
    token_query: Optional[str] = Query(None, alias="token"),
):
    """
    SSE-compatible auth dependency.
    Reads JWT from ?token= query parameter (EventSource cannot set headers).
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token_query:
        raise credentials_exception
    try:
        payload = jwt.decode(token_query, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception