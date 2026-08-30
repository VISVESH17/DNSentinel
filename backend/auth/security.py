"""
JWT authentication + role-based access control (RBAC) for DNSentinel's
admin/analyst endpoints (feed sync, PCAP upload, alert status changes).

Demo credentials (see docs/api.md) -- change SECRET_KEY and user store
before any real deployment. This is intentionally minimal (in-memory
user store) so the hackathon team can wire up a real user table later
without changing the token-issuing/verification contract.
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dnsentinel-hackathon-demo-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


class User(BaseModel):
    username: str
    role: str  # "admin" | "analyst" | "viewer"


# In-memory demo user store: username -> (bcrypt hash, role)
# admin/admin123, analyst/analyst123, viewer/viewer123
_DEMO_USERS = {
    "admin": {"hash": pwd_context.hash("admin123"), "role": "admin"},
    "analyst": {"hash": pwd_context.hash("analyst123"), "role": "analyst"},
    "viewer": {"hash": pwd_context.hash("viewer123"), "role": "viewer"},
}


def authenticate_user(username: str, password: str) -> Optional[User]:
    record = _DEMO_USERS.get(username)
    if not record or not pwd_context.verify(password, record["hash"]):
        return None
    return User(username=username, role=record["role"])


def create_access_token(user: User) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": user.username, "role": user.role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return User(username=payload["sub"], role=payload["role"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return decode_token(token)


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: require_role('admin', 'analyst')"""
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(allowed_roles)}",
            )
        return user
    return checker
