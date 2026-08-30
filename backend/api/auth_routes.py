"""
Authentication API: POST /api/auth/login issues a JWT for the demo
in-memory users (see backend/auth/security.py for the credential list).
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from backend.auth.security import authenticate_user, create_access_token, get_current_user, User

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(user)
    return {"access_token": token, "token_type": "bearer", "role": user.role}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role}
