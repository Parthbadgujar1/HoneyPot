from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import User
from app.schemas.response import TokenResponse
from app.security.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.services.audit import write_audit

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None
    role: str = "VIEWER"


def user_out(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at,
    }


@router.post("/register", status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    if payload.role not in ("ADMIN", "ANALYST", "RESEARCHER", "VIEWER"):
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    write_audit(
        db, action="user_registered", resource_type="user", resource_id=user.username
    )
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        write_audit(
            db,
            action="login_failed",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    user.last_login_at = datetime.utcnow()
    db.add(user)
    db.commit()
    token = create_access_token(user.id, user.role, user.username)
    write_audit(
        db,
        action="login_success",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
    )
    return TokenResponse(access_token=token, user=user_out(user))


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_out(user)
