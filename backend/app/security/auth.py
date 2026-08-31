import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.models import User

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 (stdlib, no external deps needed)."""
    salt = secrets.token_hex(16)
    iterations = 200_000
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        algorithm, iterations, salt, expected = hashed.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        )
        computed = dk.hex()
        return hmac.compare_digest(computed, expected)
    except Exception:
        return False


def create_access_token(user_id: str, role: str, username: str) -> str:
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    payload = {
        "sub": user_id,
        "role": role,
        "username": username,
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    payload = decode_token(token)
    user_id = payload.get("sub")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    return user


ROLE_HIERARCHY = {
    "VIEWER": 0,
    "RESEARCHER": 1,
    "ANALYST": 2,
    "ADMIN": 3,
}


def require_role(min_role: str):
    min_level = ROLE_HIERARCHY.get(min_role, 0)

    def checker(user: User = Depends(get_current_user)) -> User:
        level = ROLE_HIERARCHY.get(user.role, 0)
        if level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role {min_role} or higher",
            )
        return user

    return checker


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def generate_synthetic_hex(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)
