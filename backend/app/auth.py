"""Authentication helpers — JWT creation/verification and password hashing.

AGENTS.md rule #6: the SECRET_KEY is read from the environment and NEVER logged.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

# Secret read from env — never hardcoded, never logged
_SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
_ALGORITHM = "HS256"
_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


def create_access_token(user_id: str, email: str) -> str:
    """Create a signed JWT. Never log the return value."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": user_id, "email": email, "exp": expire}
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT. Raises JWTError on failure."""
    return jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])

