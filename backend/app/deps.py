"""Shared FastAPI dependencies: DB session, current user."""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.auth import decode_token
from app.database import get_session
from app.models import User

_bearer = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    session: Session = Depends(get_session),
) -> User:
    """Validate JWT and return the authenticated User row.

    Raises 401 for any invalid/expired/missing token.
    NEVER logs the token string (AGENTS.md rule #6).
    """
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(credentials.credentials)
        user_id: str = payload.get("sub", "")
    except JWTError:
        raise exc

    user = session.query(User).filter(User.id == user_id).first()
    if user is None:
        raise exc
    return user

