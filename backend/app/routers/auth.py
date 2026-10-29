"""Auth router — register and login."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import create_access_token, hash_password, verify_password
from app.database import get_session
from app.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])

_PASSWORD_RE = re.compile(r"^.{8,}$")   # min 8 chars


class RegisterRequest(BaseModel):
    email: EmailStr
    name: str
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not _PASSWORD_RE.match(v):
            raise ValueError("password must be at least 8 characters")
        return v

    @field_validator("name")
    @classmethod
    def name_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be empty")
        return v.strip()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    name: str


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserOut)
def register(body: RegisterRequest, session: Session = Depends(get_session)):
    user = User(
        id=str(uuid.uuid4()),
        email=body.email,
        name=body.name,
        password_hash=hash_password(body.password),
        created_at=datetime.now(timezone.utc),
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")
    return UserOut(id=user.id, email=user.email, name=user.name)


@router.post("/login")
def login(body: LoginRequest, session: Session = Depends(get_session)):
    user = session.query(User).filter(User.email == body.email).first()
    # Constant-time: always verify even if user not found
    _dummy_hash = "$2b$12$aaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    stored_hash = user.password_hash if user else _dummy_hash
    if not verify_password(body.password, stored_hash) or user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # AGENTS.md rule #6: token is returned to client, NOT logged
    token = create_access_token(user.id, user.email)
    return {"access_token": token, "token_type": "bearer"}

