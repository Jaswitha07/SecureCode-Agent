"""Database engine and session factory.

Reads DATABASE_URL from environment. Never logs the connection string
(AGENTS.md rule #6).

The engine is created lazily so that importing this module during tests
(where DATABASE_URL may not point at a live Postgres) does not fail.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://securecode:securecode@localhost:5432/securecode",
)

_engine = None
_SessionLocal = None


def _get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    return _engine


def _get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=_get_engine())
    return _SessionLocal


def get_session():
    """Dependency-injection helper for FastAPI."""
    SessionLocal = _get_session_factory()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
