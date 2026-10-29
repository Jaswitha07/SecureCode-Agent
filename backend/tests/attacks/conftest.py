"""Shared fixtures for the attack-scenario test suite.

Each attack test:
  1. Exercises a specific threat from SPEC.md.
  2. Asserts the attack IS BLOCKED (decision != "allow" or executor outcome == DENIED).
  3. Asserts the block IS RECORDED in the audit log with the right event_type.

The in-memory SQLite database is isolated per test function.
The ToolExecutor + PolicyEngine are exercised directly — no HTTP layer needed,
so we avoid bcrypt / network issues and test the actual security controls.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.models import Base, User, Project, Task, AuditEvent
from app.audit import append_audit_event


@pytest.fixture()
def db() -> Session:  # type: ignore[return]
    """Fresh in-memory SQLite session for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def task_id(db: Session) -> str:
    """Seed a minimal User → Project → Task so audit FK is satisfied."""
    user = User(
        id=str(uuid.uuid4()),
        email=f"{uuid.uuid4()}@test.example",
        name="attacker",
        password_hash="x",
    )
    db.add(user)
    db.flush()

    project = Project(
        id=str(uuid.uuid4()),
        user_id=user.id,
        name="attack-project",
        repo_path="/tmp/attack",
    )
    db.add(project)
    db.flush()

    task = Task(
        id=str(uuid.uuid4()),
        project_id=project.id,
        prompt="malicious prompt",
        state="EXECUTING",
        retries=0,
    )
    db.add(task)
    db.commit()
    return task.id


def make_executor(db: Session, task_id: str, project_root: str = "/tmp/safe"):
    """Build a ToolExecutor wired to the given session and task."""
    from app.tool_executor import ToolExecutor
    return ToolExecutor(
        project_root=project_root,
        session=db,
        task_id=task_id,
    )


def audit_events(db: Session, task_id: str) -> list[AuditEvent]:
    """Return all audit events for *task_id* ordered by creation time."""
    return (
        db.query(AuditEvent)
        .filter(AuditEvent.task_id == task_id)
        .order_by(AuditEvent.created_at)
        .all()
    )


def was_logged(db: Session, task_id: str, event_type: str) -> bool:
    """Return True if at least one audit event of *event_type* exists."""
    return any(e.event_type == event_type for e in audit_events(db, task_id))
