"""Audit and evidence report router."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.audit import verify_chain
from app.database import get_session
from app.deps import get_current_user
from app.models import AuditEvent, Patch, Task, TestRun, User
from app.queries import scoped_query

router = APIRouter(tags=["audit"])


@router.get("/api/audit")
def get_audit_log(
    task_id: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Return audit events scoped to the calling user's tasks."""
    q = scoped_query(session, AuditEvent, user_id=current_user.id)
    if task_id:
        q = q.filter(AuditEvent.task_id == task_id)
    events = q.order_by(AuditEvent.created_at).all()
    return [
        {
            "id": e.id,
            "task_id": e.task_id,
            "actor": e.actor,
            "event_type": e.event_type,
            "detail_json": e.detail_json,
            "created_at": e.created_at.isoformat(),
        }
        for e in events
    ]


@router.get("/api/tasks/{task_id}/evidence")
def get_evidence(
    task_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Return the full evidence report for a task: patches, test runs, audit chain."""
    task = (
        scoped_query(session, Task, user_id=current_user.id)
        .filter(Task.id == task_id)
        .first()
    )
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    patches = (
        scoped_query(session, Patch, user_id=current_user.id)
        .filter(Patch.task_id == task_id)
        .all()
    )
    test_runs = (
        scoped_query(session, TestRun, user_id=current_user.id)
        .filter(TestRun.task_id == task_id)
        .all()
    )
    audit_events = (
        scoped_query(session, AuditEvent, user_id=current_user.id)
        .filter(AuditEvent.task_id == task_id)
        .order_by(AuditEvent.created_at)
        .all()
    )
    chain_valid, chain_msg = verify_chain(session)

    return {
        "task_id": task_id,
        "state": task.state,
        "patches": [{"id": p.id, "file_path": p.file_path, "diff": p.diff} for p in patches],
        "test_runs": [{"id": r.id, "passed": r.passed, "log": r.log} for r in test_runs],
        "audit_events": [
            {"id": e.id, "event_type": e.event_type, "actor": e.actor,
             "detail_json": e.detail_json, "created_at": e.created_at.isoformat()}
            for e in audit_events
        ],
        "audit_chain_valid": chain_valid,
        "audit_chain_message": chain_msg,
    }

