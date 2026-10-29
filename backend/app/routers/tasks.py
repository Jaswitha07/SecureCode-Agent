"""Tasks router — create, get status, approve, reject, patches, test-runs, plan."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.audit import append_audit_event
from app.database import get_session
from app.deps import get_current_user
from app.models import Approval, Patch, Plan, Project, Task, TestRun, User
from app.queries import scoped_query

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


# ── Schemas ───────────────────────────────────────────────────────

class TaskCreate(BaseModel):
    project_id: str
    prompt: str

    @field_validator("prompt")
    @classmethod
    def prompt_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("prompt must not be empty")
        return v.strip()


class TaskOut(BaseModel):
    id: str
    project_id: str
    prompt: str
    state: str
    retries: int


class ApprovalBody(BaseModel):
    reason: Optional[str] = ""


class PatchOut(BaseModel):
    id: str
    file_path: str
    diff: str


class TestRunOut(BaseModel):
    id: str
    passed: bool
    log: Optional[str] = ""


class PlanOut(BaseModel):
    id: Optional[str] = None
    steps_json: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────

def _get_owned_task(task_id: str, user: User, session: Session) -> Task:
    """Return the Task if it belongs to *user*, else raise 404."""
    task = (
        scoped_query(session, Task, user_id=user.id)
        .filter(Task.id == task_id)
        .first()
    )
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


# ── Endpoints ─────────────────────────────────────────────────────

@router.post("", status_code=status.HTTP_201_CREATED, response_model=TaskOut)
def create_task(
    body: TaskCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    # Verify the project belongs to this user
    project = (
        scoped_query(session, Project, user_id=current_user.id)
        .filter(Project.id == body.project_id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    task = Task(
        id=str(uuid.uuid4()),
        project_id=body.project_id,
        prompt=body.prompt,
        state="IDLE",
        retries=0,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(task)
    session.commit()
    return TaskOut(id=task.id, project_id=task.project_id,
                   prompt=task.prompt, state=task.state, retries=task.retries)


@router.get("/{task_id}", response_model=TaskOut)
def get_task(
    task_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    task = _get_owned_task(task_id, current_user, session)
    return TaskOut(id=task.id, project_id=task.project_id,
                   prompt=task.prompt, state=task.state, retries=task.retries)


@router.post("/{task_id}/approve", status_code=status.HTTP_200_OK)
def approve_task(
    task_id: str,
    body: ApprovalBody,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    task = _get_owned_task(task_id, current_user, session)

    if task.state != "APPROVAL":
        raise HTTPException(
            status_code=409,
            detail=f"Task is in state '{task.state}', not 'APPROVAL'. Cannot approve.",
        )

    approval = Approval(
        id=str(uuid.uuid4()),
        task_id=task.id,
        user_id=current_user.id,
        action="approve",
        reason=body.reason or "",
        created_at=datetime.now(timezone.utc),
    )
    session.add(approval)

    task.state = "EXECUTING"
    task.updated_at = datetime.now(timezone.utc)

    append_audit_event(
        session,
        task_id=task.id,
        actor="user",
        event_type="task_approved",
        detail_json=f'{{"user_id":"{current_user.id}","reason":"{body.reason or ""}"}}',
    )
    session.commit()
    return {"status": "approved", "task_id": task_id}


@router.post("/{task_id}/reject", status_code=status.HTTP_200_OK)
def reject_task(
    task_id: str,
    body: ApprovalBody,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    task = _get_owned_task(task_id, current_user, session)

    if task.state != "APPROVAL":
        raise HTTPException(
            status_code=409,
            detail=f"Task is in state '{task.state}', not 'APPROVAL'. Cannot reject.",
        )

    approval = Approval(
        id=str(uuid.uuid4()),
        task_id=task.id,
        user_id=current_user.id,
        action="reject",
        reason=body.reason or "",
        created_at=datetime.now(timezone.utc),
    )
    session.add(approval)

    task.state = "FAILED"
    task.updated_at = datetime.now(timezone.utc)

    append_audit_event(
        session,
        task_id=task.id,
        actor="user",
        event_type="task_rejected",
        detail_json=f'{{"user_id":"{current_user.id}","reason":"{body.reason or ""}"}}',
    )
    session.commit()
    return {"status": "rejected", "task_id": task_id}


@router.get("/{task_id}/patches", response_model=list[PatchOut])
def get_patches(
    task_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    _get_owned_task(task_id, current_user, session)   # ownership check
    patches = (
        scoped_query(session, Patch, user_id=current_user.id)
        .filter(Patch.task_id == task_id)
        .all()
    )
    return [PatchOut(id=p.id, file_path=p.file_path, diff=p.diff) for p in patches]


@router.get("/{task_id}/test-runs", response_model=list[TestRunOut])
def get_test_runs(
    task_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    _get_owned_task(task_id, current_user, session)
    runs = (
        scoped_query(session, TestRun, user_id=current_user.id)
        .filter(TestRun.task_id == task_id)
        .all()
    )
    return [TestRunOut(id=r.id, passed=r.passed, log=r.log or "") for r in runs]


@router.get("/{task_id}/plan", response_model=PlanOut)
def get_plan(
    task_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    _get_owned_task(task_id, current_user, session)
    plan = (
        scoped_query(session, Plan, user_id=current_user.id)
        .filter(Plan.task_id == task_id)
        .order_by(Plan.created_at.desc())
        .first()
    )
    if plan:
        return PlanOut(id=plan.id, steps_json=plan.steps_json)
    return PlanOut()

