"""Query helper enforcing per-user project isolation (SPEC threat #9).

Every database query MUST go through ``scoped_query`` so that rows belonging
to other users are never returned.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Query, Session

from app.models import (
    Approval,
    AuditEvent,
    Patch,
    Plan,
    Project,
    Task,
    TestRun,
    ToolCall,
)

# Models that hang directly off Project (have project_id)
_PROJECT_CHILD = {Task}

# Models that hang off Task (have task_id)
_TASK_CHILDREN = {Plan, ToolCall, Patch, TestRun, Approval, AuditEvent}


def scoped_query(session: Session, model: type, *, user_id: UUID | str) -> Query:
    """Return a query for *model* filtered to only rows owned by *user_id*.

    Supports: Project, Task, and all task-child models (Plan, ToolCall,
    Patch, TestRun, Approval, AuditEvent).

    Raises ValueError for unsupported models.
    """
    uid = str(user_id)

    if model is Project:
        return session.query(model).filter(Project.user_id == uid)

    if model in _PROJECT_CHILD:
        # Join through Project to enforce user_id filter
        return (
            session.query(model)
            .join(Project, Task.project_id == Project.id)
            .filter(Project.user_id == uid)
        )

    if model in _TASK_CHILDREN:
        return (
            session.query(model)
            .join(Task, model.task_id == Task.id)
            .join(Project, Task.project_id == Project.id)
            .filter(Project.user_id == uid)
        )

    raise ValueError(f"scoped_query does not support model {model.__name__}")

