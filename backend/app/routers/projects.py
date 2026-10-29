"""Projects router."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_session
from app.deps import get_current_user
from app.models import Project, User
from app.queries import scoped_query

router = APIRouter(prefix="/api/projects", tags=["projects"])


class ProjectCreate(BaseModel):
    name: str
    repo_path: str

    class Config:
        str_strip_whitespace = True
        str_min_length = 1


class ProjectOut(BaseModel):
    id: str
    name: str
    repo_path: str
    user_id: str


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ProjectOut)
def create_project(
    body: ProjectCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    project = Project(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        name=body.name,
        repo_path=body.repo_path,
        created_at=datetime.now(timezone.utc),
    )
    session.add(project)
    session.commit()
    return ProjectOut(
        id=project.id, name=project.name,
        repo_path=project.repo_path, user_id=project.user_id,
    )


@router.get("", response_model=list[ProjectOut])
def list_projects(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    projects = scoped_query(session, Project, user_id=current_user.id).all()
    return [ProjectOut(id=p.id, name=p.name, repo_path=p.repo_path, user_id=p.user_id) for p in projects]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    project = (
        scoped_query(session, Project, user_id=current_user.id)
        .filter(Project.id == project_id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectOut(id=project.id, name=project.name, repo_path=project.repo_path, user_id=project.user_id)

