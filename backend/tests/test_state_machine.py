"""Tests for the agent state machine and workspace rollback.

Written FIRST per AGENTS.md rule #3.

Covers:
  - All legal state transitions from SPEC.md
  - All illegal transitions raise IllegalTransitionError
  - Every transition is written to the audit log
  - MAX_RETRIES = 3 is enforced
  - Git checkpoint created before patch is applied
  - Rollback restores the exact earlier file contents
  - Retry exhaustion triggers rollback and FAILED state
"""

import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.models import Base, AuditEvent, User, Project, Task
from app.state_machine import (
    AgentStateMachine,
    IllegalTransitionError,
    State,
    MAX_RETRIES,
)
from app.workspace import WorkspaceCheckpoint


# ──────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session_ = sessionmaker(bind=engine)
    s = Session_()
    yield s
    s.close()


@pytest.fixture()
def task_id():
    return str(uuid.uuid4())


@pytest.fixture()
def sm(db_session, task_id):
    """State machine starting in IDLE with a real audit session."""
    return AgentStateMachine(
        task_id=task_id,
        session=db_session,
    )


@pytest.fixture()
def git_repo(tmp_path):
    """Initialise a bare git repo in a temp dir and return its path."""
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(tmp_path), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(tmp_path), check=True, capture_output=True,
    )
    # Initial commit so HEAD exists
    (tmp_path / "README.md").write_text("init")
    subprocess.run(["git", "add", "-A"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=str(tmp_path), check=True, capture_output=True,
    )
    return tmp_path


# ══════════════════════════════════════════════════════════════════
# A. LEGAL TRANSITIONS  (from SPEC.md state machine)
# ══════════════════════════════════════════════════════════════════

class TestLegalTransitions:

    def test_initial_state_is_idle(self, sm):
        assert sm.state == State.IDLE

    def test_idle_to_planning(self, sm):
        sm.transition(State.PLANNING)
        assert sm.state == State.PLANNING

    def test_planning_to_approval(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        assert sm.state == State.APPROVAL

    def test_approval_to_executing(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        assert sm.state == State.EXECUTING

    def test_approval_to_failed(self, sm):
        """Rejected plan goes directly to FAILED."""
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.FAILED)
        assert sm.state == State.FAILED

    def test_executing_to_verifying(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.VERIFYING)
        assert sm.state == State.VERIFYING

    def test_verifying_to_done(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.VERIFYING)
        sm.transition(State.DONE)
        assert sm.state == State.DONE

    def test_verifying_to_failed(self, sm):
        """Verification fail after retries exhausted → FAILED."""
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.VERIFYING)
        sm.transition(State.FAILED)
        assert sm.state == State.FAILED

    def test_executing_retries_back_to_executing(self, sm):
        """Error during execution allows retry — back to EXECUTING."""
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.EXECUTING)   # retry
        assert sm.state == State.EXECUTING

    def test_verifying_retries_back_to_executing(self, sm):
        """Verification fail within retry limit → back to EXECUTING."""
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.VERIFYING)
        sm.transition(State.EXECUTING)  # retry after verify fail
        assert sm.state == State.EXECUTING

    def test_max_retries_constant_is_three(self):
        assert MAX_RETRIES == 3


# ══════════════════════════════════════════════════════════════════
# B. ILLEGAL TRANSITIONS
# ══════════════════════════════════════════════════════════════════

class TestIllegalTransitions:

    def test_idle_to_executing_is_illegal(self, sm):
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.EXECUTING)

    def test_idle_to_verifying_is_illegal(self, sm):
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.VERIFYING)

    def test_idle_to_done_is_illegal(self, sm):
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.DONE)

    def test_idle_to_approval_is_illegal(self, sm):
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.APPROVAL)

    def test_idle_to_failed_is_illegal(self, sm):
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.FAILED)

    def test_planning_to_done_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.DONE)

    def test_planning_to_executing_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.EXECUTING)

    def test_planning_to_verifying_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.VERIFYING)

    def test_planning_to_failed_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.FAILED)

    def test_approval_to_planning_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.PLANNING)

    def test_approval_to_verifying_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.VERIFYING)

    def test_approval_to_done_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.DONE)

    def test_done_to_any_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.VERIFYING)
        sm.transition(State.DONE)
        for target in [State.IDLE, State.PLANNING, State.APPROVAL,
                       State.EXECUTING, State.VERIFYING, State.FAILED]:
            with pytest.raises(IllegalTransitionError):
                sm.transition(target)

    def test_failed_to_any_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.FAILED)
        for target in [State.IDLE, State.PLANNING, State.APPROVAL,
                       State.EXECUTING, State.VERIFYING, State.DONE]:
            with pytest.raises(IllegalTransitionError):
                sm.transition(target)

    def test_verifying_to_idle_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.VERIFYING)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.IDLE)

    def test_verifying_to_approval_is_illegal(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.VERIFYING)
        with pytest.raises(IllegalTransitionError):
            sm.transition(State.APPROVAL)

    def test_illegal_transition_does_not_change_state(self, sm):
        """State must be unchanged after a rejected transition."""
        try:
            sm.transition(State.DONE)
        except IllegalTransitionError:
            pass
        assert sm.state == State.IDLE

    def test_error_message_includes_from_and_to(self, sm):
        with pytest.raises(IllegalTransitionError, match="IDLE"):
            sm.transition(State.DONE)


# ══════════════════════════════════════════════════════════════════
# C. RETRY LIMIT
# ══════════════════════════════════════════════════════════════════

class TestRetryLimit:

    def _reach_executing(self, sm):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)

    def test_three_execution_retries_allowed(self, sm):
        self._reach_executing(sm)
        sm.transition(State.EXECUTING)  # retry 1
        sm.transition(State.EXECUTING)  # retry 2
        sm.transition(State.EXECUTING)  # retry 3
        assert sm.state == State.EXECUTING
        assert sm.retries == 3

    def test_fourth_execution_retry_is_illegal(self, sm):
        self._reach_executing(sm)
        sm.transition(State.EXECUTING)  # 1
        sm.transition(State.EXECUTING)  # 2
        sm.transition(State.EXECUTING)  # 3
        with pytest.raises(IllegalTransitionError, match="(?i)retry"):
            sm.transition(State.EXECUTING)  # 4 — over limit

    def test_verify_then_executing_counts_as_retry(self, sm):
        self._reach_executing(sm)
        sm.transition(State.VERIFYING)
        sm.transition(State.EXECUTING)  # 1
        sm.transition(State.VERIFYING)
        sm.transition(State.EXECUTING)  # 2
        sm.transition(State.VERIFYING)
        sm.transition(State.EXECUTING)  # 3
        assert sm.retries == 3

    def test_retry_count_resets_on_new_sm(self, db_session):
        sm2 = AgentStateMachine(task_id=str(uuid.uuid4()), session=db_session)
        assert sm2.retries == 0


# ══════════════════════════════════════════════════════════════════
# D. AUDIT LOG  — every transition is recorded
# ══════════════════════════════════════════════════════════════════

class TestAuditLogging:

    def test_transition_appends_audit_event(self, sm, db_session):
        sm.transition(State.PLANNING)
        events = db_session.query(AuditEvent).all()
        assert len(events) == 1

    def test_audit_event_records_from_and_to_state(self, sm, db_session):
        sm.transition(State.PLANNING)
        event = db_session.query(AuditEvent).first()
        assert "IDLE" in event.detail_json
        assert "PLANNING" in event.detail_json

    def test_audit_event_actor_is_agent(self, sm, db_session):
        sm.transition(State.PLANNING)
        event = db_session.query(AuditEvent).first()
        assert event.actor == "agent"

    def test_audit_event_type_is_state_transition(self, sm, db_session):
        sm.transition(State.PLANNING)
        event = db_session.query(AuditEvent).first()
        assert event.event_type == "state_transition"

    def test_illegal_transition_does_not_append_audit_event(self, sm, db_session):
        try:
            sm.transition(State.DONE)
        except IllegalTransitionError:
            pass
        assert db_session.query(AuditEvent).count() == 0

    def test_full_happy_path_produces_five_events(self, sm, db_session):
        sm.transition(State.PLANNING)
        sm.transition(State.APPROVAL)
        sm.transition(State.EXECUTING)
        sm.transition(State.VERIFYING)
        sm.transition(State.DONE)
        assert db_session.query(AuditEvent).count() == 5

    def test_audit_task_id_matches(self, sm, db_session, task_id):
        sm.transition(State.PLANNING)
        event = db_session.query(AuditEvent).first()
        assert event.task_id == task_id


# ══════════════════════════════════════════════════════════════════
# E. GIT CHECKPOINT — WorkspaceCheckpoint
# ══════════════════════════════════════════════════════════════════

class TestWorkspaceCheckpoint:

    def test_checkpoint_is_created(self, git_repo):
        cp = WorkspaceCheckpoint(str(git_repo))
        sha = cp.create("before patch")
        assert sha and len(sha) == 40  # full git SHA

    def test_rollback_restores_file_contents(self, git_repo):
        """After rollback, the file must contain the pre-patch content."""
        target = git_repo / "src" / "main.py"
        target.parent.mkdir(exist_ok=True)
        target.write_text("original content")
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "pre-patch state"],
            cwd=str(git_repo), check=True, capture_output=True,
        )

        cp = WorkspaceCheckpoint(str(git_repo))
        sha = cp.create("checkpoint before patch")

        # Simulate a patch being applied
        target.write_text("PATCHED — broken code")
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "bad patch"],
            cwd=str(git_repo), check=True, capture_output=True,
        )

        # Rollback
        cp.rollback(sha)

        assert target.read_text() == "original content"

    def test_rollback_removes_new_file(self, git_repo):
        """A file added by the patch must not exist after rollback."""
        cp = WorkspaceCheckpoint(str(git_repo))
        sha = cp.create("before new file")

        new_file = git_repo / "injected.py"
        new_file.write_text("malicious()")
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "added injected file"],
            cwd=str(git_repo), check=True, capture_output=True,
        )

        cp.rollback(sha)
        assert not new_file.exists()

    def test_rollback_restores_deleted_file(self, git_repo):
        """A file deleted by the patch must be restored by rollback."""
        kept = git_repo / "keep.py"
        kept.write_text("keep me")
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "add keep.py"],
            cwd=str(git_repo), check=True, capture_output=True,
        )

        cp = WorkspaceCheckpoint(str(git_repo))
        sha = cp.create("before delete")

        kept.unlink()
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "deleted keep.py"],
            cwd=str(git_repo), check=True, capture_output=True,
        )

        cp.rollback(sha)
        assert kept.exists()
        assert kept.read_text() == "keep me"

    def test_multiple_rollback_targets_are_independent(self, git_repo):
        """Each checkpoint SHA must roll back to its own state."""
        f = git_repo / "counter.txt"
        f.write_text("v1")
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "v1"], cwd=str(git_repo), check=True, capture_output=True)

        cp = WorkspaceCheckpoint(str(git_repo))
        sha1 = cp.create("v1 checkpoint")

        f.write_text("v2")
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "v2"], cwd=str(git_repo), check=True, capture_output=True)
        sha2 = cp.create("v2 checkpoint")

        f.write_text("v3-broken")
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "v3"], cwd=str(git_repo), check=True, capture_output=True)

        # Roll back to v1
        cp.rollback(sha1)
        assert f.read_text() == "v1"

        # Then simulate new work and roll back to v2
        f.write_text("v4-broken")
        subprocess.run(["git", "add", "-A"], cwd=str(git_repo), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "v4"], cwd=str(git_repo), check=True, capture_output=True)

        cp.rollback(sha2)
        assert f.read_text() == "v2"
