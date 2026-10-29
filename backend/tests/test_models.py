"""Tests for database models, user isolation, audit hash chain, and log redaction.

Written FIRST per AGENTS.md rule #3.

Covers:
  - Cross-user isolation (SPEC threat #9): user A cannot read user B's data
  - Audit hash chain integrity: tampering with a row is detected
  - Audit hash chain integrity: deleting a row is detected
  - Log redaction (AGENTS.md rule #6): secrets are never written to logs
"""

import logging
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.models import (
    Approval,
    AuditEvent,
    Base,
    Patch,
    Plan,
    Project,
    Task,
    TestRun,
    ToolCall,
    User,
)
from app.queries import scoped_query
from app.audit import append_audit_event, verify_chain
from app.log_redact import RedactingFilter, get_redacting_logger


# ---------------------------------------------------------------------------
# Fixtures — in-memory SQLite for speed (no Docker needed for unit tests)
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def session(engine):
    SessionLocal = sessionmaker(bind=engine)
    s = SessionLocal()
    yield s
    s.close()


def _make_user(session: Session, email: str, name: str) -> User:
    u = User(id=uuid.uuid4(), email=email, name=name, created_at=datetime.now(timezone.utc))
    session.add(u)
    session.flush()
    return u


def _make_project(session: Session, user: User, name: str) -> Project:
    p = Project(
        id=uuid.uuid4(),
        user_id=user.id,
        name=name,
        repo_path=f"/repos/{name}",
        created_at=datetime.now(timezone.utc),
    )
    session.add(p)
    session.flush()
    return p


def _make_task(session: Session, project: Project, prompt: str = "do something") -> Task:
    t = Task(
        id=uuid.uuid4(),
        project_id=project.id,
        prompt=prompt,
        state="IDLE",
        retries=0,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(t)
    session.flush()
    return t


# ===================================================================
# 1. CROSS-USER ISOLATION  (SPEC threat #9)
# ===================================================================

class TestUserIsolation:
    """User A must never see user B's projects, tasks, or child rows."""

    def test_user_a_cannot_see_user_b_projects(self, session):
        alice = _make_user(session, "alice@x.com", "Alice")
        bob = _make_user(session, "bob@x.com", "Bob")
        _make_project(session, alice, "alice-proj")
        _make_project(session, bob, "bob-proj")
        session.flush()

        results = scoped_query(session, Project, user_id=alice.id).all()
        names = [p.name for p in results]
        assert "alice-proj" in names
        assert "bob-proj" not in names

    def test_user_b_cannot_see_user_a_projects(self, session):
        alice = _make_user(session, "a2@x.com", "Alice")
        bob = _make_user(session, "b2@x.com", "Bob")
        _make_project(session, alice, "a2-proj")
        _make_project(session, bob, "b2-proj")
        session.flush()

        results = scoped_query(session, Project, user_id=bob.id).all()
        names = [p.name for p in results]
        assert "b2-proj" in names
        assert "a2-proj" not in names

    def test_user_a_cannot_see_user_b_tasks(self, session):
        alice = _make_user(session, "a3@x.com", "Alice")
        bob = _make_user(session, "b3@x.com", "Bob")
        proj_a = _make_project(session, alice, "pa")
        proj_b = _make_project(session, bob, "pb")
        _make_task(session, proj_a, "alice task")
        _make_task(session, proj_b, "bob task")
        session.flush()

        results = scoped_query(session, Task, user_id=alice.id).all()
        prompts = [t.prompt for t in results]
        assert "alice task" in prompts
        assert "bob task" not in prompts

    def test_user_a_cannot_see_user_b_tool_calls(self, session):
        alice = _make_user(session, "a4@x.com", "Alice")
        bob = _make_user(session, "b4@x.com", "Bob")
        task_a = _make_task(session, _make_project(session, alice, "pa4"), "a")
        task_b = _make_task(session, _make_project(session, bob, "pb4"), "b")
        session.add(ToolCall(id=uuid.uuid4(), task_id=task_a.id, tool_name="read",
                             input_json="{}", output_json="{}", risk_level="low",
                             created_at=datetime.now(timezone.utc)))
        session.add(ToolCall(id=uuid.uuid4(), task_id=task_b.id, tool_name="write",
                             input_json="{}", output_json="{}", risk_level="high",
                             created_at=datetime.now(timezone.utc)))
        session.flush()

        results = scoped_query(session, ToolCall, user_id=alice.id).all()
        tool_names = [tc.tool_name for tc in results]
        assert "read" in tool_names
        assert "write" not in tool_names

    def test_user_a_cannot_see_user_b_patches(self, session):
        alice = _make_user(session, "a5@x.com", "Alice")
        bob = _make_user(session, "b5@x.com", "Bob")
        task_a = _make_task(session, _make_project(session, alice, "pa5"), "a")
        task_b = _make_task(session, _make_project(session, bob, "pb5"), "b")
        session.add(Patch(id=uuid.uuid4(), task_id=task_a.id, diff="alice-diff",
                          file_path="a.py", created_at=datetime.now(timezone.utc)))
        session.add(Patch(id=uuid.uuid4(), task_id=task_b.id, diff="bob-diff",
                          file_path="b.py", created_at=datetime.now(timezone.utc)))
        session.flush()

        results = scoped_query(session, Patch, user_id=alice.id).all()
        diffs = [p.diff for p in results]
        assert "alice-diff" in diffs
        assert "bob-diff" not in diffs

    def test_user_a_cannot_see_user_b_test_runs(self, session):
        alice = _make_user(session, "a6@x.com", "Alice")
        bob = _make_user(session, "b6@x.com", "Bob")
        task_a = _make_task(session, _make_project(session, alice, "pa6"), "a")
        task_b = _make_task(session, _make_project(session, bob, "pb6"), "b")
        session.add(TestRun(id=uuid.uuid4(), task_id=task_a.id, passed=True,
                            log="ok", created_at=datetime.now(timezone.utc)))
        session.add(TestRun(id=uuid.uuid4(), task_id=task_b.id, passed=False,
                            log="fail", created_at=datetime.now(timezone.utc)))
        session.flush()

        results = scoped_query(session, TestRun, user_id=alice.id).all()
        logs = [tr.log for tr in results]
        assert "ok" in logs
        assert "fail" not in logs

    def test_user_a_cannot_see_user_b_approvals(self, session):
        alice = _make_user(session, "a7@x.com", "Alice")
        bob = _make_user(session, "b7@x.com", "Bob")
        task_a = _make_task(session, _make_project(session, alice, "pa7"), "a")
        task_b = _make_task(session, _make_project(session, bob, "pb7"), "b")
        session.add(Approval(id=uuid.uuid4(), task_id=task_a.id, user_id=alice.id,
                             action="approve", reason="ok",
                             created_at=datetime.now(timezone.utc)))
        session.add(Approval(id=uuid.uuid4(), task_id=task_b.id, user_id=bob.id,
                             action="reject", reason="no",
                             created_at=datetime.now(timezone.utc)))
        session.flush()

        results = scoped_query(session, Approval, user_id=alice.id).all()
        reasons = [a.reason for a in results]
        assert "ok" in reasons
        assert "no" not in reasons

    def test_user_a_cannot_see_user_b_plans(self, session):
        alice = _make_user(session, "a8@x.com", "Alice")
        bob = _make_user(session, "b8@x.com", "Bob")
        task_a = _make_task(session, _make_project(session, alice, "pa8"), "a")
        task_b = _make_task(session, _make_project(session, bob, "pb8"), "b")
        session.add(Plan(id=uuid.uuid4(), task_id=task_a.id, steps_json='["a"]',
                         created_at=datetime.now(timezone.utc)))
        session.add(Plan(id=uuid.uuid4(), task_id=task_b.id, steps_json='["b"]',
                         created_at=datetime.now(timezone.utc)))
        session.flush()

        results = scoped_query(session, Plan, user_id=alice.id).all()
        steps = [p.steps_json for p in results]
        assert '["a"]' in steps
        assert '["b"]' not in steps

    def test_scoped_query_with_no_projects_returns_empty(self, session):
        alice = _make_user(session, "alone@x.com", "Alone")
        results = scoped_query(session, Project, user_id=alice.id).all()
        assert results == []

    def test_scoped_query_with_wrong_user_id_returns_empty(self, session):
        alice = _make_user(session, "a9@x.com", "Alice")
        _make_project(session, alice, "proj9")
        session.flush()

        fake_uid = uuid.uuid4()
        results = scoped_query(session, Project, user_id=fake_uid).all()
        assert results == []


# ===================================================================
# 2. AUDIT HASH CHAIN INTEGRITY
# ===================================================================

class TestAuditHashChain:
    """Audit events are append-only with a hash chain.
    Tampering or deletion must be detected by verify_chain()."""

    def test_valid_chain_passes(self, session):
        alice = _make_user(session, "ac1@x.com", "Alice")
        task = _make_task(session, _make_project(session, alice, "p"), "t")

        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="plan_created", detail_json='{}')
        append_audit_event(session, task_id=task.id, actor="user",
                           event_type="plan_approved", detail_json='{}')
        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="code_generated", detail_json='{}')
        session.flush()

        ok, msg = verify_chain(session)
        assert ok is True, msg

    def test_tampered_row_detected(self, session):
        """Changing detail_json of an old row must break the chain."""
        alice = _make_user(session, "ac2@x.com", "Alice")
        task = _make_task(session, _make_project(session, alice, "p2"), "t2")

        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="step_1", detail_json='{"x":1}')
        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="step_2", detail_json='{"x":2}')
        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="step_3", detail_json='{"x":3}')
        session.flush()

        # Tamper with the first event
        first = session.query(AuditEvent).order_by(AuditEvent.created_at).first()
        first.detail_json = '{"x":"HACKED"}'
        session.flush()

        ok, msg = verify_chain(session)
        assert ok is False
        assert "mismatch" in msg.lower() or "tamper" in msg.lower()

    def test_deleted_row_detected(self, session):
        """Removing a middle row must break the chain."""
        alice = _make_user(session, "ac3@x.com", "Alice")
        task = _make_task(session, _make_project(session, alice, "p3"), "t3")

        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="s1", detail_json='{}')
        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="s2", detail_json='{}')
        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="s3", detail_json='{}')
        session.flush()

        # Delete the middle event
        middle = session.query(AuditEvent).order_by(AuditEvent.created_at).offset(1).first()
        session.delete(middle)
        session.flush()

        ok, msg = verify_chain(session)
        assert ok is False

    def test_empty_chain_is_valid(self, session):
        ok, msg = verify_chain(session)
        assert ok is True

    def test_single_event_chain_is_valid(self, session):
        alice = _make_user(session, "ac4@x.com", "Alice")
        task = _make_task(session, _make_project(session, alice, "p4"), "t4")
        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="only", detail_json='{}')
        session.flush()

        ok, msg = verify_chain(session)
        assert ok is True

    def test_audit_event_has_prev_hash(self, session):
        alice = _make_user(session, "ac5@x.com", "Alice")
        task = _make_task(session, _make_project(session, alice, "p5"), "t5")
        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="e1", detail_json='{}')
        append_audit_event(session, task_id=task.id, actor="agent",
                           event_type="e2", detail_json='{}')
        session.flush()

        events = session.query(AuditEvent).order_by(AuditEvent.created_at).all()
        # First event has no predecessor — prev_hash is a known genesis value
        assert events[0].row_hash is not None
        assert events[0].prev_hash is not None
        # Second event's prev_hash must equal first event's row_hash
        assert events[1].prev_hash == events[0].row_hash


# ===================================================================
# 3. LOG REDACTION  (AGENTS.md rule #6)
# ===================================================================

class TestLogRedaction:
    """Secrets, API keys, and env-var-style values must be redacted."""

    def test_api_key_is_redacted(self, caplog):
        logger = get_redacting_logger("test.redact1")
        with caplog.at_level(logging.DEBUG, logger="test.redact1"):
            logger.info("Key is AIzaSyD-FAKE-KEY-1234567890")
        assert "AIzaSyD" not in caplog.text
        assert "***REDACTED***" in caplog.text

    def test_bearer_token_is_redacted(self, caplog):
        logger = get_redacting_logger("test.redact2")
        with caplog.at_level(logging.DEBUG, logger="test.redact2"):
            logger.info("Authorization: Bearer eyJhbGciOiJSUzI1NiIs.xxxx.yyyy")
        assert "eyJhbGci" not in caplog.text
        assert "***REDACTED***" in caplog.text

    def test_password_in_url_is_redacted(self, caplog):
        logger = get_redacting_logger("test.redact3")
        with caplog.at_level(logging.DEBUG, logger="test.redact3"):
            logger.info("postgres://user:s3cretP@ss@localhost/db")
        assert "s3cretP@ss" not in caplog.text
        assert "***REDACTED***" in caplog.text

    def test_env_var_style_secret_is_redacted(self, caplog):
        logger = get_redacting_logger("test.redact4")
        with caplog.at_level(logging.DEBUG, logger="test.redact4"):
            logger.info("SECRET_KEY=super-secret-value-12345")
        assert "super-secret-value-12345" not in caplog.text
        assert "***REDACTED***" in caplog.text

    def test_aws_secret_key_is_redacted(self, caplog):
        logger = get_redacting_logger("test.redact5")
        with caplog.at_level(logging.DEBUG, logger="test.redact5"):
            logger.info("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        assert "wJalrXUtnFEMI" not in caplog.text

    def test_safe_message_passes_through(self, caplog):
        logger = get_redacting_logger("test.redact6")
        with caplog.at_level(logging.DEBUG, logger="test.redact6"):
            logger.info("Task completed successfully in 2.3s")
        assert "Task completed successfully in 2.3s" in caplog.text

    def test_private_key_block_is_redacted(self, caplog):
        logger = get_redacting_logger("test.redact7")
        with caplog.at_level(logging.DEBUG, logger="test.redact7"):
            logger.info("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        assert "BEGIN RSA PRIVATE KEY" not in caplog.text
        assert "***REDACTED***" in caplog.text

    def test_github_token_is_redacted(self, caplog):
        logger = get_redacting_logger("test.redact8")
        with caplog.at_level(logging.DEBUG, logger="test.redact8"):
            logger.info("token ghp_ABCDefgh1234567890abcdefghijklmnopqr")
        assert "ghp_" not in caplog.text
        assert "***REDACTED***" in caplog.text

