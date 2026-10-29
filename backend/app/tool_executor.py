"""Tool executor — the single dispatch point for all agent tool calls.

Security invariant (AGENTS.md rule #2 / SPEC threat #10):
  There is NO code path that executes a tool without first calling
  policy_engine. The sandbox is only reachable inside _run_in_sandbox(),
  which is only called from within the single policy-checked branch of
  execute(). Any attempt to add a bypass will require touching this
  comment, which serves as an architectural trip-wire.

Supported tools (from ToolRequest schema):
  - read_file   → path policy check → sandbox cat
  - write_file  → path policy check → sandbox write
  - run_command → command policy check → sandbox run
  - finish      → no sandbox, signals task completion
  - (all others) → denied by unknown_tool

Correction attempts are capped at MAX_CORRECTIONS = 3. A correction is a
re-try of a previously failed or denied action. Callers set is_correction=True.
The 4th call with is_correction=True raises CorrectionLimitError.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum

from sqlalchemy.orm import Session

from app.audit import append_audit_event
from app.policy_engine import check_command, check_path, Decision
from app.providers.base import ToolRequest

# ---------------------------------------------------------------------------
# Sandbox runner import — centralised here so every sandbox call passes
# through this module and cannot bypass the policy check above it.
# ---------------------------------------------------------------------------
try:
    from sandbox.runner import run_sandboxed as sandbox_run  # type: ignore[import]
except ModuleNotFoundError:
    # sandbox package not installed in test environment — tests mock this name.
    sandbox_run = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_CORRECTIONS: int = 3

# Tools the executor explicitly understands
_KNOWN_TOOLS: frozenset[str] = frozenset({
    "read_file",
    "write_file",
    "run_command",
    "finish",
})


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class ExecutionOutcome(str, Enum):
    RAN              = "ran"               # tool ran in sandbox
    DENIED           = "denied"            # policy engine said deny
    PENDING_APPROVAL = "pending_approval"  # policy engine said needs_approval
    FINISHED         = "finished"          # model emitted 'finish' tool


@dataclass
class ExecutionResult:
    """Result returned from ToolExecutor.execute()."""

    outcome: ExecutionOutcome
    reason: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_seconds: float | None = None
    killed: bool = False


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CorrectionLimitError(RuntimeError):
    """Raised when the correction attempt limit (MAX_CORRECTIONS) is exceeded."""


class UnknownToolError(ValueError):
    """Raised internally when the tool name is not in _KNOWN_TOOLS."""


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------

class ToolExecutor:
    """Executes validated ToolRequests under strict policy control.

    Parameters
    ----------
    project_root:
        Absolute path to the project root. All file-tool paths are validated
        against this root via check_path().
    session:
        SQLAlchemy session for audit logging.
    task_id:
        UUID of the current task, written to every audit event.
    """

    def __init__(
        self,
        *,
        project_root: str,
        session: Session,
        task_id: str,
    ) -> None:
        self._project_root = project_root
        self._session = session
        self._task_id = task_id
        self._corrections: int = 0

    @property
    def corrections(self) -> int:
        return self._corrections

    # ------------------------------------------------------------------
    # Public API — the only entry point
    # ------------------------------------------------------------------

    def execute(
        self,
        request: ToolRequest,
        *,
        is_correction: bool = False,
    ) -> ExecutionResult:
        """Policy-check *request* and execute it if allowed.

        Parameters
        ----------
        request:
            A validated ToolRequest from a model provider.
        is_correction:
            Set True when re-trying after a failure. Increments the
            correction counter; raises CorrectionLimitError on the 4th call.

        Returns
        -------
        ExecutionResult
            Describes what happened. The caller inspects .outcome.

        Raises
        ------
        CorrectionLimitError
            If is_correction=True and corrections already reached MAX_CORRECTIONS.
        """
        # ── 1. Enforce correction limit ─────────────────────────────────────
        if is_correction:
            if self._corrections >= MAX_CORRECTIONS:
                raise CorrectionLimitError(
                    f"Correction limit ({MAX_CORRECTIONS}) reached for task "
                    f"{self._task_id}. Cannot accept more corrections."
                )
            self._corrections += 1

        # ── 2. Route to the right policy check ─────────────────────────────
        #       This is the ONLY place that decides whether to run the tool.
        #       There is no other call site for _run_in_sandbox().
        try:
            decision, shell_cmd = self._policy_check(request)
        except UnknownToolError:
            result = ExecutionResult(
                outcome=ExecutionOutcome.DENIED,
                reason=f"unknown_tool:{request.tool}",
            )
            self._audit("tool_denied", request, result)
            return result

        # ── 3. Act on the policy decision ───────────────────────────────────
        if decision.action == "deny":
            result = ExecutionResult(
                outcome=ExecutionOutcome.DENIED,
                reason=decision.reason,
            )
            self._audit("tool_denied", request, result)
            return result

        if decision.action == "needs_approval":
            result = ExecutionResult(
                outcome=ExecutionOutcome.PENDING_APPROVAL,
                reason=decision.reason,
            )
            self._audit("tool_pending_approval", request, result)
            return result

        # decision.action == "allow" — only path that reaches the sandbox
        if request.tool == "finish":
            result = ExecutionResult(
                outcome=ExecutionOutcome.FINISHED,
                reason="task_complete",
            )
            self._audit("tool_finished", request, result)
            return result

        # ── 4. Run in sandbox ───────────────────────────────────────────────
        #       Reachable ONLY after a confirmed "allow" decision.
        sandbox_result = self._run_in_sandbox(shell_cmd, request)
        result = ExecutionResult(
            outcome=ExecutionOutcome.RAN,
            reason="policy_allow",
            stdout=sandbox_result.stdout,
            stderr=sandbox_result.stderr,
            exit_code=sandbox_result.exit_code,
            duration_seconds=sandbox_result.duration_seconds,
            killed=sandbox_result.killed,
        )
        self._audit("tool_ran", request, result)
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _policy_check(
        self, request: ToolRequest
    ) -> tuple[Decision, str]:
        """Run the appropriate policy check for *request*.

        Returns (decision, shell_command_string).
        Raises UnknownToolError for unsupported tool names.

        This method ONLY reads policy; it has no side effects.
        """
        tool = request.tool
        args = request.args

        if tool not in _KNOWN_TOOLS:
            raise UnknownToolError(tool)

        if tool == "finish":
            # 'finish' signals completion — always allow, no sandbox needed.
            from app.policy_engine import Decision as D
            return D(action="allow", reason="finish_tool"), ""

        if tool == "read_file":
            path = str(args.get("path", ""))
            decision = check_path(path, project_root=self._project_root)
            # Translate to a safe shell command for the sandbox
            shell_cmd = f"cat {_quote(path)}" if decision.action == "allow" else ""
            return decision, shell_cmd

        if tool == "write_file":
            path = str(args.get("path", ""))
            decision = check_path(path, project_root=self._project_root)
            content = str(args.get("content", ""))
            if decision.action == "allow":
                # Write via python to handle arbitrary content safely
                shell_cmd = (
                    f"python3 -c \""
                    f"import pathlib; "
                    f"p=pathlib.Path({_quote(path)}); "
                    f"p.parent.mkdir(parents=True,exist_ok=True); "
                    f"p.write_text({_quote(content)})\""
                )
            else:
                shell_cmd = ""
            return decision, shell_cmd

        if tool == "run_command":
            command = str(args.get("command", ""))
            decision = check_command(command)
            return decision, command

        # Should never reach here given _KNOWN_TOOLS guard above
        raise UnknownToolError(tool)  # pragma: no cover

    def _run_in_sandbox(self, shell_cmd: str, request: ToolRequest):
        """Call the sandbox runner with *shell_cmd*.

        This method is intentionally private and has only one call site
        (the allow-branch of execute()). It cannot be called directly
        without first passing through _policy_check().
        """
        return sandbox_run(
            command=shell_cmd,
            workspace_dir=self._project_root,
        )

    def _audit(
        self,
        event_type: str,
        request: ToolRequest,
        result: ExecutionResult,
    ) -> None:
        """Append an audit event for this tool decision.

        AGENTS.md rule #6: never log secrets. We log tool name and
        outcome only — not the full args (which might contain content).
        """
        detail = json.dumps({
            "tool": request.tool,
            "outcome": result.outcome.value,
            "reason": result.reason,
            # Intentionally omit args.content to avoid logging file content
            "path": request.args.get("path", ""),
            "command": request.args.get("command", ""),
        })
        append_audit_event(
            self._session,
            task_id=self._task_id,
            actor="agent",
            event_type=event_type,
            detail_json=detail,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _quote(s: str) -> str:
    """Minimal shell single-quoting for sandbox commands.
    Only used for safe, policy-approved paths and content strings.
    """
    # Escape existing single quotes by ending quote, adding literal ', re-opening
    escaped = s.replace("'", "'\\''")
    return f"'{escaped}'"

