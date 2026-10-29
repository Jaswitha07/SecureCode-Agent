"""Agent state machine — implements the SPEC.md state machine exactly.

States and transitions are taken verbatim from docs/SPEC.md § "Agent State Machine".

Rules:
  - Illegal transitions raise IllegalTransitionError immediately,
    without changing state or writing to the audit log.
  - Every legal transition is appended to the audit log via audit.append_audit_event().
  - Retry counter (EXECUTING→EXECUTING and VERIFYING→EXECUTING) is capped at MAX_RETRIES.
  - Terminal states (DONE, FAILED) have no outgoing edges.
"""

from __future__ import annotations

import json
from enum import Enum

from sqlalchemy.orm import Session

from app.audit import append_audit_event

MAX_RETRIES: int = 3


class State(str, Enum):
    """All states from SPEC.md."""
    IDLE      = "IDLE"
    PLANNING  = "PLANNING"
    APPROVAL  = "APPROVAL"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    DONE      = "DONE"
    FAILED    = "FAILED"


class IllegalTransitionError(RuntimeError):
    """Raised when a state transition is not permitted by the SPEC."""


# ---------------------------------------------------------------------------
# Transition table — exactly as drawn in SPEC.md.
# Maps (from_state, to_state) → bool.
# Retry self-edges (EXECUTING→EXECUTING, VERIFYING→EXECUTING) are handled
# specially in transition() to enforce the retry cap.
# ---------------------------------------------------------------------------
_ALLOWED: frozenset[tuple[State, State]] = frozenset({
    (State.IDLE,      State.PLANNING),   # task assigned
    (State.PLANNING,  State.APPROVAL),   # plan ready
    (State.APPROVAL,  State.EXECUTING),  # approved
    (State.APPROVAL,  State.FAILED),     # rejected
    (State.EXECUTING, State.VERIFYING),  # success → verify
    (State.EXECUTING, State.EXECUTING),  # error, retry (capped at MAX_RETRIES)
    (State.VERIFYING, State.DONE),       # pass
    (State.VERIFYING, State.FAILED),     # fail, retries exhausted
    (State.VERIFYING, State.EXECUTING),  # fail, retry (capped at MAX_RETRIES)
})

# Edges that consume a retry slot
_RETRY_EDGES: frozenset[tuple[State, State]] = frozenset({
    (State.EXECUTING, State.EXECUTING),
    (State.VERIFYING, State.EXECUTING),
})


class AgentStateMachine:
    """Manages the state of a single agent task.

    Parameters
    ----------
    task_id:
        UUID of the task being tracked.
    session:
        SQLAlchemy session used to write audit events.
    initial_state:
        Defaults to IDLE; override for reconstruction from DB.
    initial_retries:
        Defaults to 0; override when reconstructing from DB.
    """

    def __init__(
        self,
        task_id: str,
        session: Session,
        initial_state: State = State.IDLE,
        initial_retries: int = 0,
    ) -> None:
        self._state = initial_state
        self._task_id = task_id
        self._session = session
        self._retries = initial_retries

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> State:
        return self._state

    @property
    def retries(self) -> int:
        return self._retries

    # ------------------------------------------------------------------
    # Core transition method
    # ------------------------------------------------------------------

    def transition(self, to: State) -> None:
        """Attempt to transition to *to*.

        Raises
        ------
        IllegalTransitionError
            If the transition is not in the SPEC or the retry cap is exceeded.
            State and audit log are left unchanged on error.
        """
        from_state = self._state
        edge = (from_state, to)

        # 1. Check edge is in the allowed set
        if edge not in _ALLOWED:
            raise IllegalTransitionError(
                f"Transition {from_state.value} → {to.value} is not allowed. "
                f"Current state: {from_state.value}"
            )

        # 2. Enforce retry cap on retry edges
        if edge in _RETRY_EDGES:
            if self._retries >= MAX_RETRIES:
                raise IllegalTransitionError(
                    f"Retry limit ({MAX_RETRIES}) exceeded. "
                    f"Cannot transition {from_state.value} → {to.value}."
                )
            self._retries += 1

        # 3. Apply the transition
        self._state = to

        # 4. Append to audit log (rule #6: no secrets in the detail)
        detail = json.dumps({
            "from": from_state.value,
            "to": to.value,
            "retries": self._retries,
        })
        append_audit_event(
            self._session,
            task_id=self._task_id,
            actor="agent",
            event_type="state_transition",
            detail_json=detail,
        )
