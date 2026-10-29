"""Audit event hash chain — append-only tamper-evident log.

Each row stores:
  prev_hash:  row_hash of the immediately preceding row
  row_hash:   SHA-256(prev_hash || canonical content of this row)

The first row uses a well-known genesis seed for prev_hash.
verify_chain() re-computes every hash and reports the first mismatch.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import AuditEvent

# A fixed genesis value so the first event's prev_hash is deterministic.
GENESIS_HASH = "0" * 64


def _canonical(event: AuditEvent) -> str:
    """Produce a deterministic string from the mutable content fields."""
    return f"{event.task_id}|{event.actor}|{event.event_type}|{event.detail_json}"


def _compute_hash(prev_hash: str, canonical: str) -> str:
    """SHA-256( prev_hash || canonical )."""
    payload = f"{prev_hash}||{canonical}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit_event(
    session: Session,
    *,
    task_id: uuid.UUID | str,
    actor: str,
    event_type: str,
    detail_json: str,
) -> AuditEvent:
    """Create a new audit event and chain it to the previous one.

    The caller is responsible for ``session.flush()`` / ``session.commit()``.
    """
    # Find the most recent event to get its hash
    last: AuditEvent | None = (
        session.query(AuditEvent)
        .order_by(AuditEvent.created_at.desc())
        .first()
    )
    prev_hash = last.row_hash if last else GENESIS_HASH

    event = AuditEvent(
        id=str(uuid.uuid4()),
        task_id=str(task_id),
        actor=actor,
        event_type=event_type,
        detail_json=detail_json,
        created_at=datetime.now(timezone.utc),
        prev_hash=prev_hash,
        row_hash="",  # placeholder — computed below
    )

    # Compute this row's hash
    event.row_hash = _compute_hash(prev_hash, _canonical(event))

    session.add(event)
    return event


def verify_chain(session: Session) -> tuple[bool, str]:
    """Walk the entire audit_events table and verify the hash chain.

    Returns (True, "ok") if valid, or (False, "<explanation>") on the first
    broken link.
    """
    events: list[AuditEvent] = (
        session.query(AuditEvent)
        .order_by(AuditEvent.created_at)
        .all()
    )

    if not events:
        return True, "ok — no events"

    expected_prev = GENESIS_HASH

    for i, event in enumerate(events):
        # 1. Check prev_hash pointer
        if event.prev_hash != expected_prev:
            return False, (
                f"Event #{i} ({event.id}): prev_hash mismatch — "
                f"expected {expected_prev[:16]}… got {event.prev_hash[:16]}…"
            )

        # 2. Recompute row_hash from content
        recomputed = _compute_hash(event.prev_hash, _canonical(event))
        if event.row_hash != recomputed:
            return False, (
                f"Event #{i} ({event.id}): row_hash tamper detected — "
                f"expected {recomputed[:16]}… got {event.row_hash[:16]}…"
            )

        expected_prev = event.row_hash

    return True, "ok"

