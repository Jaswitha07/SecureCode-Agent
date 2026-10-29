"""JSON-schema validation for model provider responses.

Every response from any model provider is UNTRUSTED (SPEC threats #1 and #2).
validate_response() is the single choke-point: only a valid ToolRequest
structure may leave this module. Everything else raises ValidationError.

Schema rules:
  - Root object only (no arrays, strings, nulls at the top level).
  - Required fields: "tool" (non-empty string ≤ 64 chars), "args" (object).
  - Optional field: "thought" (string).
  - No additional properties allowed.
  - args object depth is capped at MAX_ARG_DEPTH to prevent DoS.
"""

from __future__ import annotations

import json

import jsonschema
from jsonschema import Draft202012Validator

from app.providers.base import ToolRequest

# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

MAX_TOOL_NAME_LEN = 64
MAX_ARG_DEPTH = 5

_TOOL_REQUEST_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["tool", "args"],
    "additionalProperties": False,
    "properties": {
        "thought": {
            "type": "string",
        },
        "tool": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_TOOL_NAME_LEN,
        },
        "args": {
            "type": "object",
        },
    },
}

_VALIDATOR = Draft202012Validator(_TOOL_REQUEST_SCHEMA)


class ValidationError(ValueError):
    """Raised when a model response fails schema validation."""


# --------------------------------------------------------------------------
# Depth check (separate from jsonschema — prevents DoS)
# --------------------------------------------------------------------------

def _check_depth(obj: object, current: int = 0) -> None:
    """Recursively check that *obj* is not deeper than MAX_ARG_DEPTH."""
    if current > MAX_ARG_DEPTH:
        raise ValidationError(
            f"args object is nested deeper than the allowed maximum ({MAX_ARG_DEPTH})"
        )
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_depth(item, current + 1)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def validate_response(raw: str) -> ToolRequest:
    """Parse *raw* JSON and validate it against the tool-request schema.

    Parameters
    ----------
    raw:
        Raw string returned by a model provider.

    Returns
    -------
    ToolRequest
        A validated, immutable tool request.

    Raises
    ------
    ValidationError
        If *raw* is not valid JSON, does not match the schema, or contains
        an args object that is too deeply nested.
    """
    # 1. Parse JSON ─────────────────────────────────────────────────────────
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationError("Response is empty or not a string")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Response is not valid JSON: {exc}") from exc

    # 2. Top-level must be an object ────────────────────────────────────────
    if not isinstance(data, dict):
        raise ValidationError(
            f"Response must be a JSON object, got {type(data).__name__}"
        )

    # 3. JSON Schema validation ─────────────────────────────────────────────
    errors = list(_VALIDATOR.iter_errors(data))
    if errors:
        # Report the first error with its path for clarity
        first = errors[0]
        path = " → ".join(str(p) for p in first.absolute_path) or "<root>"
        raise ValidationError(f"Schema violation at {path!r}: {first.message}")

    # 4. Args depth cap ─────────────────────────────────────────────────────
    _check_depth(data.get("args", {}))

    # 5. Build ToolRequest ──────────────────────────────────────────────────
    return ToolRequest(
        tool=data["tool"],
        args=data["args"],
        thought=data.get("thought"),
    )
