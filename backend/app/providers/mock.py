"""MockProvider — deterministic model provider for tests.

Makes no network or file-system calls.
Responses are scripted at construction time and consumed in order.
If the scripted response is invalid, ValidationError is raised just as
it would be in production — tests must stay realistic.
"""

from __future__ import annotations

from app.providers.base import ModelProvider, ToolRequest
from app.providers.schema import validate_response


class MockProvider(ModelProvider):
    """Cycles through a pre-scripted list of raw JSON response strings.

    Parameters
    ----------
    responses:
        Ordered list of raw JSON strings that complete() will return.
        Each string is passed through validate_response() so invalid
        scripted responses still raise ValidationError.
    """

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._index = 0
        self.call_history: list[list[dict]] = []

    async def complete(self, messages: list[dict]) -> ToolRequest:
        """Return the next scripted response, validated."""
        self.call_history.append(messages)

        if not self._responses:
            raise RuntimeError("MockProvider has no more scripted responses")

        raw = self._responses[self._index % len(self._responses)]
        self._index += 1

        # Always validate — mirrors production behaviour
        return validate_response(raw)
