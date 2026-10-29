"""HostedProvider — placeholder for a future hosted model API.

Not implemented in v1. (SPEC Non-Goals: self-hosting the LLM is out of scope;
multi-model orchestration is a non-goal.)

When implemented, it MUST:
  - Read the API key from the environment, never from code.
  - Never log or print the API key (AGENTS.md rule #6).
  - Call validate_response() on every raw output before returning.
"""

from __future__ import annotations

from app.providers.base import ModelProvider, ToolRequest


class HostedProvider(ModelProvider):
    """Stub for a future hosted model provider (e.g. Gemini API).

    Raises NotImplementedError on any call until implemented.
    """

    async def complete(self, messages: list[dict]) -> ToolRequest:
        raise NotImplementedError(
            "HostedProvider is not implemented in v1. "
            "Use MockProvider for tests or OllamaProvider for local inference."
        )
