"""Base class and shared types for model providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolRequest:
    """Validated, structured request that a model returns.

    Fields match the JSON schema exactly.
    Every ToolRequest has passed schema validation — it is safe to dispatch.
    """

    tool: str
    args: dict
    thought: str | None = field(default=None)


class ModelProvider(ABC):
    """Abstract base for all model backends.

    Implementations must:
      - Be async-safe.
      - Call validate_response() on every raw model output before returning.
      - Never log or store the raw API key / token.
    """

    @abstractmethod
    async def complete(self, messages: list[dict]) -> ToolRequest:
        """Send *messages* to the model and return a validated ToolRequest.

        Raises:
            app.providers.schema.ValidationError: if the model output does
                not conform to the tool-request schema.
        """
