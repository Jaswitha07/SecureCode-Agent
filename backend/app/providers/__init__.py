"""providers package — model provider interface and factory.

Usage:
    from app.providers import get_provider
    provider = get_provider("mock")          # for tests
    provider = get_provider("ollama")        # local Ollama
    provider = get_provider("hosted")        # future hosted API

All providers return validated ToolRequest objects.
Provider output is always untrusted — validate_response() is called
inside every provider before anything is returned to the caller.
"""

from __future__ import annotations

from app.providers.base import ModelProvider, ToolRequest
from app.providers.hosted import HostedProvider
from app.providers.mock import MockProvider
from app.providers.ollama import OllamaProvider
from app.providers.schema import ValidationError, validate_response

_REGISTRY: dict[str, type[ModelProvider]] = {
    "mock": MockProvider,
    "ollama": OllamaProvider,
    "hosted": HostedProvider,
}


def get_provider(name: str, **kwargs) -> ModelProvider:
    """Return an instance of the named provider.

    Parameters
    ----------
    name:
        One of "mock", "ollama", or "hosted".
    **kwargs:
        Forwarded to the provider constructor.

    Raises
    ------
    ValueError:
        If *name* is not a registered provider.
    """
    try:
        cls = _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY))
        raise ValueError(
            f"Unknown provider {name!r}. Known providers: {known}"
        )

    # MockProvider requires 'responses' kwarg; default to empty list
    if cls is MockProvider and "responses" not in kwargs:
        kwargs["responses"] = []

    # OllamaProvider requires 'model' kwarg; default to llama3
    if cls is OllamaProvider and "model" not in kwargs:
        kwargs["model"] = "llama3"

    return cls(**kwargs)


__all__ = [
    "get_provider",
    "ModelProvider",
    "MockProvider",
    "OllamaProvider",
    "HostedProvider",
    "ToolRequest",
    "validate_response",
    "ValidationError",
]
