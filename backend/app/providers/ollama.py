"""OllamaProvider — connects to a local Ollama instance (localhost:11434).

Ollama API: POST /api/chat with {"model": ..., "messages": ..., "stream": false}
Response format: {"message": {"role": "assistant", "content": "<raw>"}}

All output is untrusted and passed through validate_response().
The API key is never present (Ollama is local-only) so no secret logging risk.
"""

from __future__ import annotations

import httpx

from app.providers.base import ModelProvider, ToolRequest
from app.providers.schema import validate_response

_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider(ModelProvider):
    """Calls a locally-running Ollama server.

    Parameters
    ----------
    model:
        Ollama model tag, e.g. "codellama", "llama3", "mistral".
    base_url:
        Base URL for the Ollama server. Defaults to localhost:11434.
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        model: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.timeout = timeout

    async def complete(self, messages: list[dict]) -> ToolRequest:
        """Send *messages* to Ollama and return a validated ToolRequest."""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
                json=payload,
            )
            response.raise_for_status()

        data = response.json()
        raw_content: str = data["message"]["content"]

        # Provider output is UNTRUSTED — validate before returning
        return validate_response(raw_content)
