"""Tests for ModelProvider interface and response validation.

Written FIRST per AGENTS.md rule #3.

Every model response is UNTRUSTED (SPEC threats #1 and #2).
The validator must reject anything that is not a well-formed tool request.

Test groups:
  A. Schema validation — valid payloads pass, bad ones are rejected
  B. MockProvider — deterministic, no I/O, scripted responses
  C. OllamaProvider — network is mocked; tests validate the HTTP path
  D. Provider factory — get_provider() returns the right type
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.providers.schema import validate_response, ValidationError
from app.providers.mock import MockProvider
from app.providers.ollama import OllamaProvider
from app.providers.hosted import HostedProvider
from app.providers import get_provider
from app.providers.base import ToolRequest


# ═══════════════════════════════════════════════════════════════════
# A. SCHEMA VALIDATION
# ═══════════════════════════════════════════════════════════════════

class TestSchemaValidation:
    """validate_response() must accept exactly the allowed structure
    and reject anything else."""

    # ── valid payloads ─────────────────────────────────────────────

    def test_valid_minimal_tool_request(self):
        payload = json.dumps({
            "tool": "read_file",
            "args": {"path": "src/main.py"},
        })
        req = validate_response(payload)
        assert req.tool == "read_file"
        assert req.args == {"path": "src/main.py"}

    def test_valid_tool_with_empty_args(self):
        payload = json.dumps({"tool": "list_files", "args": {}})
        req = validate_response(payload)
        assert req.tool == "list_files"
        assert req.args == {}

    def test_valid_tool_with_thought(self):
        """Optional 'thought' field is allowed."""
        payload = json.dumps({
            "thought": "I need to read the main module.",
            "tool": "read_file",
            "args": {"path": "main.py"},
        })
        req = validate_response(payload)
        assert req.tool == "read_file"
        assert req.thought == "I need to read the main module."

    def test_valid_tool_args_with_nested_object(self):
        payload = json.dumps({
            "tool": "write_file",
            "args": {"path": "out.py", "content": "x = 1\n"},
        })
        req = validate_response(payload)
        assert req.args["path"] == "out.py"

    def test_valid_tool_run_command(self):
        payload = json.dumps({
            "tool": "run_command",
            "args": {"command": "pytest tests/"},
        })
        req = validate_response(payload)
        assert req.tool == "run_command"

    def test_valid_tool_finish(self):
        """'finish' signals task completion."""
        payload = json.dumps({
            "tool": "finish",
            "args": {"summary": "Done."},
        })
        req = validate_response(payload)
        assert req.tool == "finish"

    # ── malformed / invalid payloads ──────────────────────────────

    def test_reject_plain_text(self):
        with pytest.raises(ValidationError):
            validate_response("Sure, I can help you with that!")

    def test_reject_empty_string(self):
        with pytest.raises(ValidationError):
            validate_response("")

    def test_reject_null_json(self):
        with pytest.raises(ValidationError):
            validate_response("null")

    def test_reject_json_array(self):
        with pytest.raises(ValidationError):
            validate_response('[{"tool":"read_file","args":{}}]')

    def test_reject_missing_tool_field(self):
        with pytest.raises(ValidationError):
            validate_response(json.dumps({"args": {"path": "x.py"}}))

    def test_reject_missing_args_field(self):
        with pytest.raises(ValidationError):
            validate_response(json.dumps({"tool": "read_file"}))

    def test_reject_tool_not_a_string(self):
        with pytest.raises(ValidationError):
            validate_response(json.dumps({"tool": 42, "args": {}}))

    def test_reject_args_not_an_object(self):
        with pytest.raises(ValidationError):
            validate_response(json.dumps({"tool": "read_file", "args": "path/to/file"}))

    def test_reject_empty_tool_name(self):
        with pytest.raises(ValidationError):
            validate_response(json.dumps({"tool": "", "args": {}}))

    def test_reject_extra_top_level_field(self):
        """Extra fields beyond tool/args/thought must be rejected."""
        with pytest.raises(ValidationError):
            validate_response(json.dumps({
                "tool": "read_file",
                "args": {},
                "inject": "rm -rf /",   # <-- unknown extra field
            }))

    def test_reject_malformed_json(self):
        with pytest.raises(ValidationError):
            validate_response('{"tool": "read_file", "args":')

    def test_reject_thought_not_a_string(self):
        with pytest.raises(ValidationError):
            validate_response(json.dumps({
                "thought": 999,
                "tool": "read_file",
                "args": {},
            }))

    def test_reject_tool_name_too_long(self):
        with pytest.raises(ValidationError):
            validate_response(json.dumps({"tool": "x" * 200, "args": {}}))

    def test_reject_deeply_nested_args_attack(self):
        """A deeply nested object should be rejected to prevent DoS."""
        def nest(depth: int):
            obj = {}
            cur = obj
            for _ in range(depth):
                cur["a"] = {}
                cur = cur["a"]
            return obj

        with pytest.raises(ValidationError):
            validate_response(json.dumps({"tool": "read_file", "args": nest(20)}))


# ═══════════════════════════════════════════════════════════════════
# B. MOCK PROVIDER
# ═══════════════════════════════════════════════════════════════════

class TestMockProvider:
    """MockProvider is deterministic and makes no network/file calls."""

    @pytest.mark.asyncio
    async def test_mock_returns_scripted_response(self):
        canned = {"tool": "read_file", "args": {"path": "main.py"}}
        provider = MockProvider(responses=[json.dumps(canned)])
        result = await provider.complete(messages=[{"role": "user", "content": "go"}])
        assert result.tool == "read_file"

    @pytest.mark.asyncio
    async def test_mock_cycles_through_responses(self):
        r1 = json.dumps({"tool": "read_file", "args": {"path": "a.py"}})
        r2 = json.dumps({"tool": "finish", "args": {"summary": "done"}})
        provider = MockProvider(responses=[r1, r2])

        out1 = await provider.complete(messages=[{"role": "user", "content": "step1"}])
        out2 = await provider.complete(messages=[{"role": "user", "content": "step2"}])
        assert out1.tool == "read_file"
        assert out2.tool == "finish"

    @pytest.mark.asyncio
    async def test_mock_raises_on_scripted_invalid_response(self):
        """If a canned response is invalid, MockProvider must still raise."""
        provider = MockProvider(responses=["not valid json"])
        with pytest.raises(ValidationError):
            await provider.complete(messages=[{"role": "user", "content": "go"}])

    @pytest.mark.asyncio
    async def test_mock_records_call_history(self):
        canned = json.dumps({"tool": "finish", "args": {}})
        provider = MockProvider(responses=[canned, canned])
        await provider.complete(messages=[{"role": "user", "content": "a"}])
        await provider.complete(messages=[{"role": "user", "content": "b"}])
        assert len(provider.call_history) == 2

    @pytest.mark.asyncio
    async def test_mock_returns_tool_request_dataclass(self):
        canned = json.dumps({"tool": "list_files", "args": {}})
        provider = MockProvider(responses=[canned])
        result = await provider.complete(messages=[])
        assert isinstance(result, ToolRequest)

    def test_mock_has_no_network_dependency(self):
        """MockProvider must not require any live connection."""
        provider = MockProvider(responses=[])
        # Simply instantiating it without any network available is the test.
        assert provider is not None


# ═══════════════════════════════════════════════════════════════════
# C. OLLAMA PROVIDER (HTTP mocked)
# ═══════════════════════════════════════════════════════════════════

class TestOllamaProvider:
    """OllamaProvider uses httpx; we mock the HTTP layer entirely."""

    def _mock_response(self, payload: str):
        """Build a fake httpx Response-like object."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "message": {"role": "assistant", "content": payload}
        }
        resp.raise_for_status = MagicMock()
        return resp

    @pytest.mark.asyncio
    async def test_ollama_valid_response_parsed(self):
        payload = json.dumps({"tool": "read_file", "args": {"path": "x.py"}})
        provider = OllamaProvider(model="codellama")

        with patch("app.providers.ollama.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=self._mock_response(payload))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await provider.complete(messages=[{"role": "user", "content": "go"}])

        assert result.tool == "read_file"

    @pytest.mark.asyncio
    async def test_ollama_invalid_response_raises(self):
        """If Ollama returns non-JSON prose, ValidationError must be raised."""
        provider = OllamaProvider(model="codellama")

        with patch("app.providers.ollama.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=self._mock_response("Sure! I'll do that."))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(ValidationError):
                await provider.complete(messages=[{"role": "user", "content": "go"}])

    @pytest.mark.asyncio
    async def test_ollama_extra_fields_rejected(self):
        payload = json.dumps({
            "tool": "read_file",
            "args": {},
            "secret_payload": "exfiltrate",
        })
        provider = OllamaProvider(model="codellama")

        with patch("app.providers.ollama.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=self._mock_response(payload))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(ValidationError):
                await provider.complete(messages=[{"role": "user", "content": "go"}])

    def test_ollama_default_base_url(self):
        provider = OllamaProvider(model="llama3")
        assert "11434" in provider.base_url

    def test_ollama_custom_base_url(self):
        provider = OllamaProvider(model="llama3", base_url="http://myhost:11434")
        assert provider.base_url == "http://myhost:11434"


# ═══════════════════════════════════════════════════════════════════
# D. HOSTED PROVIDER PLACEHOLDER
# ═══════════════════════════════════════════════════════════════════

class TestHostedProvider:
    def test_hosted_provider_exists(self):
        provider = HostedProvider()
        assert provider is not None

    @pytest.mark.asyncio
    async def test_hosted_provider_raises_not_implemented(self):
        provider = HostedProvider()
        with pytest.raises(NotImplementedError):
            await provider.complete(messages=[])


# ═══════════════════════════════════════════════════════════════════
# E. PROVIDER FACTORY
# ═══════════════════════════════════════════════════════════════════

class TestProviderFactory:
    def test_get_provider_mock(self):
        provider = get_provider("mock")
        assert isinstance(provider, MockProvider)

    def test_get_provider_ollama(self):
        provider = get_provider("ollama")
        assert isinstance(provider, OllamaProvider)

    def test_get_provider_hosted(self):
        provider = get_provider("hosted")
        assert isinstance(provider, HostedProvider)

    def test_get_provider_unknown_raises(self):
        with pytest.raises(ValueError):
            get_provider("unknown_provider_xyz")
