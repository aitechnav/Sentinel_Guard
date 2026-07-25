"""Tests for SentinelGuard gateway helpers."""

import json

import pytest

from sentinelguard.core.scanner import AggregatedResult, RiskLevel, ScanResult
from sentinelguard.gateway.config import GatewayConfig, ProviderConfig
from sentinelguard.gateway.policy import PolicyAction, evaluate_prompt_policy
from sentinelguard.gateway.providers import (
    effective_api_key_env,
    effective_provider,
    effective_upstream_url,
    extract_assistant_text,
    extract_last_user_text,
    forward_chat_completion_with_failover,
    iter_openai_stream_events,
    replace_assistant_text,
    replace_last_user_text,
    select_provider_sequence,
    _anthropic_to_openai_response,
    _build_anthropic_headers,
    _build_gemini_headers,
    _gemini_to_openai_response,
    _openai_to_anthropic_payload,
    _openai_to_gemini_payload,
)
from sentinelguard.gateway.server import _is_authorized


class TestGatewayConfig:
    def test_defaults(self):
        config = GatewayConfig()
        assert config.enabled is True
        assert config.provider == "openai"
        assert config.upstream_url == "https://api.openai.com/v1"
        assert config.sanitize is True
        assert config.default_max_tokens == 1024
        assert config.streaming_mode == "buffered"
        assert config.metrics_enabled is True
        assert config.audit_enabled is True
        assert config.audit_hash_salt_env == "SENTINELGUARD_AUDIT_SALT"

    def test_from_nested_dict(self):
        config = GatewayConfig.from_dict(
            {
                "gateway": {
                    "enabled": False,
                    "provider": "openai-compatible",
                    "upstream_url": "http://localhost:11434/v1",
                    "client_api_key_env": "SENTINELGUARD_GATEWAY_API_KEY",
                    "sanitize": False,
                    "metrics_enabled": False,
                    "audit_enabled": False,
                    "audit_hash_salt_env": "CUSTOM_AUDIT_SALT",
                }
            }
        )
        assert config.enabled is False
        assert config.provider == "openai-compatible"
        assert config.upstream_url == "http://localhost:11434/v1"
        assert config.client_api_key_env == "SENTINELGUARD_GATEWAY_API_KEY"
        assert config.sanitize is False
        assert config.metrics_enabled is False
        assert config.audit_enabled is False
        assert config.audit_hash_salt_env == "CUSTOM_AUDIT_SALT"

    def test_from_nested_dict_with_provider_pool(self):
        config = GatewayConfig.from_dict(
            {
                "gateway": {
                    "fallback_enabled": True,
                    "route_pii_to_private_provider": True,
                    "providers": [
                        {
                            "name": "public-openai",
                            "provider": "openai",
                            "upstream_url": "https://api.openai.com/v1",
                            "priority": 10,
                            "weight": 2,
                        },
                        {
                            "name": "private-ollama",
                            "provider": "openai-compatible",
                            "upstream_url": "http://ollama:11434/v1",
                            "private": True,
                            "priority": 5,
                        },
                    ],
                }
            }
        )

        assert config.route_pii_to_private_provider is True
        assert len(config.providers) == 2
        assert config.providers[0].name == "public-openai"
        assert config.providers[1].private is True

    def test_provider_defaults_are_effective_without_overwriting_config(self):
        anthropic = GatewayConfig(provider="anthropic")
        assert effective_provider(anthropic) == "anthropic"
        assert effective_upstream_url(anthropic) == "https://api.anthropic.com/v1"
        assert effective_api_key_env(anthropic) == "ANTHROPIC_API_KEY"

        gemini = GatewayConfig(provider="gemini")
        assert effective_provider(gemini) == "gemini"
        assert effective_upstream_url(gemini) == "https://generativelanguage.googleapis.com/v1beta"
        assert effective_api_key_env(gemini) == "GEMINI_API_KEY"


class TestGatewayClientAuth:
    def test_allows_requests_when_client_auth_not_configured(self):
        assert _is_authorized({}, GatewayConfig())

    def test_rejects_missing_or_wrong_client_key(self, monkeypatch):
        monkeypatch.setenv("SENTINELGUARD_GATEWAY_API_KEY", "gateway-secret")
        config = GatewayConfig(client_api_key_env="SENTINELGUARD_GATEWAY_API_KEY")

        assert not _is_authorized({}, config)
        assert not _is_authorized({"authorization": "Bearer wrong"}, config)

    def test_accepts_bearer_or_api_key_header(self, monkeypatch):
        monkeypatch.setenv("SENTINELGUARD_GATEWAY_API_KEY", "gateway-secret")
        config = GatewayConfig(client_api_key_env="SENTINELGUARD_GATEWAY_API_KEY")

        assert _is_authorized({"authorization": "Bearer gateway-secret"}, config)
        assert _is_authorized({"x-api-key": "gateway-secret"}, config)
        assert _is_authorized({"x-sentinelguard-api-key": "gateway-secret"}, config)


class TestGatewayPolicy:
    def test_pii_detection_can_redact_instead_of_blocking(self, monkeypatch):
        monkeypatch.setattr(
            "sentinelguard.gateway.policy._redact_pii",
            lambda text: "Contact <EMAIL_ADDRESS>",
        )
        result = AggregatedResult(
            is_valid=False,
            results=[
                ScanResult(
                    is_valid=False,
                    score=0.9,
                    risk_level=RiskLevel.HIGH,
                    scanner_name="pii",
                )
            ],
            failed_scanners=["pii"],
        )

        decision = evaluate_prompt_policy(
            "Contact jane@example.com",
            result,
            GatewayConfig(redact_pii=True),
        )

        assert decision.action == PolicyAction.REDACT
        assert decision.allowed
        assert decision.sanitized_text == "Contact <EMAIL_ADDRESS>"
        assert "pii_redacted" in decision.reason_codes

    def test_secret_detection_blocks_by_default(self):
        result = AggregatedResult(
            is_valid=False,
            results=[
                ScanResult(
                    is_valid=False,
                    score=1.0,
                    risk_level=RiskLevel.CRITICAL,
                    scanner_name="secrets",
                )
            ],
            failed_scanners=["secrets"],
        )

        decision = evaluate_prompt_policy(
            "api_key=sk-proj-secret",
            result,
            GatewayConfig(),
        )

        assert decision.action == PolicyAction.BLOCK
        assert not decision.allowed
        assert "secret:secrets" in decision.reason_codes


class TestGatewayProviders:
    def test_extract_last_user_text_string(self):
        messages = [
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "reply"},
            {"role": "user", "content": "second"},
        ]
        assert extract_last_user_text(messages) == "second"

    def test_extract_last_user_text_blocks(self):
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "text", "text": "world"},
                ],
            }
        ]
        assert extract_last_user_text(messages) == "hello world"

    def test_replace_last_user_text_does_not_mutate_original(self):
        messages = [{"role": "user", "content": "secret"}]
        updated = replace_last_user_text(messages, "<SECRET>")

        assert updated[0]["content"] == "<SECRET>"
        assert messages[0]["content"] == "secret"

    def test_extract_and_replace_assistant_text(self):
        response = {"choices": [{"message": {"role": "assistant", "content": "leaky response"}}]}
        assert extract_assistant_text(response) == "leaky response"

        updated = replace_assistant_text(response, "safe response")
        assert extract_assistant_text(updated) == "safe response"
        assert extract_assistant_text(response) == "leaky response"

    def test_iter_openai_stream_events(self):
        response = {
            "id": "chatcmpl_123",
            "created": 123,
            "model": "test-model",
            "choices": [
                {
                    "message": {"role": "assistant", "content": "hello world"},
                    "finish_reason": "stop",
                }
            ],
        }

        events = list(iter_openai_stream_events(response, chunk_size=5))

        assert events[-1] == "data: [DONE]\n\n"
        role_chunk = _decode_sse(events[0])
        assert role_chunk["object"] == "chat.completion.chunk"
        assert role_chunk["choices"][0]["delta"] == {"role": "assistant"}

        content = "".join(
            _decode_sse(event)["choices"][0]["delta"].get("content", "") for event in events[1:-2]
        )
        assert content == "hello world"

        final_chunk = _decode_sse(events[-2])
        assert final_chunk["choices"][0]["finish_reason"] == "stop"

    def test_private_route_filters_provider_pool(self):
        config = GatewayConfig(
            providers=[
                ProviderConfig(
                    name="public",
                    provider="openai",
                    upstream_url="https://api.openai.com/v1",
                    priority=1,
                ),
                ProviderConfig(
                    name="private",
                    provider="openai-compatible",
                    upstream_url="http://ollama:11434/v1",
                    private=True,
                    priority=2,
                ),
            ]
        )

        assert [provider.name for provider in select_provider_sequence(config)] == [
            "public",
            "private",
        ]
        assert [
            provider.name
            for provider in select_provider_sequence(config, route_constraint="private")
        ] == ["private"]

    @pytest.mark.asyncio
    async def test_failover_tries_next_provider_on_retryable_status(self, monkeypatch):
        async def fake_forward(payload, headers, config):
            if config.upstream_url == "http://bad/v1":
                return 503, {"error": {"type": "unavailable"}}
            return 200, {"choices": [{"message": {"content": "ok"}}]}

        monkeypatch.setattr(
            "sentinelguard.gateway.providers._forward_chat_completion_single",
            fake_forward,
        )
        config = GatewayConfig(
            providers=[
                ProviderConfig(
                    name="bad",
                    provider="openai",
                    upstream_url="http://bad/v1",
                    priority=1,
                ),
                ProviderConfig(
                    name="good",
                    provider="openai",
                    upstream_url="http://good/v1",
                    priority=2,
                ),
            ]
        )

        result = await forward_chat_completion_with_failover(
            {"messages": [{"role": "user", "content": "hello"}]},
            {},
            config,
        )

        assert result.status_code == 200
        assert result.provider_name == "good"
        assert [attempt.name for attempt in result.attempts] == ["bad", "good"]


class TestNativeProviderAdapters:
    def test_anthropic_payload_translation(self):
        payload = {
            "model": "claude-3-5-sonnet-latest",
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi"},
                {"role": "user", "content": "Tell me more"},
            ],
            "temperature": 0.2,
            "stop": ["END"],
        }

        translated = _openai_to_anthropic_payload(payload, GatewayConfig())

        assert translated["model"] == "claude-3-5-sonnet-latest"
        assert translated["system"] == "Be concise."
        assert translated["max_tokens"] == 1024
        assert translated["temperature"] == 0.2
        assert translated["stop_sequences"] == ["END"]
        assert translated["messages"] == [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi"},
            {"role": "user", "content": "Tell me more"},
        ]

    def test_anthropic_response_translation(self):
        response = {
            "id": "msg_123",
            "model": "claude-3-5-sonnet-latest",
            "content": [{"type": "text", "text": "Safe answer"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 3},
        }

        translated = _anthropic_to_openai_response(
            response,
            {"model": "claude-3-5-sonnet-latest"},
        )

        assert translated["id"] == "msg_123"
        assert extract_assistant_text(translated) == "Safe answer"
        assert translated["choices"][0]["finish_reason"] == "stop"
        assert translated["usage"]["total_tokens"] == 13

    def test_anthropic_headers_use_native_auth(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")

        headers = _build_anthropic_headers({}, GatewayConfig(provider="anthropic"))

        assert headers["x-api-key"] == "anthropic-key"
        assert headers["anthropic-version"] == "2023-06-01"

    def test_gemini_payload_translation(self):
        payload = {
            "model": "gemini-1.5-flash",
            "messages": [
                {"role": "system", "content": "Be helpful."},
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi"},
                {"role": "user", "content": "Return JSON"},
            ],
            "max_tokens": 200,
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }

        translated = _openai_to_gemini_payload(payload)

        assert translated["systemInstruction"] == {"parts": [{"text": "Be helpful."}]}
        assert translated["contents"] == [
            {"role": "user", "parts": [{"text": "Hello"}]},
            {"role": "model", "parts": [{"text": "Hi"}]},
            {"role": "user", "parts": [{"text": "Return JSON"}]},
        ]
        assert translated["generationConfig"]["maxOutputTokens"] == 200
        assert translated["generationConfig"]["temperature"] == 0
        assert translated["generationConfig"]["responseMimeType"] == "application/json"

    def test_gemini_response_translation(self):
        response = {
            "candidates": [
                {
                    "content": {"parts": [{"text": "Gemini answer"}]},
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 6,
                "candidatesTokenCount": 4,
                "totalTokenCount": 10,
            },
        }

        translated = _gemini_to_openai_response(
            response,
            {"model": "gemini-1.5-flash"},
        )

        assert translated["model"] == "gemini-1.5-flash"
        assert extract_assistant_text(translated) == "Gemini answer"
        assert translated["choices"][0]["finish_reason"] == "stop"
        assert translated["usage"]["total_tokens"] == 10

    def test_gemini_headers_use_native_auth(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")

        headers = _build_gemini_headers({}, GatewayConfig(provider="gemini"))

        assert headers["x-goog-api-key"] == "gemini-key"


def _decode_sse(event: str) -> dict:
    assert event.startswith("data: ")
    return json.loads(event.removeprefix("data: ").strip())
