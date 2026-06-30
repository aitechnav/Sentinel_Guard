"""Tests for SentinelGuard gateway helpers."""

import json

from sentinelguard.gateway.config import GatewayConfig
from sentinelguard.gateway.providers import (
    effective_api_key_env,
    effective_provider,
    effective_upstream_url,
    extract_assistant_text,
    extract_last_user_text,
    iter_openai_stream_events,
    replace_assistant_text,
    replace_last_user_text,
    _anthropic_to_openai_response,
    _build_anthropic_headers,
    _build_gemini_headers,
    _gemini_to_openai_response,
    _openai_to_anthropic_payload,
    _openai_to_gemini_payload,
)


class TestGatewayConfig:
    def test_defaults(self):
        config = GatewayConfig()
        assert config.enabled is True
        assert config.provider == "openai"
        assert config.upstream_url == "https://api.openai.com/v1"
        assert config.sanitize is True
        assert config.default_max_tokens == 1024
        assert config.streaming_mode == "buffered"

    def test_from_nested_dict(self):
        config = GatewayConfig.from_dict(
            {
                "gateway": {
                    "enabled": False,
                    "provider": "openai-compatible",
                    "upstream_url": "http://localhost:11434/v1",
                    "sanitize": False,
                }
            }
        )
        assert config.enabled is False
        assert config.provider == "openai-compatible"
        assert config.upstream_url == "http://localhost:11434/v1"
        assert config.sanitize is False

    def test_provider_defaults_are_effective_without_overwriting_config(self):
        anthropic = GatewayConfig(provider="anthropic")
        assert effective_provider(anthropic) == "anthropic"
        assert effective_upstream_url(anthropic) == "https://api.anthropic.com/v1"
        assert effective_api_key_env(anthropic) == "ANTHROPIC_API_KEY"

        gemini = GatewayConfig(provider="gemini")
        assert effective_provider(gemini) == "gemini"
        assert (
            effective_upstream_url(gemini)
            == "https://generativelanguage.googleapis.com/v1beta"
        )
        assert effective_api_key_env(gemini) == "GEMINI_API_KEY"


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
        response = {
            "choices": [
                {"message": {"role": "assistant", "content": "leaky response"}}
            ]
        }
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
            _decode_sse(event)["choices"][0]["delta"].get("content", "")
            for event in events[1:-2]
        )
        assert content == "hello world"

        final_chunk = _decode_sse(events[-2])
        assert final_chunk["choices"][0]["finish_reason"] == "stop"


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

        assert translated["systemInstruction"] == {
            "parts": [{"text": "Be helpful."}]
        }
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
