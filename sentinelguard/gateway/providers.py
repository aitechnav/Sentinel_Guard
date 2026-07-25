"""Provider forwarding helpers for OpenAI-compatible gateway requests."""

from __future__ import annotations

import copy
import json
import os
import threading
import time
from dataclasses import dataclass, replace
from itertools import groupby
from typing import Any, Iterator, Mapping, Optional, Tuple

from sentinelguard.gateway.config import GatewayConfig, ProviderConfig

OPENAI_DEFAULT_UPSTREAM = "https://api.openai.com/v1"
ANTHROPIC_DEFAULT_UPSTREAM = "https://api.anthropic.com/v1"
GEMINI_DEFAULT_UPSTREAM = "https://generativelanguage.googleapis.com/v1beta"

OPENAI_COMPATIBLE_DEFAULTS = {
    "deepseek": ("https://api.deepseek.com", ["DEEPSEEK_API_KEY", "OPENAI_API_KEY"]),
    "huggingface": (
        "https://router.huggingface.co/v1",
        ["HF_TOKEN", "HUGGINGFACE_API_KEY", "OPENAI_API_KEY"],
    ),
    "minimax": ("https://api.minimaxi.com/v1", ["MINIMAX_API_KEY", "OPENAI_API_KEY"]),
    "mistral": ("https://api.mistral.ai/v1", ["MISTRAL_API_KEY", "OPENAI_API_KEY"]),
    "ollama": ("http://localhost:11434/v1", ["OLLAMA_API_KEY"]),
}

PROVIDER_ALIASES = {
    "anthropic": "anthropic",
    "claude": "anthropic",
    "deep-seek": "deepseek",
    "deepseek": "deepseek",
    "gemini": "gemini",
    "google": "gemini",
    "google-gemini": "gemini",
    "hf": "huggingface",
    "hugging-face": "huggingface",
    "huggingface": "huggingface",
    "minimax": "minimax",
    "mini-max": "minimax",
    "minimaxi": "minimax",
    "mistral": "mistral",
    "ollama": "ollama",
    "openai": "openai",
    "openai-compatible": "openai-compatible",
}

_ROUTER_LOCK = threading.Lock()
_ROUTER_COUNTERS: dict[tuple[int, str], int] = {}


@dataclass(frozen=True)
class ProviderAttempt:
    """One provider attempt made by the gateway router."""

    name: str
    provider: str
    status_code: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "provider": self.provider,
            "status_code": self.status_code,
            "error": self.error,
        }


@dataclass(frozen=True)
class ForwardResult:
    """Provider forwarding result with routing metadata."""

    status_code: int
    body: dict
    provider_name: str
    provider: str
    attempts: tuple[ProviderAttempt, ...] = ()


def extract_last_user_text(messages: list) -> str:
    """Extract text from the last user message in an OpenAI-style chat payload."""
    for message in reversed(messages):
        if message.get("role") != "user":
            continue
        return _content_to_text(message.get("content", ""))
    return ""


def replace_last_user_text(messages: list, replacement: str) -> list:
    """Return a copy of messages with the last user message content replaced."""
    updated = copy.deepcopy(messages)
    for message in reversed(updated):
        if message.get("role") != "user":
            continue
        content = message.get("content", "")
        if isinstance(content, str):
            message["content"] = replacement
            return updated
        if isinstance(content, list):
            message["content"] = [{"type": "text", "text": replacement}]
            return updated
    return updated


def extract_assistant_text(response_json: Mapping[str, Any]) -> str:
    """Extract the first assistant text from an OpenAI-style chat response."""
    choices = response_json.get("choices") or []
    if not choices:
        return ""
    first = choices[0] or {}
    message = first.get("message") or {}
    if message:
        return _content_to_text(message.get("content", ""))
    return _content_to_text(first.get("text", ""))


def replace_assistant_text(response_json: Mapping[str, Any], replacement: str) -> dict:
    """Return a copy of an OpenAI-style response with assistant text replaced."""
    updated = copy.deepcopy(dict(response_json))
    choices = updated.get("choices") or []
    if not choices:
        return updated
    first = choices[0] or {}
    message = first.get("message")
    if isinstance(message, dict):
        message["content"] = replacement
    elif "text" in first:
        first["text"] = replacement
    return updated


def iter_openai_stream_events(
    response_json: Mapping[str, Any],
    chunk_size: int = 160,
) -> Iterator[str]:
    """Yield OpenAI-compatible SSE chat completion chunks from a full response."""
    response_id = str(response_json.get("id") or f"chatcmpl-sentinel-{int(time.time())}")
    created = int(response_json.get("created") or time.time())
    model = response_json.get("model")
    choice = _first(response_json.get("choices")) or {}
    message = choice.get("message") or {}
    text = _content_to_text(message.get("content", ""))
    finish_reason = choice.get("finish_reason") or "stop"

    yield _sse_event(
        {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant"},
                    "finish_reason": None,
                }
            ],
        }
    )

    for chunk in _text_chunks(text, chunk_size):
        yield _sse_event(
            {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": chunk},
                        "finish_reason": None,
                    }
                ],
            }
        )

    yield _sse_event(
        {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": finish_reason,
                }
            ],
        }
    )
    yield "data: [DONE]\n\n"


async def forward_chat_completion(
    payload: Mapping[str, Any],
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
) -> Tuple[int, dict]:
    """Forward a chat completion request to the configured upstream provider."""
    return await _forward_chat_completion_single(payload, incoming_headers, config)


async def forward_chat_completion_with_failover(
    payload: Mapping[str, Any],
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
    *,
    route_constraint: str = "any",
) -> ForwardResult:
    """Forward a chat completion request using provider-pool failover.

    Only provider or network failures are eligible for failover. Policy blocks
    happen before this function is called, so blocked prompts are never retried
    against another provider.
    """
    candidates = select_provider_sequence(config, route_constraint=route_constraint)
    if not candidates:
        body = {
            "error": {
                "message": "No eligible upstream provider for SentinelGuard route",
                "type": "sentinelguard_no_eligible_provider",
                "route_constraint": route_constraint,
            }
        }
        return ForwardResult(
            status_code=503,
            body=body,
            provider_name="none",
            provider="none",
            attempts=(),
        )

    attempts: list[ProviderAttempt] = []
    last_body: dict = {}
    last_status = 502

    for candidate in candidates:
        candidate_config = _gateway_config_for_provider(config, candidate)
        provider = effective_provider(candidate_config)
        try:
            status_code, body = await _forward_chat_completion_single(
                payload,
                incoming_headers,
                candidate_config,
            )
        except Exception as exc:
            attempts.append(
                ProviderAttempt(
                    name=candidate.name,
                    provider=provider,
                    error=exc.__class__.__name__,
                )
            )
            last_status = 502
            last_body = {
                "error": {
                    "message": str(exc),
                    "type": "sentinelguard_upstream_exception",
                }
            }
            if not config.fallback_enabled:
                break
            continue

        attempts.append(
            ProviderAttempt(
                name=candidate.name,
                provider=provider,
                status_code=status_code,
            )
        )
        if (
            status_code < 400
            or not config.fallback_enabled
            or not _is_failover_status(status_code, config)
        ):
            return ForwardResult(
                status_code=status_code,
                body=body,
                provider_name=candidate.name,
                provider=provider,
                attempts=tuple(attempts),
            )

        last_status = status_code
        last_body = body

    last_attempt = attempts[-1] if attempts else None
    return ForwardResult(
        status_code=last_status,
        body=last_body,
        provider_name=last_attempt.name if last_attempt else "none",
        provider=last_attempt.provider if last_attempt else "none",
        attempts=tuple(attempts),
    )


async def _forward_chat_completion_single(
    payload: Mapping[str, Any],
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
) -> Tuple[int, dict]:
    """Forward a chat completion request to one configured provider."""
    httpx = _load_httpx()
    provider = effective_provider(config)

    if provider == "anthropic":
        return await _forward_anthropic(httpx, payload, incoming_headers, config)
    if provider == "gemini":
        return await _forward_gemini(httpx, payload, incoming_headers, config)
    return await _forward_openai_compatible(httpx, payload, incoming_headers, config)


def effective_provider(config: GatewayConfig) -> str:
    """Return the adapter provider name used by the gateway."""
    return _normalize_provider(config.provider)


def configured_providers(config: GatewayConfig) -> list[ProviderConfig]:
    """Return configured provider candidates, preserving single-provider compatibility."""
    if config.providers:
        return [provider for provider in config.providers if provider.enabled]
    return [
        ProviderConfig(
            name=effective_provider(config),
            provider=config.provider,
            upstream_url=config.upstream_url,
            api_key_env=config.api_key_env,
            api_key=config.api_key,
            enabled=True,
            private=False,
            priority=100,
            weight=1,
            timeout_seconds=config.timeout_seconds,
        )
    ]


def select_provider_sequence(
    config: GatewayConfig,
    *,
    route_constraint: str = "any",
) -> list[ProviderConfig]:
    """Return ordered provider attempts for one request.

    Providers are sorted by priority, and providers with the same priority use
    a small weighted rotation for the first attempt while preserving a unique
    fallback sequence.
    """
    providers = configured_providers(config)
    if route_constraint == "private":
        providers = [provider for provider in providers if provider.private]
    if not providers:
        return []

    ordered: list[ProviderConfig] = []
    sorted_providers = sorted(
        providers,
        key=lambda provider: (int(provider.priority), provider.name),
    )
    for _priority, group_iter in groupby(sorted_providers, key=lambda p: int(p.priority)):
        group = list(group_iter)
        ordered.extend(_weighted_rotation(group, route_constraint))
    return ordered


def _normalize_provider(provider: str) -> str:
    provider = (provider or "openai").strip().lower().replace("_", "-")
    return PROVIDER_ALIASES.get(provider, "openai-compatible")


def _weighted_rotation(
    providers: list[ProviderConfig],
    route_constraint: str,
) -> list[ProviderConfig]:
    expanded: list[ProviderConfig] = []
    for provider in providers:
        weight = max(1, min(100, int(provider.weight or 1)))
        expanded.extend([provider] * weight)
    if not expanded:
        return providers

    key = (hash(tuple(provider.name for provider in providers)), route_constraint)
    with _ROUTER_LOCK:
        counter = _ROUTER_COUNTERS.get(key, 0)
        _ROUTER_COUNTERS[key] = counter + 1

    rotated = expanded[counter % len(expanded) :] + expanded[: counter % len(expanded)]
    unique: list[ProviderConfig] = []
    seen = set()
    for provider in rotated:
        if provider.name in seen:
            continue
        unique.append(provider)
        seen.add(provider.name)
    return unique


def _gateway_config_for_provider(
    config: GatewayConfig,
    provider: ProviderConfig,
) -> GatewayConfig:
    return replace(
        config,
        provider=provider.provider,
        upstream_url=provider.upstream_url,
        api_key_env=provider.api_key_env,
        api_key=provider.api_key,
        timeout_seconds=(
            provider.timeout_seconds
            if provider.timeout_seconds is not None
            else config.timeout_seconds
        ),
        providers=[],
    )


def _is_failover_status(status_code: int, config: GatewayConfig) -> bool:
    return status_code in set(config.failover_status_codes)


def effective_upstream_url(config: GatewayConfig) -> str:
    """Return the provider-aware upstream URL."""
    url = (config.upstream_url or "").rstrip("/")
    provider = effective_provider(config)

    if provider == "anthropic" and (not url or url == OPENAI_DEFAULT_UPSTREAM):
        return ANTHROPIC_DEFAULT_UPSTREAM
    if provider == "gemini" and (not url or url == OPENAI_DEFAULT_UPSTREAM):
        return GEMINI_DEFAULT_UPSTREAM
    if provider in OPENAI_COMPATIBLE_DEFAULTS and (not url or url == OPENAI_DEFAULT_UPSTREAM):
        return OPENAI_COMPATIBLE_DEFAULTS[provider][0]
    return url or OPENAI_DEFAULT_UPSTREAM


def effective_api_key_env(config: GatewayConfig) -> str:
    """Return the provider-aware default API key environment variable."""
    provider = effective_provider(config)
    configured = config.api_key_env or ""
    if provider == "anthropic" and configured == "OPENAI_API_KEY":
        return "ANTHROPIC_API_KEY"
    if provider == "gemini" and configured == "OPENAI_API_KEY":
        return "GEMINI_API_KEY"
    if provider in OPENAI_COMPATIBLE_DEFAULTS and configured == "OPENAI_API_KEY":
        return OPENAI_COMPATIBLE_DEFAULTS[provider][1][0]
    return configured or "OPENAI_API_KEY"


async def _forward_openai_compatible(
    httpx: Any,
    payload: Mapping[str, Any],
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
) -> Tuple[int, dict]:
    headers = _build_openai_headers(incoming_headers, config)
    url = f"{effective_upstream_url(config)}/chat/completions"
    body = dict(payload)
    return await _post_json(httpx, url, body, headers, config)


async def _forward_anthropic(
    httpx: Any,
    payload: Mapping[str, Any],
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
) -> Tuple[int, dict]:
    headers = _build_anthropic_headers(incoming_headers, config)
    url = f"{effective_upstream_url(config)}/messages"
    body = _openai_to_anthropic_payload(payload, config)
    status_code, upstream_body = await _post_json(httpx, url, body, headers, config)
    if status_code >= 400:
        return status_code, upstream_body
    return status_code, _anthropic_to_openai_response(upstream_body, payload)


async def _forward_gemini(
    httpx: Any,
    payload: Mapping[str, Any],
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
) -> Tuple[int, dict]:
    headers = _build_gemini_headers(incoming_headers, config)
    model = _gemini_model_path(str(payload.get("model") or "gemini-1.5-flash"))
    url = f"{effective_upstream_url(config)}/{model}:generateContent"
    body = _openai_to_gemini_payload(payload)
    status_code, upstream_body = await _post_json(httpx, url, body, headers, config)
    if status_code >= 400:
        return status_code, upstream_body
    return status_code, _gemini_to_openai_response(upstream_body, payload)


async def _post_json(
    httpx: Any,
    url: str,
    body: Mapping[str, Any],
    headers: Mapping[str, str],
    config: GatewayConfig,
) -> Tuple[int, dict]:
    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        response = await client.post(url, json=dict(body), headers=dict(headers))
    try:
        response_body = response.json()
    except ValueError:
        response_body = {"error": {"message": response.text, "type": "upstream_non_json"}}
    return response.status_code, response_body


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif item.get("type") == "text" and isinstance(item.get("content"), str):
                parts.append(item["content"])
        return " ".join(parts)
    return ""


def _sse_event(payload: Mapping[str, Any]) -> str:
    return f"data: {json.dumps(dict(payload), separators=(',', ':'))}\n\n"


def _text_chunks(text: str, chunk_size: int) -> Iterator[str]:
    chunk_size = max(1, int(chunk_size or 1))
    for start in range(0, len(text), chunk_size):
        yield text[start : start + chunk_size]


def _openai_to_anthropic_payload(
    payload: Mapping[str, Any],
    config: GatewayConfig,
) -> dict:
    system_text = _system_text(payload.get("messages", []))
    messages = []
    for message in payload.get("messages", []):
        role = message.get("role")
        if role in {"system", "developer"}:
            continue

        text = _content_to_text(message.get("content", ""))
        if not text:
            continue

        anthropic_role = "assistant" if role == "assistant" else "user"
        messages.append({"role": anthropic_role, "content": text})

    body = {
        "model": payload.get("model"),
        "max_tokens": _request_max_tokens(payload, config.default_max_tokens),
        "messages": messages,
    }
    if system_text:
        body["system"] = system_text
    if payload.get("temperature") is not None:
        body["temperature"] = payload["temperature"]
    if payload.get("top_p") is not None:
        body["top_p"] = payload["top_p"]

    stop_sequences = _stop_sequences(payload.get("stop"))
    if stop_sequences:
        body["stop_sequences"] = stop_sequences

    if payload.get("user"):
        body["metadata"] = {"user_id": str(payload["user"])}

    return body


def _anthropic_to_openai_response(
    response_json: Mapping[str, Any],
    original_payload: Mapping[str, Any],
) -> dict:
    text = _anthropic_text(response_json)
    usage = response_json.get("usage") or {}
    prompt_tokens = usage.get("input_tokens")
    completion_tokens = usage.get("output_tokens")
    total_tokens = _sum_tokens(prompt_tokens, completion_tokens)

    return {
        "id": response_json.get("id") or f"chatcmpl-anthropic-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": response_json.get("model") or original_payload.get("model"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": _anthropic_finish_reason(response_json.get("stop_reason")),
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens or 0,
            "completion_tokens": completion_tokens or 0,
            "total_tokens": total_tokens,
        },
    }


def _openai_to_gemini_payload(payload: Mapping[str, Any]) -> dict:
    system_text = _system_text(payload.get("messages", []))
    contents = []
    for message in payload.get("messages", []):
        role = message.get("role")
        if role in {"system", "developer"}:
            continue

        text = _content_to_text(message.get("content", ""))
        if not text:
            continue

        gemini_role = "model" if role == "assistant" else "user"
        contents.append({"role": gemini_role, "parts": [{"text": text}]})

    body: dict = {"contents": contents}
    if system_text:
        body["systemInstruction"] = {"parts": [{"text": system_text}]}

    generation_config = _gemini_generation_config(payload)
    if generation_config:
        body["generationConfig"] = generation_config

    return body


def _gemini_to_openai_response(
    response_json: Mapping[str, Any],
    original_payload: Mapping[str, Any],
) -> dict:
    candidate = _first(response_json.get("candidates"))
    usage = response_json.get("usageMetadata") or {}
    prompt_tokens = usage.get("promptTokenCount")
    completion_tokens = usage.get("candidatesTokenCount")
    total_tokens = usage.get("totalTokenCount") or _sum_tokens(
        prompt_tokens,
        completion_tokens,
    )

    return {
        "id": f"chatcmpl-gemini-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": original_payload.get("model"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": _gemini_text(candidate)},
                "finish_reason": _gemini_finish_reason(
                    candidate.get("finishReason") if candidate else None
                ),
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens or 0,
            "completion_tokens": completion_tokens or 0,
            "total_tokens": total_tokens,
        },
    }


def _system_text(messages: Any) -> str:
    parts = []
    for message in messages or []:
        if not isinstance(message, Mapping):
            continue
        if message.get("role") in {"system", "developer"}:
            text = _content_to_text(message.get("content", ""))
            if text:
                parts.append(text)
    return "\n\n".join(parts)


def _request_max_tokens(
    payload: Mapping[str, Any],
    fallback: Optional[int] = None,
) -> Optional[int]:
    value = payload.get("max_tokens")
    if value is None:
        value = payload.get("max_completion_tokens")
    if value is None:
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _stop_sequences(stop: Any) -> list:
    if isinstance(stop, str):
        return [stop]
    if isinstance(stop, list):
        return [str(item) for item in stop if item]
    return []


def _gemini_generation_config(payload: Mapping[str, Any]) -> dict:
    generation_config = {}
    max_tokens = _request_max_tokens(payload)
    if max_tokens is not None:
        generation_config["maxOutputTokens"] = max_tokens
    if payload.get("temperature") is not None:
        generation_config["temperature"] = payload["temperature"]
    if payload.get("top_p") is not None:
        generation_config["topP"] = payload["top_p"]
    if payload.get("top_k") is not None:
        generation_config["topK"] = payload["top_k"]

    stop_sequences = _stop_sequences(payload.get("stop"))
    if stop_sequences:
        generation_config["stopSequences"] = stop_sequences

    if isinstance(payload.get("n"), int) and payload["n"] > 1:
        generation_config["candidateCount"] = payload["n"]

    response_format = payload.get("response_format")
    if isinstance(response_format, Mapping) and response_format.get("type") == "json_object":
        generation_config["responseMimeType"] = "application/json"

    return generation_config


def _anthropic_text(response_json: Mapping[str, Any]) -> str:
    parts = []
    for item in response_json.get("content") or []:
        if isinstance(item, Mapping) and isinstance(item.get("text"), str):
            parts.append(item["text"])
    return "".join(parts)


def _gemini_text(candidate: Optional[Mapping[str, Any]]) -> str:
    if not candidate:
        return ""
    content = candidate.get("content") or {}
    parts = []
    for item in content.get("parts") or []:
        if isinstance(item, Mapping) and isinstance(item.get("text"), str):
            parts.append(item["text"])
    return "".join(parts)


def _anthropic_finish_reason(reason: Optional[str]) -> Optional[str]:
    return {
        "end_turn": "stop",
        "max_tokens": "length",
        "stop_sequence": "stop",
        "tool_use": "tool_calls",
        "refusal": "content_filter",
    }.get(reason or "", reason)


def _gemini_finish_reason(reason: Optional[str]) -> Optional[str]:
    return {
        "STOP": "stop",
        "MAX_TOKENS": "length",
        "SAFETY": "content_filter",
        "RECITATION": "content_filter",
        "BLOCKLIST": "content_filter",
        "PROHIBITED_CONTENT": "content_filter",
        "SPII": "content_filter",
    }.get(reason or "", reason.lower() if reason else None)


def _gemini_model_path(model: str) -> str:
    model = model.strip("/")
    if model.startswith("models/"):
        return model
    return f"models/{model}"


def _sum_tokens(*values: Optional[int]) -> int:
    return sum(value for value in values if isinstance(value, int))


def _first(items: Any) -> Optional[Mapping[str, Any]]:
    if isinstance(items, list) and items:
        first = items[0]
        if isinstance(first, Mapping):
            return first
    return None


def _build_openai_headers(
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
) -> dict:
    headers = {"content-type": "application/json"}
    incoming = {key.lower(): value for key, value in incoming_headers.items()}

    api_key = _api_key(config)
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    elif config.forward_authorization and incoming.get("authorization"):
        headers["authorization"] = incoming["authorization"]

    for name in ("openai-organization", "openai-project"):
        if incoming.get(name):
            headers[name] = incoming[name]

    return headers


def _build_anthropic_headers(
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
) -> dict:
    headers = {
        "content-type": "application/json",
        "anthropic-version": config.anthropic_version,
    }
    incoming = {key.lower(): value for key, value in incoming_headers.items()}

    api_key = _api_key(config)
    if api_key:
        headers["x-api-key"] = api_key
    elif config.forward_authorization and incoming.get("x-api-key"):
        headers["x-api-key"] = incoming["x-api-key"]
    elif config.forward_authorization and incoming.get("authorization"):
        headers["x-api-key"] = _bearer_token(incoming["authorization"])

    if incoming.get("anthropic-beta"):
        headers["anthropic-beta"] = incoming["anthropic-beta"]

    return headers


def _build_gemini_headers(
    incoming_headers: Mapping[str, str],
    config: GatewayConfig,
) -> dict:
    headers = {"content-type": "application/json"}
    incoming = {key.lower(): value for key, value in incoming_headers.items()}

    api_key = _api_key(config)
    if api_key:
        headers["x-goog-api-key"] = api_key
    elif config.forward_authorization and incoming.get("x-goog-api-key"):
        headers["x-goog-api-key"] = incoming["x-goog-api-key"]
    elif config.forward_authorization and incoming.get("authorization"):
        headers["authorization"] = incoming["authorization"]

    return headers


def _bearer_token(value: str) -> str:
    prefix = "Bearer "
    if value.startswith(prefix):
        return value[len(prefix) :]
    return value


def _api_key(config: GatewayConfig) -> Optional[str]:
    if config.api_key:
        return config.api_key
    for env_name in _api_key_env_names(config):
        value = os.getenv(env_name)
        if value:
            return value
    return None


def _api_key_env_names(config: GatewayConfig) -> list:
    provider = effective_provider(config)
    configured = config.api_key_env or ""

    if provider == "anthropic":
        if configured and configured != "OPENAI_API_KEY":
            return [configured]
        return ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]

    if provider == "gemini":
        if configured and configured != "OPENAI_API_KEY":
            return [configured]
        return ["GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY"]

    if provider in OPENAI_COMPATIBLE_DEFAULTS:
        if configured and configured != "OPENAI_API_KEY":
            return [configured]
        return OPENAI_COMPATIBLE_DEFAULTS[provider][1]

    return [configured or "OPENAI_API_KEY"]


def _load_httpx() -> Any:
    try:
        import httpx
    except ImportError as exc:
        raise ImportError(
            "httpx is required for gateway mode. "
            "Install with: pip install sentinelguard[gateway]"
        ) from exc

    return httpx
