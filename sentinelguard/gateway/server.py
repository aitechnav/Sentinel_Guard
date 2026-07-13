"""OpenAI-compatible SentinelGuard LLM gateway."""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping, Optional

from sentinelguard.audit import AuditContext, build_audit_context, log_scan_detections
from sentinelguard.core.config import GuardConfig
from sentinelguard.core.guard import SentinelGuard
from sentinelguard.core.scanner import AggregatedResult
from sentinelguard.gateway.config import GatewayConfig
from sentinelguard.gateway.providers import (
    effective_api_key_env,
    effective_provider,
    effective_upstream_url,
    extract_assistant_text,
    extract_last_user_text,
    forward_chat_completion,
    iter_openai_stream_events,
    replace_assistant_text,
    replace_last_user_text,
)
from sentinelguard.models import model_status
from sentinelguard.monitoring import (
    metrics_content_type,
    prometheus_available,
    record_gateway_request,
    record_scan,
    render_metrics,
)

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, Response, StreamingResponse

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


def create_gateway_app(
    guard_config: Optional[GuardConfig] = None,
    gateway_config: Optional[GatewayConfig] = None,
) -> Any:
    """Create an OpenAI-compatible gateway app."""
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required for gateway mode. "
            "Install with: pip install sentinelguard[gateway]"
        )

    config = gateway_config or GatewayConfig()
    guard = SentinelGuard(config=guard_config)

    app = FastAPI(
        title="SentinelGuard LLM Gateway",
        description="OpenAI-compatible LLM gateway with SentinelGuard scanning",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/gateway/health")
    async def health():
        return {
            "status": "healthy",
            "enabled": config.enabled,
            "provider": effective_provider(config),
            "upstream_url": effective_upstream_url(config),
            "api_key_env": effective_api_key_env(config),
            "streaming_mode": config.streaming_mode,
            "metrics_enabled": config.metrics_enabled,
            "audit_enabled": config.audit_enabled,
            "client_auth_enabled": bool(_client_api_key(config)),
            "prometheus_available": prometheus_available(),
            "model_status": model_status(),
            "prompt_scanners": guard.prompt_scanner_names,
            "output_scanners": guard.output_scanner_names,
        }

    if config.metrics_enabled:

        @app.get("/metrics")
        async def metrics():
            if not prometheus_available():
                raise HTTPException(
                    status_code=501,
                    detail=(
                        "Prometheus metrics require prometheus-client. "
                        "Install with: pip install sentinelguard[monitoring]"
                    ),
                )
            return Response(content=render_metrics(), media_type=metrics_content_type())

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        if not _is_authorized(request.headers, config):
            return _unauthorized_response()

        payload = await request.json()
        _validate_payload(payload)
        audit_context = build_audit_context(
            request.headers,
            payload,
            salt_env=config.audit_hash_salt_env,
        )

        if payload.get("stream"):
            return await _handle_streaming_chat(
                payload,
                request.headers,
                config,
                guard,
                audit_context,
            )

        if not config.enabled:
            status_code, upstream_body = await forward_chat_completion(
                payload,
                request.headers,
                config,
            )
            outcome = "pass_through" if status_code < 400 else "upstream_error"
            record_gateway_request(effective_provider(config), False, outcome)
            return JSONResponse(content=upstream_body, status_code=status_code)

        messages = payload["messages"]
        prompt_text = extract_last_user_text(messages)
        prompt_scan = guard.scan_prompt(prompt_text)
        record_scan("prompt", prompt_scan)
        _audit_scan(config, audit_context, False, "prompt", prompt_scan)
        if not prompt_scan.is_valid and config.block_on_prompt_fail:
            record_gateway_request(effective_provider(config), False, "blocked_prompt")
            return _blocked_response("prompt", prompt_scan, status_code=400)

        safe_prompt = prompt_scan.sanitized_output or prompt_text
        upstream_payload = dict(payload)
        if config.sanitize and safe_prompt != prompt_text:
            upstream_payload["messages"] = replace_last_user_text(messages, safe_prompt)

        status_code, upstream_body = await forward_chat_completion(
            upstream_payload,
            request.headers,
            config,
        )
        if status_code >= 400:
            record_gateway_request(effective_provider(config), False, "upstream_error")
            return JSONResponse(content=upstream_body, status_code=status_code)

        output_text = extract_assistant_text(upstream_body)
        output_scan = guard.scan_output(output_text, prompt=safe_prompt)
        record_scan("output", output_scan)
        _audit_scan(config, audit_context, False, "output", output_scan)
        if not output_scan.is_valid and config.block_on_output_fail:
            record_gateway_request(effective_provider(config), False, "blocked_output")
            return _blocked_response("output", output_scan, status_code=502)

        safe_output = output_scan.sanitized_output or output_text
        if config.sanitize and safe_output != output_text:
            upstream_body = replace_assistant_text(upstream_body, safe_output)

        record_gateway_request(effective_provider(config), False, "passed")
        return JSONResponse(content=upstream_body, status_code=status_code)

    return app


async def _handle_streaming_chat(
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    config: GatewayConfig,
    guard: SentinelGuard,
    audit_context: AuditContext,
) -> Any:
    if config.streaming_mode != "buffered":
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported gateway streaming_mode. "
                "Use streaming_mode: buffered."
            ),
        )

    upstream_payload = dict(payload)
    upstream_payload["stream"] = False

    if not config.enabled:
        status_code, upstream_body = await forward_chat_completion(
            upstream_payload,
            headers,
            config,
        )
        if status_code >= 400:
            record_gateway_request(effective_provider(config), True, "upstream_error")
            return JSONResponse(content=upstream_body, status_code=status_code)
        record_gateway_request(effective_provider(config), True, "pass_through")
        return _streaming_response(upstream_body)

    messages = payload["messages"]
    prompt_text = extract_last_user_text(messages)
    prompt_scan = guard.scan_prompt(prompt_text)
    record_scan("prompt", prompt_scan)
    _audit_scan(config, audit_context, True, "prompt", prompt_scan)
    if not prompt_scan.is_valid and config.block_on_prompt_fail:
        record_gateway_request(effective_provider(config), True, "blocked_prompt")
        return _blocked_response("prompt", prompt_scan, status_code=400)

    safe_prompt = prompt_scan.sanitized_output or prompt_text
    if config.sanitize and safe_prompt != prompt_text:
        upstream_payload["messages"] = replace_last_user_text(messages, safe_prompt)

    status_code, upstream_body = await forward_chat_completion(
        upstream_payload,
        headers,
        config,
    )
    if status_code >= 400:
        record_gateway_request(effective_provider(config), True, "upstream_error")
        return JSONResponse(content=upstream_body, status_code=status_code)

    output_text = extract_assistant_text(upstream_body)
    output_scan = guard.scan_output(output_text, prompt=safe_prompt)
    record_scan("output", output_scan)
    _audit_scan(config, audit_context, True, "output", output_scan)
    if not output_scan.is_valid and config.block_on_output_fail:
        record_gateway_request(effective_provider(config), True, "blocked_output")
        return _blocked_response("output", output_scan, status_code=502)

    safe_output = output_scan.sanitized_output or output_text
    if config.sanitize and safe_output != output_text:
        upstream_body = replace_assistant_text(upstream_body, safe_output)

    record_gateway_request(effective_provider(config), True, "passed")
    return _streaming_response(upstream_body)


def _audit_scan(
    config: GatewayConfig,
    audit_context: AuditContext,
    streaming: bool,
    direction: str,
    result: AggregatedResult,
) -> None:
    if not config.audit_enabled:
        return
    log_scan_detections(
        audit_context,
        provider=effective_provider(config),
        streaming=streaming,
        direction=direction,
        result=result,
    )


def _streaming_response(response_json: Mapping[str, Any]) -> Any:
    return StreamingResponse(
        iter_openai_stream_events(response_json),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _validate_payload(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")
    messages = payload.get("messages")
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="OpenAI chat payload requires messages[]")
    if not extract_last_user_text(messages):
        raise HTTPException(status_code=400, detail="No user message text found")


def _is_authorized(headers: Mapping[str, str], config: GatewayConfig) -> bool:
    expected = _client_api_key(config)
    if not expected:
        return True

    incoming = {key.lower(): value for key, value in headers.items()}
    candidates = []

    authorization = incoming.get("authorization")
    if authorization:
        candidates.append(authorization)
        bearer_prefix = "Bearer "
        if authorization.startswith(bearer_prefix):
            candidates.append(authorization[len(bearer_prefix):])

    if incoming.get("x-api-key"):
        candidates.append(incoming["x-api-key"])
    if incoming.get("x-sentinelguard-api-key"):
        candidates.append(incoming["x-sentinelguard-api-key"])

    return any(candidate == expected for candidate in candidates)


def _client_api_key(config: GatewayConfig) -> Optional[str]:
    if config.client_api_key:
        return config.client_api_key
    if config.client_api_key_env:
        return os.getenv(config.client_api_key_env)
    return None


def _unauthorized_response() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={
            "error": {
                "message": "SentinelGuard gateway authentication failed",
                "type": "sentinelguard_gateway_unauthorized",
            }
        },
    )


def _blocked_response(
    direction: str,
    result: AggregatedResult,
    status_code: int,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": f"SentinelGuard blocked {direction}",
                "type": f"sentinelguard_{direction}_blocked",
                "failed_scanners": result.failed_scanners,
                "risk": result.highest_risk.value,
            }
        },
    )
