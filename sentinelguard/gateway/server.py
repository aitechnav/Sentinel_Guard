"""OpenAI-compatible SentinelGuard LLM gateway."""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

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

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, StreamingResponse

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
            "prompt_scanners": guard.prompt_scanner_names,
            "output_scanners": guard.output_scanner_names,
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        payload = await request.json()
        _validate_payload(payload)

        if payload.get("stream"):
            return await _handle_streaming_chat(payload, request.headers, config, guard)

        if not config.enabled:
            status_code, upstream_body = await forward_chat_completion(
                payload,
                request.headers,
                config,
            )
            return JSONResponse(content=upstream_body, status_code=status_code)

        messages = payload["messages"]
        prompt_text = extract_last_user_text(messages)
        prompt_scan = guard.scan_prompt(prompt_text)
        if not prompt_scan.is_valid and config.block_on_prompt_fail:
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
            return JSONResponse(content=upstream_body, status_code=status_code)

        output_text = extract_assistant_text(upstream_body)
        output_scan = guard.scan_output(output_text, prompt=safe_prompt)
        if not output_scan.is_valid and config.block_on_output_fail:
            return _blocked_response("output", output_scan, status_code=502)

        safe_output = output_scan.sanitized_output or output_text
        if config.sanitize and safe_output != output_text:
            upstream_body = replace_assistant_text(upstream_body, safe_output)

        return JSONResponse(content=upstream_body, status_code=status_code)

    return app


async def _handle_streaming_chat(
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    config: GatewayConfig,
    guard: SentinelGuard,
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
            return JSONResponse(content=upstream_body, status_code=status_code)
        return _streaming_response(upstream_body)

    messages = payload["messages"]
    prompt_text = extract_last_user_text(messages)
    prompt_scan = guard.scan_prompt(prompt_text)
    if not prompt_scan.is_valid and config.block_on_prompt_fail:
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
        return JSONResponse(content=upstream_body, status_code=status_code)

    output_text = extract_assistant_text(upstream_body)
    output_scan = guard.scan_output(output_text, prompt=safe_prompt)
    if not output_scan.is_valid and config.block_on_output_fail:
        return _blocked_response("output", output_scan, status_code=502)

    safe_output = output_scan.sanitized_output or output_text
    if config.sanitize and safe_output != output_text:
        upstream_body = replace_assistant_text(upstream_body, safe_output)

    return _streaming_response(upstream_body)


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
