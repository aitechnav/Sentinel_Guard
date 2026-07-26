"""OpenAI-compatible SentinelGuard LLM gateway."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Mapping, Optional

from sentinelguard.audit import AuditContext, build_audit_context, log_scan_detections
from sentinelguard.core.config import GuardConfig
from sentinelguard.core.guard import SentinelGuard
from sentinelguard.core.scanner import AggregatedResult
from sentinelguard.gateway.config import GatewayConfig
from sentinelguard.gateway.operations import (
    GatewayClient,
    authenticate_gateway_request,
    check_gateway_access,
    extract_chat_usage,
    gateway_response_cache,
    gateway_usage_store,
    provider_for_result,
    virtual_key_summary,
)
from sentinelguard.gateway.observability import emit_gateway_event
from sentinelguard.gateway.providers import (
    available_gateway_models,
    configured_providers,
    effective_api_key_env,
    effective_provider,
    effective_upstream_url,
    extract_assistant_text,
    extract_last_user_text,
    forward_chat_completion_with_failover,
    iter_openai_stream_events,
    replace_assistant_text,
    replace_last_user_text,
)
from sentinelguard.gateway.policy import (
    PolicyDecision,
    evaluate_output_policy,
    evaluate_prompt_policy,
)
from sentinelguard.models import model_status
from sentinelguard.monitoring import (
    metrics_content_type,
    prometheus_available,
    record_gateway_request,
    record_provider_attempts,
    record_scan,
    render_metrics,
)

logger = logging.getLogger(__name__)

GATEWAY_API_VERSION = "v1"
GATEWAY_API_STABILITY = "stable"

try:
    from fastapi import FastAPI, HTTPException, Request, WebSocket
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
    usage_store = gateway_usage_store(config)
    response_cache = gateway_response_cache(config)

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

    @app.get("/health")
    @app.get("/gateway/health")
    @app.get("/gateway/v1/health")
    async def health():
        return _health_payload(config, guard)

    @app.get("/routes")
    @app.get("/gateway/v1/routes")
    async def routes():
        return _routes_payload(config)

    @app.get("/models")
    @app.get("/v1/models")
    @app.get("/gateway/v1/models")
    async def models():
        return _models_payload(config)

    @app.get("/gateway/usage")
    @app.get("/gateway/v1/usage")
    async def usage(request: Request):
        auth = authenticate_gateway_request(request.headers, config)
        if not auth.allowed or auth.client is None:
            return _gateway_error_response(auth.status_code, auth.error_type, auth.message)
        return _usage_payload(auth.client, usage_store)

    @app.get("/gateway/provider-health")
    @app.get("/gateway/v1/provider-health")
    async def provider_health():
        return _provider_health_payload(config)

    @app.get("/gateway/v1")
    @app.get("/gateway/v1/contract")
    async def gateway_contract():
        return _gateway_contract_payload(config)

    if config.admin_ui_enabled:

        @app.get("/admin")
        async def admin():
            return Response(content=_admin_html(), media_type="text/html")

    @app.api_route(
        "/mcp/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    async def mcp_passthrough(request: Request, path: str):
        return await _passthrough_gateway_request(
            request,
            path,
            config,
            guard,
            enabled=config.mcp_gateway_enabled,
            upstream_url=config.mcp_upstream_url,
            gateway_name="mcp",
        )

    @app.api_route(
        "/a2a/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    async def a2a_passthrough(request: Request, path: str):
        return await _passthrough_gateway_request(
            request,
            path,
            config,
            guard,
            enabled=config.a2a_gateway_enabled,
            upstream_url=config.a2a_upstream_url,
            gateway_name="a2a",
        )

    @app.websocket("/v1/realtime")
    @app.websocket("/realtime")
    async def realtime_websocket(websocket: WebSocket):
        await _realtime_websocket_proxy(websocket, config)

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
        auth = authenticate_gateway_request(request.headers, config)
        if not auth.allowed or auth.client is None:
            return _gateway_error_response(auth.status_code, auth.error_type, auth.message)

        payload = await request.json()
        _validate_payload(payload)
        access = check_gateway_access(auth.client, payload, usage_store)
        if not access.allowed:
            return _gateway_error_response(access.status_code, access.error_type, access.message)
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
                auth.client,
            )

        if not config.enabled:
            forwarded = await forward_chat_completion_with_failover(
                payload,
                request.headers,
                config,
            )
            record_provider_attempts(forwarded.attempts)
            outcome = "pass_through" if forwarded.status_code < 400 else "upstream_error"
            if forwarded.status_code < 400:
                _record_gateway_usage(
                    auth.client,
                    payload,
                    forwarded.body,
                    config,
                    forwarded.provider_name,
                    False,
                )
            record_gateway_request(forwarded.provider, False, outcome)
            return JSONResponse(
                content=forwarded.body,
                status_code=forwarded.status_code,
            )

        messages = payload["messages"]
        prompt_text = extract_last_user_text(messages)
        prompt_scan = guard.scan_prompt(prompt_text)
        record_scan("prompt", prompt_scan)
        prompt_decision = evaluate_prompt_policy(prompt_text, prompt_scan, config)
        _audit_scan(config, audit_context, False, "prompt", prompt_scan, provider="unselected")
        if not prompt_decision.allowed:
            record_gateway_request("none", False, "blocked_prompt")
            return _blocked_response(
                "prompt",
                prompt_scan,
                status_code=400,
                decision=prompt_decision,
            )

        safe_prompt = prompt_decision.sanitized_text or prompt_text
        upstream_payload = dict(payload)
        if config.sanitize and safe_prompt != prompt_text:
            upstream_payload["messages"] = replace_last_user_text(messages, safe_prompt)

        cached_body = response_cache.get(upstream_payload, config)
        if cached_body is not None:
            output_text = extract_assistant_text(cached_body)
            output_scan = guard.scan_output(output_text, prompt=safe_prompt)
            record_scan("output", output_scan)
            output_decision = evaluate_output_policy(output_text, output_scan, config)
            _audit_scan(config, audit_context, False, "output", output_scan, provider="cache")
            if not output_decision.allowed:
                record_gateway_request("cache", False, "blocked_output")
                return _blocked_response(
                    "output",
                    output_scan,
                    status_code=502,
                    decision=output_decision,
                )

            cached_safe_body = cached_body
            safe_output = output_decision.sanitized_text or output_text
            if config.sanitize and safe_output != output_text:
                cached_safe_body = replace_assistant_text(cached_safe_body, safe_output)
            _record_gateway_usage(auth.client, upstream_payload, cached_safe_body, config, "cache", True)
            record_gateway_request("cache", False, "cache_hit")
            return JSONResponse(content=cached_safe_body, status_code=200)

        forwarded = await forward_chat_completion_with_failover(
            upstream_payload,
            request.headers,
            config,
            route_constraint=prompt_decision.route_constraint,
        )
        record_provider_attempts(forwarded.attempts)
        if forwarded.status_code >= 400:
            record_gateway_request(forwarded.provider, False, "upstream_error")
            return JSONResponse(
                content=forwarded.body,
                status_code=forwarded.status_code,
            )

        output_text = extract_assistant_text(forwarded.body)
        output_scan = guard.scan_output(output_text, prompt=safe_prompt)
        record_scan("output", output_scan)
        output_decision = evaluate_output_policy(output_text, output_scan, config)
        _audit_scan(
            config, audit_context, False, "output", output_scan, provider=forwarded.provider
        )
        if not output_decision.allowed:
            record_gateway_request(forwarded.provider, False, "blocked_output")
            return _blocked_response(
                "output",
                output_scan,
                status_code=502,
                decision=output_decision,
            )

        upstream_body = forwarded.body
        safe_output = output_decision.sanitized_text or output_text
        if config.sanitize and safe_output != output_text:
            upstream_body = replace_assistant_text(upstream_body, safe_output)

        response_cache.set(upstream_payload, upstream_body, config)
        _record_gateway_usage(
            auth.client,
            upstream_payload,
            upstream_body,
            config,
            forwarded.provider_name,
            False,
        )
        record_gateway_request(forwarded.provider, False, "passed")
        return JSONResponse(content=upstream_body, status_code=forwarded.status_code)

    return app


async def _handle_streaming_chat(
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    config: GatewayConfig,
    guard: SentinelGuard,
    audit_context: AuditContext,
    client: GatewayClient,
) -> Any:
    if config.streaming_mode != "buffered":
        raise HTTPException(
            status_code=400,
            detail=("Unsupported gateway streaming_mode. " "Use streaming_mode: buffered."),
        )

    upstream_payload = dict(payload)
    upstream_payload["stream"] = False

    if not config.enabled:
        forwarded = await forward_chat_completion_with_failover(
            upstream_payload,
            headers,
            config,
        )
        record_provider_attempts(forwarded.attempts)
        if forwarded.status_code >= 400:
            record_gateway_request(forwarded.provider, True, "upstream_error")
            return JSONResponse(
                content=forwarded.body,
                status_code=forwarded.status_code,
            )
        _record_gateway_usage(
            client,
            upstream_payload,
            forwarded.body,
            config,
            forwarded.provider_name,
            False,
        )
        record_gateway_request(forwarded.provider, True, "pass_through")
        return _streaming_response(forwarded.body)

    messages = payload["messages"]
    prompt_text = extract_last_user_text(messages)
    prompt_scan = guard.scan_prompt(prompt_text)
    record_scan("prompt", prompt_scan)
    prompt_decision = evaluate_prompt_policy(prompt_text, prompt_scan, config)
    _audit_scan(config, audit_context, True, "prompt", prompt_scan, provider="unselected")
    if not prompt_decision.allowed:
        record_gateway_request("none", True, "blocked_prompt")
        return _blocked_response(
            "prompt",
            prompt_scan,
            status_code=400,
            decision=prompt_decision,
        )

    safe_prompt = prompt_decision.sanitized_text or prompt_text
    if config.sanitize and safe_prompt != prompt_text:
        upstream_payload["messages"] = replace_last_user_text(messages, safe_prompt)

    forwarded = await forward_chat_completion_with_failover(
        upstream_payload,
        headers,
        config,
        route_constraint=prompt_decision.route_constraint,
    )
    record_provider_attempts(forwarded.attempts)
    if forwarded.status_code >= 400:
        record_gateway_request(forwarded.provider, True, "upstream_error")
        return JSONResponse(
            content=forwarded.body,
            status_code=forwarded.status_code,
        )

    output_text = extract_assistant_text(forwarded.body)
    output_scan = guard.scan_output(output_text, prompt=safe_prompt)
    record_scan("output", output_scan)
    output_decision = evaluate_output_policy(output_text, output_scan, config)
    _audit_scan(config, audit_context, True, "output", output_scan, provider=forwarded.provider)
    if not output_decision.allowed:
        record_gateway_request(forwarded.provider, True, "blocked_output")
        return _blocked_response(
            "output",
            output_scan,
            status_code=502,
            decision=output_decision,
        )

    upstream_body = forwarded.body
    safe_output = output_decision.sanitized_text or output_text
    if config.sanitize and safe_output != output_text:
        upstream_body = replace_assistant_text(upstream_body, safe_output)

    _record_gateway_usage(
        client,
        upstream_payload,
        upstream_body,
        config,
        forwarded.provider_name,
        False,
    )
    record_gateway_request(forwarded.provider, True, "passed")
    return _streaming_response(upstream_body)


async def _passthrough_gateway_request(
    request: Request,
    path: str,
    config: GatewayConfig,
    guard: SentinelGuard,
    *,
    enabled: bool,
    upstream_url: Optional[str],
    gateway_name: str,
) -> Response:
    auth = authenticate_gateway_request(request.headers, config)
    if not auth.allowed or auth.client is None:
        return _gateway_error_response(auth.status_code, auth.error_type, auth.message)
    if not enabled or not upstream_url:
        return _gateway_error_response(
            501,
            f"sentinelguard_{gateway_name}_gateway_not_configured",
            f"SentinelGuard {gateway_name.upper()} gateway is not configured",
        )

    body = await request.body()
    text = _extract_passthrough_text(body)
    if config.enabled and text:
        scan = guard.scan_prompt(text)
        record_scan(gateway_name, scan)
        decision = evaluate_prompt_policy(text, scan, config)
        if not decision.allowed:
            record_gateway_request(gateway_name, False, "blocked_prompt")
            return _blocked_response(gateway_name, scan, status_code=400, decision=decision)

    httpx = _load_httpx()
    target_url = _join_upstream_url(upstream_url, path)
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    headers = _passthrough_headers(request.headers)
    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        response = await client.request(
            request.method,
            target_url,
            content=body,
            headers=headers,
        )
    record_gateway_request(gateway_name, False, "passed" if response.status_code < 400 else "upstream_error")
    return Response(
        content=response.content,
        status_code=response.status_code,
        media_type=response.headers.get("content-type"),
    )


async def _realtime_websocket_proxy(websocket: WebSocket, config: GatewayConfig) -> None:
    auth = authenticate_gateway_request(websocket.headers, config)
    if not auth.allowed:
        await websocket.close(code=1008)
        return
    if not config.realtime_gateway_enabled or not config.realtime_upstream_url:
        await websocket.close(code=1011)
        return

    try:
        import websockets
    except ImportError:
        await websocket.close(code=1011)
        return

    await websocket.accept()
    upstream_url = config.realtime_upstream_url
    if websocket.url.query:
        upstream_url = f"{upstream_url}?{websocket.url.query}"

    passthrough_headers = _websocket_passthrough_headers(websocket.headers)
    try:
        upstream_context = websockets.connect(
            upstream_url,
            additional_headers=passthrough_headers,
        )
    except TypeError:
        upstream_context = websockets.connect(
            upstream_url,
            extra_headers=passthrough_headers,
        )

    async with upstream_context as upstream:
        await asyncio.gather(
            _websocket_client_to_upstream(websocket, upstream),
            _websocket_upstream_to_client(websocket, upstream),
        )


async def _websocket_client_to_upstream(websocket: WebSocket, upstream: Any) -> None:
    while True:
        message = await websocket.receive()
        if message.get("type") == "websocket.disconnect":
            await upstream.close()
            return
        if message.get("text") is not None:
            await upstream.send(message["text"])
        elif message.get("bytes") is not None:
            await upstream.send(message["bytes"])


async def _websocket_upstream_to_client(websocket: WebSocket, upstream: Any) -> None:
    async for message in upstream:
        if isinstance(message, bytes):
            await websocket.send_bytes(message)
        else:
            await websocket.send_text(str(message))


def _record_gateway_usage(
    client: GatewayClient,
    payload: Mapping[str, Any],
    response_body: Mapping[str, Any],
    config: GatewayConfig,
    provider_name: str,
    cache_hit: bool,
) -> None:
    provider = provider_for_result(config, provider_name)
    usage = extract_chat_usage(payload, response_body, provider)
    gateway_usage_store(config).record(
        client,
        model=str(payload.get("model") or ""),
        provider=provider_name,
        usage=usage,
        cache_hit=cache_hit,
    )
    emit_gateway_event(
        config,
        "sentinelguard.gateway.usage",
        {
            "client": client.name,
            "tenant_id": client.tenant_id or "",
            "team_id": client.team_id or "",
            "model": str(payload.get("model") or ""),
            "provider": provider_name,
            "cache_hit": cache_hit,
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
            "cost": usage.cost,
        },
    )


def _health_payload(config: GatewayConfig, guard: SentinelGuard) -> dict[str, Any]:
    return {
        "object": "sentinelguard.gateway.health",
        "api_version": GATEWAY_API_VERSION,
        "stability": GATEWAY_API_STABILITY,
        "status": "healthy",
        "enabled": config.enabled,
        "provider": effective_provider(config),
        "upstream_url": effective_upstream_url(config),
        "api_key_env": effective_api_key_env(config),
        "provider_pool": [
            {
                "name": provider.name,
                "provider": provider.provider,
                "private": provider.private,
                "priority": provider.priority,
                "weight": provider.weight,
            }
            for provider in configured_providers(config)
        ],
        "fallback_enabled": config.fallback_enabled,
        "route_pii_to_private_provider": config.route_pii_to_private_provider,
        "redact_pii": config.redact_pii,
        "redact_output_pii": config.redact_output_pii,
        "streaming_mode": config.streaming_mode,
        "state_backend": config.state_backend,
        "cache_backend": config.cache_backend,
        "cache_enabled": config.cache_enabled,
        "routing_strategy": config.routing_strategy,
        "health_check_enabled": config.health_check_enabled,
        "metrics_enabled": config.metrics_enabled,
        "audit_enabled": config.audit_enabled,
        "client_auth_enabled": bool(_client_api_key(config) or config.virtual_keys),
        "virtual_keys": virtual_key_summary(config),
        "prometheus_available": prometheus_available(),
        "model_status": model_status(),
        "prompt_scanners": guard.prompt_scanner_names,
        "output_scanners": guard.output_scanner_names,
    }


def _routes_payload(config: GatewayConfig) -> dict[str, Any]:
    endpoints = _gateway_endpoints(config)
    return {
        "object": "sentinelguard.gateway.routes",
        "api_version": GATEWAY_API_VERSION,
        "stability": GATEWAY_API_STABILITY,
        "gateway": "sentinelguard",
        "endpoints": endpoints["all"],
        "stable_management_endpoints": endpoints["stable_management"],
        "openai_compatible_endpoints": endpoints["openai_compatible"],
        "compatibility_endpoints": endpoints["compatibility"],
        "models": available_gateway_models(config),
        "providers": [
            {
                "name": provider.name,
                "provider": provider.provider,
                "model_name": provider.model_name,
                "upstream_model": provider.upstream_model,
                "private": provider.private,
                "priority": provider.priority,
                "weight": provider.weight,
                "enabled": provider.enabled,
            }
            for provider in configured_providers(config)
        ],
    }


def _models_payload(config: GatewayConfig) -> dict[str, Any]:
    return {
        "object": "list",
        "api_version": GATEWAY_API_VERSION,
        "data": available_gateway_models(config),
    }


def _usage_payload(client: GatewayClient, usage_store: Any) -> dict[str, Any]:
    return {
        "object": "sentinelguard.gateway.usage",
        "api_version": GATEWAY_API_VERSION,
        "client": {
            "name": client.name,
            "tenant_id": client.tenant_id,
            "team_id": client.team_id,
            "user_id": client.user_id,
        },
        "usage": usage_store.snapshot(
            client.key_id,
            client.budget_reset,
        ).to_dict(),
    }


def _provider_health_payload(config: GatewayConfig) -> dict[str, Any]:
    from sentinelguard.gateway.providers import provider_health_snapshot

    return {
        "object": "sentinelguard.gateway.provider_health",
        "api_version": GATEWAY_API_VERSION,
        "providers": provider_health_snapshot(config),
    }


def _gateway_contract_payload(config: GatewayConfig) -> dict[str, Any]:
    endpoints = _gateway_endpoints(config)
    return {
        "object": "sentinelguard.gateway.contract",
        "gateway": "sentinelguard",
        "api_version": GATEWAY_API_VERSION,
        "stability": GATEWAY_API_STABILITY,
        "base_path": "/gateway/v1",
        "openai_base_path": "/v1",
        "stable_management_endpoints": {
            "health": "/gateway/v1/health",
            "routes": "/gateway/v1/routes",
            "models": "/gateway/v1/models",
            "usage": "/gateway/v1/usage",
            "provider_health": "/gateway/v1/provider-health",
            "contract": "/gateway/v1/contract",
        },
        "openai_compatible_endpoints": endpoints["openai_compatible"],
        "compatibility_endpoints": endpoints["compatibility"],
        "auth": {
            "client_auth_enabled": bool(_client_api_key(config) or config.virtual_keys),
            "headers": ["Authorization: Bearer <token>", "X-API-Key", "X-SentinelGuard-API-Key"],
            "usage_requires_auth": True,
        },
        "streaming": {
            "supported": True,
            "mode": config.streaming_mode,
            "safe_default": "buffered",
        },
    }


def _gateway_endpoints(config: GatewayConfig) -> dict[str, list[str]]:
    openai_compatible = ["/v1/chat/completions", "/v1/models"]
    stable_management = [
        "/gateway/v1",
        "/gateway/v1/contract",
        "/gateway/v1/health",
        "/gateway/v1/routes",
        "/gateway/v1/models",
        "/gateway/v1/usage",
        "/gateway/v1/provider-health",
    ]
    compatibility = [
        "/models",
        "/routes",
        "/health",
        "/gateway/health",
        "/gateway/usage",
        "/gateway/provider-health",
    ]
    optional = []
    if config.admin_ui_enabled:
        optional.append("/admin")
    if config.mcp_gateway_enabled:
        optional.append("/mcp/{path}")
    if config.a2a_gateway_enabled:
        optional.append("/a2a/{path}")
    if config.realtime_gateway_enabled:
        optional.extend(["/v1/realtime", "/realtime"])
    if config.metrics_enabled:
        optional.append("/metrics")

    return {
        "openai_compatible": openai_compatible,
        "stable_management": stable_management,
        "compatibility": compatibility,
        "optional": optional,
        "all": openai_compatible + stable_management + compatibility + optional,
    }


def _admin_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelGuard Gateway</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #17202a; }
    main { max-width: 920px; margin: 0 auto; }
    h1 { font-size: 28px; margin-bottom: 8px; }
    p { color: #4b5563; }
    section { border: 1px solid #d6dde6; border-radius: 8px; padding: 18px; margin-top: 18px; }
    a { color: #0f5db8; text-decoration: none; font-weight: 600; }
    code { background: #eef2f7; padding: 2px 6px; border-radius: 4px; }
    ul { line-height: 1.8; }
  </style>
</head>
<body>
  <main>
    <h1>SentinelGuard Gateway</h1>
    <p>Security enforcement, model routing, usage tracking, and operational checks.</p>
    <section>
      <h2>Operations</h2>
      <ul>
        <li><a href="/gateway/v1/routes">Routes and providers</a></li>
        <li><a href="/gateway/v1/models">Models</a></li>
        <li><a href="/gateway/v1/provider-health">Provider health</a></li>
        <li><a href="/gateway/v1/health">Gateway health</a></li>
        <li><a href="/gateway/v1/contract">Stable API contract</a></li>
        <li><code>/gateway/v1/usage</code> requires your gateway API key.</li>
      </ul>
    </section>
  </main>
</body>
</html>"""


def _audit_scan(
    config: GatewayConfig,
    audit_context: AuditContext,
    streaming: bool,
    direction: str,
    result: AggregatedResult,
    provider: Optional[str] = None,
) -> None:
    if not config.audit_enabled:
        return
    log_scan_detections(
        audit_context,
        provider=provider or effective_provider(config),
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


def _extract_passthrough_text(body: bytes) -> str:
    if not body:
        return ""
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return ""
    values: list[str] = []
    _collect_text_values(payload, values)
    return "\n".join(values)[:20000]


def _collect_text_values(value: Any, values: list[str]) -> None:
    if isinstance(value, str):
        values.append(value)
        return
    if isinstance(value, list):
        for item in value:
            _collect_text_values(item, values)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"text", "content", "prompt", "message", "input", "query"}:
                _collect_text_values(item, values)
            elif isinstance(item, (dict, list)):
                _collect_text_values(item, values)


def _join_upstream_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _passthrough_headers(headers: Mapping[str, str]) -> dict[str, str]:
    blocked = {"host", "content-length"}
    return {key: value for key, value in headers.items() if key.lower() not in blocked}


def _websocket_passthrough_headers(headers: Mapping[str, str]) -> dict[str, str]:
    blocked = {
        "host",
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
    }
    return {key: value for key, value in headers.items() if key.lower() not in blocked}


def _load_httpx() -> Any:
    try:
        import httpx
    except ImportError as exc:
        raise ImportError(
            "httpx is required for gateway passthrough. "
            "Install with: pip install sentinelguard[gateway]"
        ) from exc
    return httpx


def _is_authorized(headers: Mapping[str, str], config: GatewayConfig) -> bool:
    return authenticate_gateway_request(headers, config).allowed


def _client_api_key(config: GatewayConfig) -> Optional[str]:
    if config.client_api_key:
        return config.client_api_key
    if config.client_api_key_env:
        return os.getenv(config.client_api_key_env)
    return None


def _unauthorized_response() -> JSONResponse:
    return _gateway_error_response(
        401,
        "sentinelguard_gateway_unauthorized",
        "SentinelGuard gateway authentication failed",
    )


def _gateway_error_response(status_code: int, error_type: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": message,
                "type": error_type,
            }
        },
    )


def _blocked_response(
    direction: str,
    result: AggregatedResult,
    status_code: int,
    decision: Optional[PolicyDecision] = None,
) -> JSONResponse:
    reason_codes = decision.reason_codes if decision else []
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": f"SentinelGuard blocked {direction}",
                "type": f"sentinelguard_{direction}_blocked",
                "failed_scanners": result.failed_scanners,
                "risk": result.highest_risk.value,
                "reason_codes": reason_codes,
            }
        },
    )
