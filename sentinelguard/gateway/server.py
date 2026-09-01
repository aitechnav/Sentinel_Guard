"""OpenAI-compatible SentinelGuard LLM gateway."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
import logging
import os
from typing import Any, Mapping, Optional

from sentinelguard.audit import AuditContext, build_audit_context, log_scan_detections
from sentinelguard.core.config import GuardConfig
from sentinelguard.core.guard import SentinelGuard
from sentinelguard.core.scanner import AggregatedResult
from sentinelguard.gateway.admin import (
    ADMIN_COOKIE_NAME,
    ADMIN_ROLE,
    AdminIdentity,
    GatewayAdminStore,
    gateway_admin_store,
)
from sentinelguard.gateway.config import GatewayConfig
from sentinelguard.gateway.guardrails import (
    apply_gateway_guardrails,
    guardrail_summary,
    remember_sensitive_session_if_needed,
    requested_guardrail_names,
    resolve_sensitive_session_key,
    sensitive_session_active,
    sensitive_route_store,
    unknown_requested_guardrails,
)
from sentinelguard.gateway.operations import (
    GatewayClient,
    authenticate_gateway_request,
    check_gateway_access,
    extract_chat_usage,
    gateway_response_cache,
    gateway_usage_store,
    hash_secret,
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
from sentinelguard.gateway.routing import (
    ComplexityRouteDecision,
    apply_complexity_route,
    resolve_complexity_route,
)
from sentinelguard.models import model_status
from sentinelguard.monitoring import (
    metrics_content_type,
    prometheus_available,
    record_gateway_request,
    record_provider_attempts,
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
    admin_store = gateway_admin_store(config) if config.admin_ui_enabled else None

    @asynccontextmanager
    async def lifespan(_: Any):
        if _gateway_uses_pii(guard, config):
            await asyncio.to_thread(_warm_presidio_for_gateway)
        await _warm_gateway_scanners(guard, config)
        yield

    app = FastAPI(
        title="SentinelGuard LLM Gateway",
        description="OpenAI-compatible LLM gateway with SentinelGuard scanning",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
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

    @app.post("/guardrails/apply")
    @app.post("/gateway/v1/guardrails/apply")
    async def guardrails_apply(request: Request):
        if not config.guardrails_apply_endpoint_enabled:
            return _gateway_error_response(
                501,
                "sentinelguard_guardrails_apply_not_enabled",
                "SentinelGuard guardrails apply endpoint is not enabled",
            )
        auth = authenticate_gateway_request(request.headers, config)
        if not auth.allowed or auth.client is None:
            return _gateway_error_response(auth.status_code, auth.error_type, auth.message)

        payload = await _json_body(request)
        text = _guardrail_input_text(payload)
        if not text:
            return _gateway_error_response(
                400,
                "sentinelguard_guardrails_apply_bad_request",
                "Guardrail apply requires input, text, prompt, output, or messages",
            )

        requested = requested_guardrail_names(request.headers, payload)
        unknown = unknown_requested_guardrails(config, requested)
        if unknown:
            return _unknown_guardrails_response(unknown)

        result = await apply_gateway_guardrails(
            guard,
            text,
            config,
            direction=_guardrail_direction(payload),
            stage=str(payload.get("stage") or "manual"),
            prompt=_payload_text(payload, "prompt"),
            requested_guardrails=requested,
        )
        return JSONResponse(content=result.to_dict(include_text=True), status_code=200)

    if config.admin_ui_enabled and admin_store is not None:

        @app.get("/admin")
        @app.get("/admin/login")
        async def admin():
            return Response(content=_admin_html(), media_type="text/html")

        @app.post("/admin/api/login")
        async def admin_login(request: Request):
            payload = await _json_body(request)
            identity = admin_store.verify_user(
                str(payload.get("username") or ""),
                str(payload.get("password") or ""),
            )
            if identity is None:
                return _gateway_error_response(
                    401,
                    "sentinelguard_admin_login_failed",
                    "Invalid SentinelGuard dashboard credentials",
                )
            session = admin_store.create_session(identity)
            response = JSONResponse(
                content={"authenticated": True, "user": _admin_identity_payload(identity)}
            )
            response.set_cookie(
                key=ADMIN_COOKIE_NAME,
                value=session,
                max_age=max(300, int(config.admin_session_ttl_seconds or 28800)),
                httponly=True,
                samesite="lax",
                path="/admin",
            )
            return response

        @app.post("/admin/api/logout")
        async def admin_logout(request: Request):
            admin_store.delete_session(_admin_session_token(request))
            response = JSONResponse(content={"ok": True})
            response.delete_cookie(ADMIN_COOKIE_NAME, path="/admin")
            return response

        @app.get("/admin/api/me")
        async def admin_me(request: Request):
            identity = _require_admin_user(request, admin_store, config)
            return {"authenticated": True, "user": _admin_identity_payload(identity)}

        @app.get("/admin/api/summary")
        async def admin_summary(request: Request):
            identity = _require_admin_user(request, admin_store, config)
            return _admin_summary_payload(config, admin_store, usage_store, identity)

        @app.get("/admin/api/clients")
        async def admin_clients(request: Request):
            _require_admin_user(request, admin_store, config)
            return {"clients": _dashboard_clients(config, admin_store, usage_store)}

        @app.post("/admin/api/clients")
        async def admin_create_client(request: Request):
            _require_admin_user(request, admin_store, config, required_role=ADMIN_ROLE)
            payload = await _json_body(request)
            try:
                client, token = admin_store.create_client(
                    name=str(payload.get("name") or ""),
                    tenant_id=_payload_text(payload, "tenant_id"),
                    team_id=_payload_text(payload, "team_id"),
                    user_id=_payload_text(payload, "user_id"),
                    allowed_models=_payload_allowed_models(payload.get("allowed_models")),
                    max_requests=_optional_int(payload.get("max_requests")),
                    max_tokens=_optional_int(payload.get("max_tokens")),
                    max_budget=_optional_float(payload.get("max_budget")),
                    budget_reset=_payload_text(payload, "budget_reset"),
                )
            except ValueError as exc:
                return _gateway_error_response(400, "sentinelguard_admin_bad_request", str(exc))
            return JSONResponse(
                status_code=201,
                content={
                    "client": _with_usage(client, usage_store),
                    "token": token,
                    "token_display": token,
                    "message": "Copy this token now. SentinelGuard stores only its hash.",
                },
            )

        @app.patch("/admin/api/clients/{client_id}")
        async def admin_update_client(client_id: str, request: Request):
            _require_admin_user(request, admin_store, config, required_role=ADMIN_ROLE)
            if not client_id.startswith("sgc_"):
                return _gateway_error_response(
                    400,
                    "sentinelguard_config_managed_client",
                    "Config-managed gateway keys cannot be changed from the dashboard",
                )
            payload = await _json_body(request)
            try:
                client = admin_store.update_client(
                    client_id,
                    enabled=_optional_bool(payload.get("enabled")),
                    tenant_id=_payload_update_text(payload, "tenant_id"),
                    team_id=_payload_update_text(payload, "team_id"),
                    user_id=_payload_update_text(payload, "user_id"),
                    allowed_models=(
                        _payload_allowed_models(payload.get("allowed_models"))
                        if "allowed_models" in payload
                        else None
                    ),
                    max_requests=_optional_int(payload.get("max_requests")),
                    max_tokens=_optional_int(payload.get("max_tokens")),
                    max_budget=_optional_float(payload.get("max_budget")),
                    budget_reset=_payload_update_text(payload, "budget_reset"),
                )
            except KeyError:
                return _gateway_error_response(
                    404,
                    "sentinelguard_gateway_client_not_found",
                    "Gateway client not found",
                )
            return {"client": _with_usage(client, usage_store)}

        @app.post("/admin/api/clients/{client_id}/rotate")
        async def admin_rotate_client(client_id: str, request: Request):
            _require_admin_user(request, admin_store, config, required_role=ADMIN_ROLE)
            if not client_id.startswith("sgc_"):
                return _gateway_error_response(
                    400,
                    "sentinelguard_config_managed_client",
                    "Config-managed gateway keys cannot be rotated from the dashboard",
                )
            try:
                client, token = admin_store.rotate_client(client_id)
            except KeyError:
                return _gateway_error_response(
                    404,
                    "sentinelguard_gateway_client_not_found",
                    "Gateway client not found",
                )
            return {
                "client": _with_usage(client, usage_store),
                "token": token,
                "token_display": token,
                "message": "Copy this token now. The previous token no longer works.",
            }

        @app.get("/admin/api/clients/{client_id}/usage")
        async def admin_client_usage(client_id: str, request: Request):
            _require_admin_user(request, admin_store, config)
            return _client_usage_payload(client_id, config, admin_store, usage_store)

        @app.post("/gateway/v1/client/token/rotate")
        async def rotate_current_client_token(request: Request):
            auth = authenticate_gateway_request(request.headers, config)
            if not auth.allowed or auth.client is None:
                return _gateway_error_response(auth.status_code, auth.error_type, auth.message)
            if not auth.client.key_id.startswith("sgc_"):
                return _gateway_error_response(
                    400,
                    "sentinelguard_config_managed_client",
                    "Only dashboard-managed gateway clients can rotate their own token",
                )
            try:
                client, token = admin_store.rotate_client(auth.client.key_id)
            except KeyError:
                return _gateway_error_response(
                    404,
                    "sentinelguard_gateway_client_not_found",
                    "Gateway client not found",
                )
            return {
                "client": _with_usage(client, usage_store),
                "token": token,
                "message": "Copy this token now. The previous token no longer works.",
            }

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
        audit_context = build_audit_context(
            request.headers,
            payload,
            salt_env=config.audit_hash_salt_env,
        )
        requested_guardrails = requested_guardrail_names(request.headers, payload)
        unknown_guardrails = unknown_requested_guardrails(config, requested_guardrails)
        if unknown_guardrails:
            return _unknown_guardrails_response(unknown_guardrails)

        if payload.get("stream"):
            return await _handle_streaming_chat(
                payload,
                request.headers,
                config,
                guard,
                audit_context,
                auth.client,
                usage_store,
                requested_guardrails,
            )

        if not config.enabled:
            access = check_gateway_access(auth.client, payload, usage_store)
            if not access.allowed:
                return _gateway_error_response(
                    access.status_code, access.error_type, access.message
                )
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
        session_key = resolve_sensitive_session_key(request.headers, auth.client, payload, config)
        sticky_sensitive_route = sensitive_session_active(config, session_key)
        prompt_guardrail = await apply_gateway_guardrails(
            guard,
            prompt_text,
            config,
            direction="prompt",
            stage="pre_call",
            requested_guardrails=requested_guardrails,
            streaming=False,
        )
        prompt_scan = prompt_guardrail.scan
        prompt_decision = prompt_guardrail.decision
        sticky_sensitive_route = (
            (
                prompt_guardrail.has_enforced_guardrail
                and remember_sensitive_session_if_needed(config, session_key, prompt_scan, prompt_decision)
            )
            or sticky_sensitive_route
        )
        route_constraint = _prompt_route_constraint(
            config,
            prompt_decision,
            sticky_sensitive_route=sticky_sensitive_route,
        )
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
        upstream_payload, routing_decision = _route_upstream_payload(
            upstream_payload,
            safe_prompt,
            prompt_decision,
            config,
            route_constraint=route_constraint,
        )
        _emit_routing_decision(config, routing_decision, streaming=False)

        access = check_gateway_access(auth.client, upstream_payload, usage_store)
        if not access.allowed:
            return _gateway_error_response(access.status_code, access.error_type, access.message)

        cached_body = response_cache.get(upstream_payload, config)
        if cached_body is not None:
            output_text = extract_assistant_text(cached_body)
            output_guardrail = await apply_gateway_guardrails(
                guard,
                output_text,
                config,
                direction="output",
                stage="post_call",
                prompt=safe_prompt,
                requested_guardrails=requested_guardrails,
                streaming=False,
            )
            output_scan = output_guardrail.scan
            output_decision = output_guardrail.decision
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
            route_constraint=route_constraint,
        )
        record_provider_attempts(forwarded.attempts)
        if forwarded.status_code >= 400:
            record_gateway_request(forwarded.provider, False, "upstream_error")
            return JSONResponse(
                content=forwarded.body,
                status_code=forwarded.status_code,
            )

        output_text = extract_assistant_text(forwarded.body)
        output_guardrail = await apply_gateway_guardrails(
            guard,
            output_text,
            config,
            direction="output",
            stage="post_call",
            prompt=safe_prompt,
            requested_guardrails=requested_guardrails,
            streaming=False,
        )
        output_scan = output_guardrail.scan
        output_decision = output_guardrail.decision
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
    usage_store: Any,
    requested_guardrails: tuple[str, ...] = (),
) -> Any:
    if config.streaming_mode != "buffered":
        raise HTTPException(
            status_code=400,
            detail=("Unsupported gateway streaming_mode. " "Use streaming_mode: buffered."),
        )

    upstream_payload = dict(payload)
    upstream_payload["stream"] = False

    if not config.enabled:
        access = check_gateway_access(client, upstream_payload, usage_store)
        if not access.allowed:
            return _gateway_error_response(access.status_code, access.error_type, access.message)
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
    session_key = resolve_sensitive_session_key(headers, client, payload, config)
    sticky_sensitive_route = sensitive_session_active(config, session_key)
    prompt_guardrail = await apply_gateway_guardrails(
        guard,
        prompt_text,
        config,
        direction="prompt",
        stage="pre_call",
        requested_guardrails=requested_guardrails,
        streaming=True,
    )
    prompt_scan = prompt_guardrail.scan
    prompt_decision = prompt_guardrail.decision
    sticky_sensitive_route = (
        remember_sensitive_session_if_needed(config, session_key, prompt_scan, prompt_decision)
        or sticky_sensitive_route
    )
    route_constraint = _prompt_route_constraint(
        config,
        prompt_decision,
        sticky_sensitive_route=sticky_sensitive_route,
    )
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
    upstream_payload, routing_decision = _route_upstream_payload(
        upstream_payload,
        safe_prompt,
        prompt_decision,
        config,
        route_constraint=route_constraint,
    )
    _emit_routing_decision(config, routing_decision, streaming=True)

    access = check_gateway_access(client, upstream_payload, usage_store)
    if not access.allowed:
        return _gateway_error_response(access.status_code, access.error_type, access.message)

    forwarded = await forward_chat_completion_with_failover(
        upstream_payload,
        headers,
        config,
        route_constraint=route_constraint,
    )
    record_provider_attempts(forwarded.attempts)
    if forwarded.status_code >= 400:
        record_gateway_request(forwarded.provider, True, "upstream_error")
        return JSONResponse(
            content=forwarded.body,
            status_code=forwarded.status_code,
        )

    output_text = extract_assistant_text(forwarded.body)
    output_guardrail = await apply_gateway_guardrails(
        guard,
        output_text,
        config,
        direction="output",
        stage="post_call",
        prompt=safe_prompt,
        requested_guardrails=requested_guardrails,
        streaming=True,
    )
    output_scan = output_guardrail.scan
    output_decision = output_guardrail.decision
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
        requested = requested_guardrail_names(request.headers, {})
        unknown = unknown_requested_guardrails(config, requested)
        if unknown:
            return _unknown_guardrails_response(unknown)
        guardrail_result = await apply_gateway_guardrails(
            guard,
            text,
            config,
            direction="prompt",
            stage="passthrough",
            requested_guardrails=requested,
            metric_direction=gateway_name,
        )
        scan = guardrail_result.scan
        decision = guardrail_result.decision
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


def _prompt_route_constraint(
    config: GatewayConfig,
    prompt_decision: PolicyDecision,
    *,
    sticky_sensitive_route: bool,
) -> str:
    if config.sensitive_session_routing_enabled and sticky_sensitive_route:
        return "private"
    return prompt_decision.route_constraint


def _route_upstream_payload(
    payload: Mapping[str, Any],
    prompt_text: str,
    prompt_decision: PolicyDecision,
    config: GatewayConfig,
    *,
    route_constraint: Optional[str] = None,
) -> tuple[dict[str, Any], ComplexityRouteDecision]:
    routing_decision = resolve_complexity_route(
        payload,
        prompt_text,
        config,
        route_constraint=route_constraint or prompt_decision.route_constraint,
        highest_risk=prompt_decision.highest_risk,
    )
    return apply_complexity_route(payload, routing_decision), routing_decision


def _emit_routing_decision(
    config: GatewayConfig,
    decision: ComplexityRouteDecision,
    *,
    streaming: bool,
) -> None:
    if not config.complexity_router.enabled:
        return
    emit_gateway_event(
        config,
        "sentinelguard.gateway.routing",
        {
            "from_model": decision.original_model,
            "to_model": decision.model or "",
            "route_type": decision.route_type,
            "applied": decision.applied,
            "score": round(decision.score, 3),
            "reasons": list(decision.reasons),
            "streaming": streaming,
        },
    )


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
        "route_sensitive_to_private_provider": config.route_sensitive_to_private_provider,
        "sensitive_session_routing": {
            "enabled": config.sensitive_session_routing_enabled,
            "ttl_seconds": config.sensitive_session_ttl_seconds,
            "active_sessions": len(sensitive_route_store().snapshot()),
        },
        "guardrails": guardrail_summary(config),
        "guardrails_apply_endpoint_enabled": config.guardrails_apply_endpoint_enabled,
        "redact_pii": config.redact_pii,
        "redact_output_pii": config.redact_output_pii,
        "streaming_mode": config.streaming_mode,
        "state_backend": config.state_backend,
        "cache_backend": config.cache_backend,
        "cache_enabled": config.cache_enabled,
        "routing_strategy": config.routing_strategy,
        "complexity_router": config.complexity_router.to_dict(),
        "health_check_enabled": config.health_check_enabled,
        "metrics_enabled": config.metrics_enabled,
        "audit_enabled": config.audit_enabled,
        "client_auth_enabled": _client_auth_enabled(config),
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
        "routing_strategy": config.routing_strategy,
        "complexity_router": config.complexity_router.to_dict(),
        "guardrails": guardrail_summary(config),
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
            "guardrails_apply": "/gateway/v1/guardrails/apply",
            "client_token_rotate": "/gateway/v1/client/token/rotate",
        },
        "openai_compatible_endpoints": endpoints["openai_compatible"],
        "compatibility_endpoints": endpoints["compatibility"],
        "auth": {
            "client_auth_enabled": _client_auth_enabled(config),
            "headers": ["Authorization: Bearer <token>", "X-API-Key", "X-SentinelGuard-API-Key"],
            "usage_requires_auth": True,
        },
        "streaming": {
            "supported": True,
            "mode": config.streaming_mode,
            "safe_default": "buffered",
        },
        "routing": {
            "provider_strategy": config.routing_strategy,
            "complexity_router": config.complexity_router.to_dict(),
            "sensitive_session_routing": {
                "enabled": config.sensitive_session_routing_enabled,
                "ttl_seconds": config.sensitive_session_ttl_seconds,
            },
        },
        "guardrails": {
            "apply_endpoint": "/gateway/v1/guardrails/apply",
            "configured": guardrail_summary(config),
            "request_header": "X-SentinelGuard-Guardrails",
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
        "/gateway/v1/guardrails/apply",
        "/gateway/v1/client/token/rotate",
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
    if config.guardrails_apply_endpoint_enabled:
        compatibility.append("/guardrails/apply")
    if config.admin_ui_enabled:
        optional.extend(["/admin", "/admin/api/*"])
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
  <title>SentinelGuard Gateway Admin</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --line: #d8e0ea;
      --text: #17202a;
      --muted: #5d6b7c;
      --accent: #145ca8;
      --accent-dark: #0e457e;
      --danger: #b42318;
      --ok: #067647;
      --warn: #b54708;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      min-height: 64px;
      padding: 14px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    main { width: min(1180px, calc(100vw - 32px)); margin: 24px auto 40px; }
    h1 { font-size: 22px; margin: 0; }
    h2 { font-size: 16px; margin: 0 0 12px; }
    p { color: var(--muted); margin: 6px 0 0; }
    button, input, select {
      font: inherit;
    }
    button {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 12px;
      background: var(--panel);
      color: var(--text);
      cursor: pointer;
    }
    button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    button.primary:hover { background: var(--accent-dark); }
    button.danger { color: var(--danger); border-color: #f2b8b5; }
    button:disabled { cursor: not-allowed; opacity: .55; }
    input, select {
      width: 100%;
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      background: #fff;
      color: var(--text);
    }
    label { display: grid; gap: 5px; color: var(--muted); font-size: 13px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: top; }
    th { color: var(--muted); font-weight: 700; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }
    .stack { display: grid; gap: 16px; }
    .topbar { display: flex; gap: 10px; align-items: center; }
    .grid { display: grid; gap: 16px; }
    .grid.stats { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .grid.two { grid-template-columns: minmax(280px, 380px) 1fr; align-items: start; }
    .field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .stat strong { display: block; font-size: 24px; line-height: 1.2; }
    .muted { color: var(--muted); }
    .pill { display: inline-flex; align-items: center; border: 1px solid var(--line); border-radius: 999px; padding: 3px 8px; font-size: 12px; color: var(--muted); }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    .danger-text { color: var(--danger); }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .hidden { display: none !important; }
    .token-box {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      margin-top: 12px;
      border: 1px solid #abd3ff;
      border-radius: 8px;
      padding: 12px;
      background: #f0f7ff;
    }
    .token-box code { overflow-wrap: anywhere; font-size: 13px; }
    .notice { border-left: 4px solid var(--warn); padding: 10px 12px; background: #fff8ed; color: #663c00; border-radius: 6px; }
    .login { max-width: 420px; margin: 80px auto; }
    .login .panel { padding: 24px; }
    .error { color: var(--danger); min-height: 20px; }
    @media (max-width: 860px) {
      header { align-items: flex-start; flex-direction: column; }
      .grid.stats, .grid.two, .field-grid { grid-template-columns: 1fr; }
      main { width: min(100vw - 20px, 1180px); }
    }
  </style>
</head>
<body>
  <section id="loginView" class="login hidden">
    <div class="panel stack">
      <div>
        <h1>SentinelGuard Gateway</h1>
        <p>Sign in to manage clients and inspect gateway usage.</p>
      </div>
      <form id="loginForm" class="stack">
        <label>Username <input id="username" autocomplete="username" value="admin"></label>
        <label>Password <input id="password" type="password" autocomplete="current-password"></label>
        <button class="primary" type="submit">Sign in</button>
        <div id="loginError" class="error"></div>
      </form>
    </div>
  </section>

  <section id="appView" class="hidden">
    <header>
      <div>
        <h1>SentinelGuard Gateway</h1>
        <p>Client tokens, usage, providers, and operational status.</p>
      </div>
      <div class="topbar">
        <span id="rolePill" class="pill"></span>
        <button id="refreshBtn">Refresh</button>
        <button id="logoutBtn">Logout</button>
      </div>
    </header>
    <main class="stack">
      <div id="warnings" class="stack"></div>
      <section class="grid stats">
        <div class="panel stat"><span class="muted">Clients</span><strong id="statClients">0</strong></div>
        <div class="panel stat"><span class="muted">Requests</span><strong id="statRequests">0</strong></div>
        <div class="panel stat"><span class="muted">Tokens</span><strong id="statTokens">0</strong></div>
        <div class="panel stat"><span class="muted">Cost</span><strong id="statCost">$0.0000</strong></div>
      </section>

      <section class="grid two">
        <div class="panel stack">
          <div>
            <h2>Client</h2>
            <select id="clientSelect"></select>
          </div>
          <div id="selectedClient"></div>
          <div class="actions admin-action">
            <button id="rotateBtn">Rotate token</button>
            <button id="toggleBtn">Enable / disable</button>
          </div>
          <div id="tokenBox" class="token-box hidden">
            <code id="tokenValue"></code>
            <button id="copyTokenBtn">Copy</button>
          </div>
          <form id="editForm" class="stack admin-action">
            <h2>Update Selected Client</h2>
            <div class="field-grid">
              <label>Allowed models <input id="editModels" placeholder="sentinel-auto, fast-chat, smart-chat, private-chat"></label>
              <label>Tenant <input id="editTenant" placeholder="tenant-a"></label>
              <label>Team <input id="editTeam" placeholder="platform"></label>
              <label>User owner <input id="editUser" placeholder="service-account"></label>
              <label>Budget reset <select id="editBudgetReset"><option value="">All time</option><option>daily</option><option>monthly</option></select></label>
            </div>
            <button id="saveClientBtn" class="primary" type="submit">Save changes</button>
            <p id="editHelp" class="muted"></p>
          </form>
        </div>

        <div class="panel stack">
          <h2>Selected Client Usage</h2>
          <table>
            <tbody id="usageTable"></tbody>
          </table>
        </div>
      </section>

      <section class="panel stack admin-action">
        <h2>Create Client Token</h2>
        <form id="createForm" class="stack">
          <div class="field-grid">
            <label>Client name <input id="newName" placeholder="chatbot-prod"></label>
            <label>Allowed models <input id="newModels" value="*" placeholder="sentinel-auto, fast-chat"></label>
            <label>Tenant <input id="newTenant" placeholder="tenant-a"></label>
            <label>Team <input id="newTeam" placeholder="platform"></label>
            <label>User owner <input id="newUser" placeholder="service-account"></label>
            <label>Budget reset <select id="newBudgetReset"><option value="">All time</option><option>daily</option><option>monthly</option></select></label>
          </div>
          <button class="primary" type="submit">Generate token</button>
        </form>
      </section>

      <section class="panel stack">
        <h2>All Clients</h2>
        <div style="overflow:auto">
          <table>
            <thead><tr><th>Name</th><th>Source</th><th>Status</th><th>Models</th><th>Requests</th><th>Last used</th></tr></thead>
            <tbody id="clientsTable"></tbody>
          </table>
        </div>
      </section>

      <section class="panel stack">
        <h2>Provider Health</h2>
        <div style="overflow:auto">
          <table>
            <thead><tr><th>Provider</th><th>Model</th><th>Status</th><th>Attempts</th><th>Successes</th><th>Failures</th></tr></thead>
            <tbody id="providerTable"></tbody>
          </table>
        </div>
      </section>
    </main>
  </section>

  <script>
    const state = { user: null, clients: [], providers: [], selected: null };
    const $ = (id) => document.getElementById(id);

    async function api(path, options = {}) {
      const response = await fetch(path, {
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', ...(options.headers || {}) },
        ...options,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const message = data?.error?.message || data?.detail || 'Request failed';
        throw new Error(message);
      }
      return data;
    }

    function showLogin() {
      $('loginView').classList.remove('hidden');
      $('appView').classList.add('hidden');
    }

    function showApp() {
      $('loginView').classList.add('hidden');
      $('appView').classList.remove('hidden');
    }

    async function loadMe() {
      try {
        const data = await api('/admin/api/me');
        state.user = data.user;
        showApp();
        await refresh();
      } catch (_) {
        showLogin();
      }
    }

    async function refresh() {
      const data = await api('/admin/api/summary');
      state.user = data.user;
      state.clients = data.clients || [];
      state.providers = data.provider_health || [];
      state.selected = state.clients.find((client) => client.id === $('clientSelect').value) || state.clients[0] || null;
      renderSummary(data.summary || {});
      renderWarnings(data.security_warnings || []);
      renderRole();
      renderClientSelect();
      renderSelectedClient();
      renderClientsTable();
      renderProviderTable();
    }

    function renderSummary(summary) {
      $('statClients').textContent = `${summary.enabled_clients || 0}/${summary.total_clients || 0}`;
      $('statRequests').textContent = summary.total_requests || 0;
      $('statTokens').textContent = summary.total_tokens || 0;
      $('statCost').textContent = `$${Number(summary.total_cost || 0).toFixed(6)}`;
    }

    function renderWarnings(warnings) {
      $('warnings').innerHTML = warnings.map((warning) => `<div class="notice">${escapeHtml(warning)}</div>`).join('');
    }

    function renderRole() {
      const user = state.user || { username: 'unknown', role: 'viewer' };
      $('rolePill').textContent = `${user.username} · ${user.role}`;
      document.querySelectorAll('.admin-action').forEach((node) => {
        node.classList.toggle('hidden', user.role !== 'admin');
      });
    }

    function renderClientSelect() {
      $('clientSelect').innerHTML = state.clients.map((client) => {
        const selected = state.selected && state.selected.id === client.id ? 'selected' : '';
        return `<option value="${escapeHtml(client.id)}" ${selected}>${escapeHtml(client.name)}</option>`;
      }).join('');
    }

    function renderSelectedClient() {
      const client = state.selected;
      if (!client) {
        $('selectedClient').innerHTML = '<p class="muted">No clients yet.</p>';
        $('usageTable').innerHTML = '';
        $('rotateBtn').disabled = true;
        $('toggleBtn').disabled = true;
        populateEditForm(null);
        return;
      }
      $('rotateBtn').disabled = !client.managed;
      $('toggleBtn').disabled = !client.managed;
      $('selectedClient').innerHTML = `
        <table><tbody>
          <tr><th>Name</th><td>${escapeHtml(client.name)}</td></tr>
          <tr><th>Token</th><td><code>${escapeHtml(client.token_prefix || 'configured outside dashboard')}</code></td></tr>
          <tr><th>Source</th><td>${escapeHtml(client.source || 'config')}</td></tr>
          <tr><th>Status</th><td class="${client.enabled ? 'ok' : 'danger-text'}">${client.enabled ? 'enabled' : 'disabled'}</td></tr>
          <tr><th>Models</th><td>${escapeHtml((client.allowed_models || []).join(', ') || '*')}</td></tr>
          <tr><th>Tenant</th><td>${escapeHtml(client.tenant_id || '')}</td></tr>
          <tr><th>Team</th><td>${escapeHtml(client.team_id || '')}</td></tr>
        </tbody></table>`;
      populateEditForm(client);
      const usage = client.usage || {};
      $('usageTable').innerHTML = rows({
        Requests: usage.requests || 0,
        'Prompt tokens': usage.prompt_tokens || 0,
        'Completion tokens': usage.completion_tokens || 0,
        'Total tokens': usage.total_tokens || 0,
        Cost: `$${Number(usage.total_cost || 0).toFixed(6)}`,
        Models: mapText(usage.models),
        Providers: mapText(usage.providers),
        'Cache hits': usage.cache_hits || 0,
        Window: usage.window || 'all_time',
      });
    }

    function populateEditForm(client) {
      const editable = Boolean(client && client.managed && state.user?.role === 'admin');
      $('editModels').value = client ? ((client.allowed_models || []).join(', ') || '*') : '';
      $('editTenant').value = client?.tenant_id || '';
      $('editTeam').value = client?.team_id || '';
      $('editUser').value = client?.user_id || '';
      $('editBudgetReset').value = client?.budget_reset || '';
      ['editModels', 'editTenant', 'editTeam', 'editUser', 'editBudgetReset', 'saveClientBtn'].forEach((id) => {
        $(id).disabled = !editable;
      });
      $('editHelp').textContent = client && !client.managed
        ? 'This client is managed by environment or YAML config and cannot be edited here.'
        : '';
    }

    function renderClientsTable() {
      $('clientsTable').innerHTML = state.clients.map((client) => `
        <tr>
          <td>${escapeHtml(client.name)}</td>
          <td>${escapeHtml(client.source || 'config')}</td>
          <td class="${client.enabled ? 'ok' : 'danger-text'}">${client.enabled ? 'enabled' : 'disabled'}</td>
          <td>${escapeHtml((client.allowed_models || []).join(', ') || '*')}</td>
          <td>${client.usage?.requests || 0}</td>
          <td>${formatTime(client.last_used_at)}</td>
        </tr>`).join('');
    }

    function renderProviderTable() {
      $('providerTable').innerHTML = state.providers.map((provider) => `
        <tr>
          <td>${escapeHtml(provider.name || provider.provider || 'unknown')}</td>
          <td>${escapeHtml(provider.model_name || provider.upstream_model || '')}</td>
          <td class="${provider.healthy === false ? 'danger-text' : 'ok'}">${provider.healthy === false ? 'unhealthy' : 'healthy'}</td>
          <td>${provider.attempts || 0}</td>
          <td>${provider.successes || 0}</td>
          <td>${provider.failures || 0}</td>
        </tr>`).join('');
    }

    function rows(values) {
      return Object.entries(values).map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(String(value))}</td></tr>`).join('');
    }

    function mapText(value) {
      const entries = Object.entries(value || {});
      return entries.length ? entries.map(([key, count]) => `${key}: ${count}`).join(', ') : 'none';
    }

    function formatTime(epoch) {
      if (!epoch) return 'never';
      return new Date(epoch * 1000).toLocaleString();
    }

    function escapeHtml(value) {
      return String(value).replace(/[&<>'"]/g, (char) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
      }[char]));
    }

    function showToken(token) {
      $('tokenValue').textContent = token;
      $('tokenBox').classList.remove('hidden');
    }

    $('loginForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      $('loginError').textContent = '';
      try {
        await api('/admin/api/login', {
          method: 'POST',
          body: JSON.stringify({ username: $('username').value, password: $('password').value }),
        });
        showApp();
        await refresh();
      } catch (error) {
        $('loginError').textContent = error.message;
      }
    });

    $('logoutBtn').addEventListener('click', async () => {
      await api('/admin/api/logout', { method: 'POST', body: '{}' }).catch(() => ({}));
      showLogin();
    });

    $('refreshBtn').addEventListener('click', refresh);
    $('clientSelect').addEventListener('change', () => {
      state.selected = state.clients.find((client) => client.id === $('clientSelect').value) || null;
      renderSelectedClient();
    });

    $('createForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const data = await api('/admin/api/clients', {
        method: 'POST',
        body: JSON.stringify({
          name: $('newName').value,
          allowed_models: $('newModels').value,
          tenant_id: $('newTenant').value,
          team_id: $('newTeam').value,
          user_id: $('newUser').value,
          budget_reset: $('newBudgetReset').value,
        }),
      });
      showToken(data.token);
      $('newName').value = '';
      await refresh();
      $('clientSelect').value = data.client.id;
      state.selected = state.clients.find((client) => client.id === data.client.id) || null;
      renderSelectedClient();
    });

    $('rotateBtn').addEventListener('click', async () => {
      if (!state.selected) return;
      const data = await api(`/admin/api/clients/${state.selected.id}/rotate`, { method: 'POST', body: '{}' });
      showToken(data.token);
      await refresh();
    });

    $('toggleBtn').addEventListener('click', async () => {
      if (!state.selected) return;
      await api(`/admin/api/clients/${state.selected.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !state.selected.enabled }),
      });
      await refresh();
    });

    $('editForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!state.selected || !state.selected.managed) return;
      const clientId = state.selected.id;
      const data = await api(`/admin/api/clients/${clientId}`, {
        method: 'PATCH',
        body: JSON.stringify({
          allowed_models: $('editModels').value,
          tenant_id: $('editTenant').value,
          team_id: $('editTeam').value,
          user_id: $('editUser').value,
          budget_reset: $('editBudgetReset').value,
        }),
      });
      await refresh();
      $('clientSelect').value = data.client.id;
      state.selected = state.clients.find((client) => client.id === data.client.id) || null;
      renderSelectedClient();
    });

    $('copyTokenBtn').addEventListener('click', async () => {
      await navigator.clipboard.writeText($('tokenValue').textContent || '');
      $('copyTokenBtn').textContent = 'Copied';
      setTimeout(() => { $('copyTokenBtn').textContent = 'Copy'; }, 1200);
    });

    loadMe();
  </script>
</body>
</html>"""


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _guardrail_input_text(payload: Mapping[str, Any]) -> str:
    for key in ("input", "text", "prompt", "output"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    messages = payload.get("messages")
    if isinstance(messages, list):
        return extract_last_user_text(messages)
    return ""


def _guardrail_direction(payload: Mapping[str, Any]) -> str:
    direction = str(payload.get("direction") or "").strip().lower()
    if direction in {"output", "response", "completion", "post_call"}:
        return "output"
    return "prompt"


def _require_admin_user(
    request: Request,
    admin_store: GatewayAdminStore,
    config: GatewayConfig,
    *,
    required_role: Optional[str] = None,
) -> AdminIdentity:
    if not getattr(config, "admin_auth_enabled", True):
        return AdminIdentity(username="admin", role=ADMIN_ROLE)
    identity = admin_store.get_session(_admin_session_token(request))
    if identity is None:
        raise HTTPException(status_code=401, detail="SentinelGuard dashboard login required")
    if required_role == ADMIN_ROLE and identity.role != ADMIN_ROLE:
        raise HTTPException(status_code=403, detail="SentinelGuard dashboard admin role required")
    return identity


def _admin_session_token(request: Request) -> Optional[str]:
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if token:
        return token
    authorization = request.headers.get("authorization") or request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        return authorization.removeprefix("Bearer ")
    return None


def _admin_identity_payload(identity: AdminIdentity) -> dict[str, Any]:
    return {"username": identity.username, "role": identity.role}


def _admin_summary_payload(
    config: GatewayConfig,
    admin_store: GatewayAdminStore,
    usage_store: Any,
    identity: AdminIdentity,
) -> dict[str, Any]:
    clients = _dashboard_clients(config, admin_store, usage_store)
    summary = _usage_summary(clients)
    return {
        "object": "sentinelguard.gateway.admin.summary",
        "api_version": GATEWAY_API_VERSION,
        "user": _admin_identity_payload(identity),
        "summary": summary,
        "clients": clients,
        "provider_health": _provider_health_payload(config)["providers"],
        "routes": _routes_payload(config),
        "security_warnings": admin_store.security_warnings(),
        "metrics": {
            "prometheus_enabled": config.metrics_enabled,
            "prometheus_path": "/metrics" if config.metrics_enabled else None,
        },
    }


def _dashboard_clients(
    config: GatewayConfig,
    admin_store: GatewayAdminStore,
    usage_store: Any,
) -> list[dict[str, Any]]:
    clients = [_with_usage(client, usage_store) for client in admin_store.list_clients()]
    clients.extend(_configured_client_summaries(config, usage_store))
    return sorted(clients, key=lambda item: (str(item.get("source")), str(item.get("name"))))


def _configured_client_summaries(config: GatewayConfig, usage_store: Any) -> list[dict[str, Any]]:
    clients: list[dict[str, Any]] = []
    for key in config.virtual_keys:
        secret = key.key or (os.getenv(key.key_env) if key.key_env else None)
        key_id = hash_secret(secret) if secret else f"config:{key.name}"
        clients.append(
            _with_usage(
                {
                    "id": key_id,
                    "key_id": key_id,
                    "name": key.name,
                    "enabled": key.enabled,
                    "token_prefix": "configured outside dashboard" if secret else "missing",
                    "tenant_id": key.tenant_id,
                    "team_id": key.team_id,
                    "user_id": key.user_id,
                    "allowed_models": list(key.allowed_models),
                    "max_requests": key.max_requests,
                    "max_tokens": key.max_tokens,
                    "max_budget": key.max_budget,
                    "budget_reset": key.budget_reset,
                    "created_at": None,
                    "updated_at": None,
                    "rotated_at": None,
                    "last_used_at": None,
                    "source": "config",
                    "managed": False,
                },
                usage_store,
            )
        )
    legacy_key = _client_api_key(config)
    if legacy_key and not config.virtual_keys:
        key_id = hash_secret(legacy_key)
        clients.append(
            _with_usage(
                {
                    "id": key_id,
                    "key_id": key_id,
                    "name": "gateway-client",
                    "enabled": True,
                    "token_prefix": "configured outside dashboard",
                    "tenant_id": None,
                    "team_id": None,
                    "user_id": None,
                    "allowed_models": ["*"],
                    "max_requests": None,
                    "max_tokens": None,
                    "max_budget": None,
                    "budget_reset": None,
                    "created_at": None,
                    "updated_at": None,
                    "rotated_at": None,
                    "last_used_at": None,
                    "source": "env",
                    "managed": False,
                },
                usage_store,
            )
        )
    return clients


def _with_usage(client: Mapping[str, Any], usage_store: Any) -> dict[str, Any]:
    item = dict(client)
    item["usage"] = usage_store.snapshot(
        str(item.get("key_id") or item.get("id")),
        item.get("budget_reset"),
    ).to_dict()
    return item


def _client_usage_payload(
    client_id: str,
    config: GatewayConfig,
    admin_store: GatewayAdminStore,
    usage_store: Any,
) -> dict[str, Any]:
    for client in _dashboard_clients(config, admin_store, usage_store):
        if client.get("id") == client_id or client.get("key_id") == client_id:
            return {
                "object": "sentinelguard.gateway.admin.client_usage",
                "api_version": GATEWAY_API_VERSION,
                "client": client,
                "usage": client["usage"],
            }
    raise HTTPException(status_code=404, detail="Gateway client not found")


def _usage_summary(clients: list[dict[str, Any]]) -> dict[str, Any]:
    total_requests = 0
    total_tokens = 0
    total_cost = 0.0
    cache_hits = 0
    for client in clients:
        usage = client.get("usage") or {}
        total_requests += int(usage.get("requests") or 0)
        total_tokens += int(usage.get("total_tokens") or 0)
        total_cost += float(usage.get("total_cost") or 0.0)
        cache_hits += int(usage.get("cache_hits") or 0)
    return {
        "total_clients": len(clients),
        "enabled_clients": sum(1 for client in clients if client.get("enabled")),
        "total_requests": total_requests,
        "total_tokens": total_tokens,
        "total_cost": round(total_cost, 10),
        "cache_hits": cache_hits,
    }


def _gateway_uses_pii(guard: SentinelGuard, config: GatewayConfig) -> bool:
    if (
        config.redact_pii
        or config.redact_output_pii
        or config.route_pii_to_private_provider
        or config.route_sensitive_to_private_provider
        or config.sensitive_session_routing_enabled
    ):
        return True
    scanner_names = set(guard.prompt_scanner_names) | set(guard.output_scanner_names)
    return bool(scanner_names & {"pii", "anonymize", "deanonymize"})


def _warm_presidio_for_gateway() -> None:
    try:
        from sentinelguard.pii import warm_presidio_analyzer

        if warm_presidio_analyzer():
            logger.info("Presidio AnalyzerEngine warmed for gateway traffic")
    except Exception as exc:
        logger.debug("Presidio warmup skipped: %s", exc)


async def _warm_gateway_scanners(guard: SentinelGuard, config: GatewayConfig) -> None:
    try:
        prompt = (
            "Warmup request for Pat Example at warmup@example.com "
            "or 555-123-4567."
        )
        prompt_scan = await guard.scan_prompt_async(prompt)
        evaluate_prompt_policy(prompt, prompt_scan, config)

        output = "Warmup response from SentinelGuard."
        output_scan = await guard.scan_output_async(output, prompt=prompt)
        evaluate_output_policy(output, output_scan, config)
        logger.info("SentinelGuard gateway scanners warmed")
    except Exception as exc:
        logger.debug("Gateway scanner warmup skipped: %s", exc)


def _payload_text(payload: Mapping[str, Any], key: str) -> Optional[str]:
    value = payload.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _payload_update_text(payload: Mapping[str, Any], key: str) -> Optional[str]:
    if key not in payload:
        return None
    value = payload.get(key)
    return "" if value is None else str(value)


def _payload_allowed_models(value: Any) -> Optional[list[str]]:
    if value is None:
        return None
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return None


def _optional_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _client_auth_enabled(config: GatewayConfig) -> bool:
    if _client_api_key(config) or config.virtual_keys:
        return True
    if not config.admin_ui_enabled:
        return False
    try:
        return gateway_admin_store(config).has_clients()
    except Exception:
        return False


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


def _unknown_guardrails_response(unknown: list[str]) -> JSONResponse:
    names = ", ".join(unknown)
    return _gateway_error_response(
        400,
        "sentinelguard_unknown_guardrail",
        f"Unknown SentinelGuard guardrail requested: {names}",
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
