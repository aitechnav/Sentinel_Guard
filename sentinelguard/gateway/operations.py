"""Operational helpers for SentinelGuard gateway mode.

This module keeps customer-facing gateway features lightweight and local:
virtual-key authorization, in-memory usage accounting, basic budgets, and a
small response cache. These are intentionally independent from provider
adapters so they can be reused by future endpoints beyond chat completions.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from sentinelguard.gateway.config import GatewayConfig, ProviderConfig, VirtualKeyConfig
from sentinelguard.gateway.providers import extract_assistant_text, extract_last_user_text


@dataclass(frozen=True)
class GatewayClient:
    """Authenticated gateway caller metadata."""

    key_id: str
    name: str = "anonymous"
    tenant_id: Optional[str] = None
    team_id: Optional[str] = None
    user_id: Optional[str] = None
    allowed_models: tuple[str, ...] = ()
    max_requests: Optional[int] = None
    max_tokens: Optional[int] = None
    max_budget: Optional[float] = None
    budget_reset: Optional[str] = None


@dataclass(frozen=True)
class GatewayAuthResult:
    """Result of authenticating a gateway client request."""

    allowed: bool
    client: Optional[GatewayClient] = None
    status_code: int = 200
    error_type: str = ""
    message: str = ""


@dataclass(frozen=True)
class GatewayAccessResult:
    """Result of checking model access and usage limits."""

    allowed: bool
    status_code: int = 200
    error_type: str = ""
    message: str = ""


@dataclass
class UsageSnapshot:
    """In-memory usage counters for one virtual key."""

    requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0
    models: dict[str, int] = field(default_factory=dict)
    providers: dict[str, int] = field(default_factory=dict)
    cache_hits: int = 0
    window: str = "all_time"
    window_start: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "total_cost": round(self.total_cost, 10),
            "models": dict(self.models),
            "providers": dict(self.providers),
            "cache_hits": self.cache_hits,
            "window": self.window,
            "window_start": self.window_start,
        }


@dataclass(frozen=True)
class ChatUsage:
    """Token and cost usage extracted from one chat response."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost: float = 0.0


class GatewayUsageStore:
    """Thread-safe in-memory usage store for virtual-key limits."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._usage: dict[str, UsageSnapshot] = {}

    def snapshot(self, key_id: str, budget_reset: Optional[str] = None) -> UsageSnapshot:
        with self._lock:
            storage_key, window, window_start = _usage_storage_key(key_id, budget_reset)
            current = self._usage.get(
                storage_key,
                UsageSnapshot(window=window, window_start=window_start),
            )
            return copy.deepcopy(current)

    def all_snapshots(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {key: copy.deepcopy(value).to_dict() for key, value in self._usage.items()}

    def check_limits(self, client: GatewayClient) -> GatewayAccessResult:
        usage = self.snapshot(client.key_id, client.budget_reset)
        if client.max_requests is not None and usage.requests >= client.max_requests:
            return GatewayAccessResult(
                allowed=False,
                status_code=429,
                error_type="sentinelguard_request_budget_exceeded",
                message="SentinelGuard gateway request budget exceeded",
            )
        if client.max_tokens is not None and usage.total_tokens >= client.max_tokens:
            return GatewayAccessResult(
                allowed=False,
                status_code=429,
                error_type="sentinelguard_token_budget_exceeded",
                message="SentinelGuard gateway token budget exceeded",
            )
        if client.max_budget is not None and usage.total_cost >= client.max_budget:
            return GatewayAccessResult(
                allowed=False,
                status_code=429,
                error_type="sentinelguard_spend_budget_exceeded",
                message="SentinelGuard gateway spend budget exceeded",
            )
        return GatewayAccessResult(allowed=True)

    def record(
        self,
        client: GatewayClient,
        *,
        model: str,
        provider: str,
        usage: ChatUsage,
        cache_hit: bool = False,
    ) -> None:
        with self._lock:
            storage_key, window, window_start = _usage_storage_key(
                client.key_id,
                client.budget_reset,
            )
            snapshot = self._usage.setdefault(
                storage_key,
                UsageSnapshot(window=window, window_start=window_start),
            )
            snapshot.requests += 1
            snapshot.prompt_tokens += usage.prompt_tokens
            snapshot.completion_tokens += usage.completion_tokens
            snapshot.total_tokens += usage.total_tokens
            snapshot.total_cost += usage.cost
            snapshot.models[model] = snapshot.models.get(model, 0) + 1
            snapshot.providers[provider] = snapshot.providers.get(provider, 0) + 1
            if cache_hit:
                snapshot.cache_hits += 1

    def reset(self) -> None:
        with self._lock:
            self._usage.clear()


class SQLiteGatewayUsageStore(GatewayUsageStore):
    """SQLite-backed usage store for persistent gateway keys and budgets."""

    def __init__(self, path: str) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def snapshot(self, key_id: str, budget_reset: Optional[str] = None) -> UsageSnapshot:
        storage_key, window, window_start = _usage_storage_key(key_id, budget_reset)
        with self._lock:
            row = self._conn().execute(
                """
                SELECT requests, prompt_tokens, completion_tokens, total_tokens,
                       total_cost, models_json, providers_json, cache_hits
                FROM gateway_usage
                WHERE storage_key = ?
                """,
                (storage_key,),
            ).fetchone()
        if row is None:
            return UsageSnapshot(window=window, window_start=window_start)
        return UsageSnapshot(
            requests=int(row[0]),
            prompt_tokens=int(row[1]),
            completion_tokens=int(row[2]),
            total_tokens=int(row[3]),
            total_cost=float(row[4]),
            models=json.loads(row[5] or "{}"),
            providers=json.loads(row[6] or "{}"),
            cache_hits=int(row[7]),
            window=window,
            window_start=window_start,
        )

    def all_snapshots(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._conn().execute(
                """
                SELECT storage_key, key_id, budget_window, window_start, requests,
                       prompt_tokens, completion_tokens, total_tokens, total_cost,
                       models_json, providers_json, cache_hits
                FROM gateway_usage
                """
            ).fetchall()
        snapshots = {}
        for row in rows:
            snapshots[row[0]] = UsageSnapshot(
                requests=int(row[4]),
                prompt_tokens=int(row[5]),
                completion_tokens=int(row[6]),
                total_tokens=int(row[7]),
                total_cost=float(row[8]),
                models=json.loads(row[9] or "{}"),
                providers=json.loads(row[10] or "{}"),
                cache_hits=int(row[11]),
                window=str(row[2]),
                window_start=int(row[3]),
            ).to_dict()
            snapshots[row[0]]["key_id"] = row[1]
        return snapshots

    def record(
        self,
        client: GatewayClient,
        *,
        model: str,
        provider: str,
        usage: ChatUsage,
        cache_hit: bool = False,
    ) -> None:
        current = self.snapshot(client.key_id, client.budget_reset)
        current.requests += 1
        current.prompt_tokens += usage.prompt_tokens
        current.completion_tokens += usage.completion_tokens
        current.total_tokens += usage.total_tokens
        current.total_cost += usage.cost
        current.models[model] = current.models.get(model, 0) + 1
        current.providers[provider] = current.providers.get(provider, 0) + 1
        if cache_hit:
            current.cache_hits += 1

        storage_key, window, window_start = _usage_storage_key(
            client.key_id,
            client.budget_reset,
        )
        with self._lock:
            self._conn().execute(
                """
                INSERT INTO gateway_usage (
                    storage_key, key_id, budget_window, window_start, requests,
                    prompt_tokens, completion_tokens, total_tokens, total_cost,
                    models_json, providers_json, cache_hits
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(storage_key) DO UPDATE SET
                    requests = excluded.requests,
                    prompt_tokens = excluded.prompt_tokens,
                    completion_tokens = excluded.completion_tokens,
                    total_tokens = excluded.total_tokens,
                    total_cost = excluded.total_cost,
                    models_json = excluded.models_json,
                    providers_json = excluded.providers_json,
                    cache_hits = excluded.cache_hits
                """,
                (
                    storage_key,
                    client.key_id,
                    window,
                    window_start,
                    current.requests,
                    current.prompt_tokens,
                    current.completion_tokens,
                    current.total_tokens,
                    current.total_cost,
                    json.dumps(current.models, sort_keys=True),
                    json.dumps(current.providers, sort_keys=True),
                    current.cache_hits,
                ),
            )
            self._conn().commit()

    def reset(self) -> None:
        with self._lock:
            self._conn().execute("DELETE FROM gateway_usage")
            self._conn().commit()

    def _init_db(self) -> None:
        with self._lock:
            self._conn().execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_usage (
                    storage_key TEXT PRIMARY KEY,
                    key_id TEXT NOT NULL,
                    budget_window TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    requests INTEGER NOT NULL,
                    prompt_tokens INTEGER NOT NULL,
                    completion_tokens INTEGER NOT NULL,
                    total_tokens INTEGER NOT NULL,
                    total_cost REAL NOT NULL,
                    models_json TEXT NOT NULL,
                    providers_json TEXT NOT NULL,
                    cache_hits INTEGER NOT NULL
                )
                """
            )
            self._conn().commit()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self, "_connection", None)
        if conn is None:
            conn = sqlite3.connect(self.path, check_same_thread=False)
            self._connection = conn
        return conn


class GatewayResponseCache:
    """Small in-memory cache for non-streaming chat completions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, tuple[float, dict[str, Any]]] = {}

    def get(self, payload: Mapping[str, Any], config: GatewayConfig) -> Optional[dict[str, Any]]:
        if not config.cache_enabled:
            return None
        key = chat_cache_key(payload)
        now = time.time()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= now:
                self._entries.pop(key, None)
                return None
            return copy.deepcopy(value)

    def set(
        self,
        payload: Mapping[str, Any],
        response: Mapping[str, Any],
        config: GatewayConfig,
    ) -> None:
        if not config.cache_enabled:
            return
        max_entries = max(1, int(config.cache_max_entries or 1))
        ttl = max(1, int(config.cache_ttl_seconds or 1))
        key = chat_cache_key(payload)
        with self._lock:
            if len(self._entries) >= max_entries and key not in self._entries:
                oldest = min(self._entries.items(), key=lambda item: item[1][0])[0]
                self._entries.pop(oldest, None)
            self._entries[key] = (time.time() + ttl, copy.deepcopy(dict(response)))

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()


class SQLiteGatewayResponseCache(GatewayResponseCache):
    """SQLite-backed chat response cache."""

    def __init__(self, path: str) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def get(self, payload: Mapping[str, Any], config: GatewayConfig) -> Optional[dict[str, Any]]:
        if not config.cache_enabled:
            return None
        key = chat_cache_key(payload)
        now = time.time()
        with self._lock:
            row = self._conn().execute(
                "SELECT expires_at, response_json FROM gateway_cache WHERE cache_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return None
            if float(row[0]) <= now:
                self._conn().execute("DELETE FROM gateway_cache WHERE cache_key = ?", (key,))
                self._conn().commit()
                return None
            return copy.deepcopy(json.loads(row[1]))

    def set(
        self,
        payload: Mapping[str, Any],
        response: Mapping[str, Any],
        config: GatewayConfig,
    ) -> None:
        if not config.cache_enabled:
            return
        max_entries = max(1, int(config.cache_max_entries or 1))
        ttl = max(1, int(config.cache_ttl_seconds or 1))
        key = chat_cache_key(payload)
        with self._lock:
            self._conn().execute(
                """
                INSERT INTO gateway_cache (cache_key, expires_at, response_json)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    expires_at = excluded.expires_at,
                    response_json = excluded.response_json
                """,
                (
                    key,
                    time.time() + ttl,
                    json.dumps(dict(response), sort_keys=True, default=str),
                ),
            )
            self._evict_if_needed(max_entries)
            self._conn().commit()

    def reset(self) -> None:
        with self._lock:
            self._conn().execute("DELETE FROM gateway_cache")
            self._conn().commit()

    def _evict_if_needed(self, max_entries: int) -> None:
        count = self._conn().execute("SELECT COUNT(*) FROM gateway_cache").fetchone()[0]
        if int(count) <= max_entries:
            return
        self._conn().execute(
            """
            DELETE FROM gateway_cache
            WHERE cache_key IN (
                SELECT cache_key FROM gateway_cache
                ORDER BY expires_at ASC
                LIMIT ?
            )
            """,
            (int(count) - max_entries,),
        )

    def _init_db(self) -> None:
        with self._lock:
            self._conn().execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_cache (
                    cache_key TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL,
                    response_json TEXT NOT NULL
                )
                """
            )
            self._conn().commit()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self, "_connection", None)
        if conn is None:
            conn = sqlite3.connect(self.path, check_same_thread=False)
            self._connection = conn
        return conn


class RedisGatewayResponseCache(GatewayResponseCache):
    """Redis-backed chat response cache when redis-py is installed."""

    def __init__(self, redis_url: str) -> None:
        try:
            import redis
        except ImportError as exc:
            raise ImportError("Install redis to use cache_backend: redis") from exc
        self._client = redis.Redis.from_url(redis_url)

    def get(self, payload: Mapping[str, Any], config: GatewayConfig) -> Optional[dict[str, Any]]:
        if not config.cache_enabled:
            return None
        raw = self._client.get(f"sentinelguard:cache:{chat_cache_key(payload)}")
        if not raw:
            return None
        return json.loads(raw)

    def set(
        self,
        payload: Mapping[str, Any],
        response: Mapping[str, Any],
        config: GatewayConfig,
    ) -> None:
        if not config.cache_enabled:
            return
        ttl = max(1, int(config.cache_ttl_seconds or 1))
        self._client.setex(
            f"sentinelguard:cache:{chat_cache_key(payload)}",
            ttl,
            json.dumps(dict(response), sort_keys=True, default=str),
        )

    def reset(self) -> None:
        for key in self._client.scan_iter("sentinelguard:cache:*"):
            self._client.delete(key)


_USAGE_STORE = GatewayUsageStore()
_RESPONSE_CACHE = GatewayResponseCache()
_STORE_CACHE: dict[tuple[str, str], GatewayUsageStore] = {}
_RESPONSE_CACHE_CACHE: dict[tuple[str, str], GatewayResponseCache] = {}


def gateway_usage_store(config: Optional[GatewayConfig] = None) -> GatewayUsageStore:
    """Return the process-local usage store."""
    if config is not None and config.state_backend.lower() == "sqlite":
        path = config.state_path or "/tmp/sentinelguard_gateway_state.sqlite3"
        key = ("sqlite", path)
        if key not in _STORE_CACHE:
            _STORE_CACHE[key] = SQLiteGatewayUsageStore(path)
        return _STORE_CACHE[key]
    return _USAGE_STORE


def gateway_response_cache(config: Optional[GatewayConfig] = None) -> GatewayResponseCache:
    """Return the process-local response cache."""
    if config is not None:
        backend = config.cache_backend.lower()
        if backend == "sqlite":
            path = config.state_path or "/tmp/sentinelguard_gateway_state.sqlite3"
            key = ("sqlite", path)
            if key not in _RESPONSE_CACHE_CACHE:
                _RESPONSE_CACHE_CACHE[key] = SQLiteGatewayResponseCache(path)
            return _RESPONSE_CACHE_CACHE[key]
        if backend == "redis":
            url = config.redis_url or os.getenv("REDIS_URL") or "redis://localhost:6379/0"
            key = ("redis", url)
            if key not in _RESPONSE_CACHE_CACHE:
                _RESPONSE_CACHE_CACHE[key] = RedisGatewayResponseCache(url)
            return _RESPONSE_CACHE_CACHE[key]
    return _RESPONSE_CACHE


def authenticate_gateway_request(
    headers: Mapping[str, str],
    config: GatewayConfig,
) -> GatewayAuthResult:
    """Authenticate a client request against virtual keys or legacy single key."""
    token = extract_gateway_token(headers)

    if config.virtual_keys:
        if not token:
            return GatewayAuthResult(
                allowed=False,
                status_code=401,
                error_type="sentinelguard_gateway_unauthorized",
                message="SentinelGuard gateway authentication failed",
            )
        for virtual_key in config.virtual_keys:
            if not virtual_key.enabled:
                continue
            configured = _virtual_key_secret(virtual_key)
            if configured and token == configured:
                return GatewayAuthResult(
                    allowed=True,
                    client=_client_from_virtual_key(virtual_key, configured),
                )
        return GatewayAuthResult(
            allowed=False,
            status_code=401,
            error_type="sentinelguard_gateway_unauthorized",
            message="SentinelGuard gateway authentication failed",
        )

    expected = _legacy_client_api_key(config)
    if expected:
        if token == expected:
            return GatewayAuthResult(
                allowed=True,
                client=GatewayClient(key_id=hash_secret(expected), name="gateway-client"),
            )
        return GatewayAuthResult(
            allowed=False,
            status_code=401,
            error_type="sentinelguard_gateway_unauthorized",
            message="SentinelGuard gateway authentication failed",
        )

    return GatewayAuthResult(
        allowed=True,
        client=GatewayClient(key_id="anonymous", name="anonymous"),
    )


def check_gateway_access(
    client: GatewayClient,
    payload: Mapping[str, Any],
    usage_store: Optional[GatewayUsageStore] = None,
) -> GatewayAccessResult:
    """Check model access and in-memory request/token/spend budgets."""
    model = str(payload.get("model") or "")
    if client.allowed_models and not any(model_matches(pattern, model) for pattern in client.allowed_models):
        return GatewayAccessResult(
            allowed=False,
            status_code=403,
            error_type="sentinelguard_model_not_allowed",
            message="SentinelGuard gateway key is not allowed to use this model",
        )

    store = usage_store or gateway_usage_store()
    return store.check_limits(client)


def extract_gateway_token(headers: Mapping[str, str]) -> Optional[str]:
    """Extract a client-facing gateway token from common API-key headers."""
    incoming = {key.lower(): value for key, value in headers.items()}
    authorization = incoming.get("authorization")
    if authorization:
        return _bearer_token(authorization)
    for name in ("x-api-key", "x-sentinelguard-api-key"):
        if incoming.get(name):
            return incoming[name]
    return None


def model_matches(pattern: str, model: str) -> bool:
    """Return True when a model name matches an exact or wildcard pattern."""
    if pattern == "*":
        return True
    if pattern.endswith("/*"):
        return model.startswith(pattern[:-1])
    if pattern.endswith("*"):
        return model.startswith(pattern[:-1])
    return pattern == model


def chat_cache_key(payload: Mapping[str, Any]) -> str:
    """Build a privacy-safe cache key for a chat-completion payload."""
    cacheable = {
        "model": payload.get("model"),
        "messages": payload.get("messages"),
        "temperature": payload.get("temperature"),
        "top_p": payload.get("top_p"),
        "max_tokens": payload.get("max_tokens"),
        "tools": payload.get("tools"),
        "tool_choice": payload.get("tool_choice"),
        "response_format": payload.get("response_format"),
    }
    encoded = json.dumps(cacheable, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def extract_chat_usage(
    payload: Mapping[str, Any],
    response: Mapping[str, Any],
    provider: Optional[ProviderConfig] = None,
) -> ChatUsage:
    """Extract or estimate usage and calculate a simple configured cost."""
    usage = response.get("usage") if isinstance(response, Mapping) else {}
    usage = usage if isinstance(usage, Mapping) else {}

    prompt_tokens = _int_or_zero(usage.get("prompt_tokens"))
    completion_tokens = _int_or_zero(usage.get("completion_tokens"))
    total_tokens = _int_or_zero(usage.get("total_tokens"))

    if total_tokens == 0:
        prompt_tokens = estimate_tokens(extract_last_user_text(payload.get("messages", [])))
        completion_tokens = estimate_tokens(extract_assistant_text(response))
        total_tokens = prompt_tokens + completion_tokens

    cost = 0.0
    if provider:
        cost += prompt_tokens * float(provider.input_cost_per_token or 0.0)
        cost += completion_tokens * float(provider.output_cost_per_token or 0.0)

    return ChatUsage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        cost=cost,
    )


def provider_for_result(
    config: GatewayConfig,
    provider_name: str,
) -> Optional[ProviderConfig]:
    """Return the configured provider that produced a forwarding result."""
    for provider in config.providers:
        if provider.name == provider_name:
            return provider
    return None


def virtual_key_summary(config: GatewayConfig) -> list[dict[str, Any]]:
    """Return non-secret virtual key metadata for health/routes endpoints."""
    return [
        {
            "name": key.name,
            "enabled": key.enabled,
            "tenant_id": key.tenant_id,
            "team_id": key.team_id,
            "user_id": key.user_id,
            "allowed_models": list(key.allowed_models),
            "max_requests": key.max_requests,
            "max_tokens": key.max_tokens,
            "max_budget": key.max_budget,
            "budget_reset": key.budget_reset,
            "key_configured": bool(_virtual_key_secret(key)),
        }
        for key in config.virtual_keys
    ]


def estimate_tokens(text: str) -> int:
    """Small local token estimate for usage fallback."""
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def hash_secret(value: str) -> str:
    """Hash secret material for identifiers without storing raw tokens."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _client_from_virtual_key(virtual_key: VirtualKeyConfig, secret: str) -> GatewayClient:
    return GatewayClient(
        key_id=hash_secret(secret),
        name=virtual_key.name,
        tenant_id=virtual_key.tenant_id,
        team_id=virtual_key.team_id,
        user_id=virtual_key.user_id,
        allowed_models=tuple(virtual_key.allowed_models),
        max_requests=virtual_key.max_requests,
        max_tokens=virtual_key.max_tokens,
        max_budget=virtual_key.max_budget,
        budget_reset=virtual_key.budget_reset,
    )


def _virtual_key_secret(virtual_key: VirtualKeyConfig) -> Optional[str]:
    if virtual_key.key:
        return virtual_key.key
    if virtual_key.key_env:
        return os.getenv(virtual_key.key_env)
    return None


def _legacy_client_api_key(config: GatewayConfig) -> Optional[str]:
    if config.client_api_key:
        return config.client_api_key
    if config.client_api_key_env:
        return os.getenv(config.client_api_key_env)
    return None


def _bearer_token(value: str) -> str:
    prefix = "Bearer "
    if value.startswith(prefix):
        return value[len(prefix) :]
    return value


def _int_or_zero(value: Any) -> int:
    return value if isinstance(value, int) else 0


def _usage_storage_key(key_id: str, budget_reset: Optional[str]) -> tuple[str, str, int]:
    window, window_start = _budget_window(budget_reset)
    return f"{key_id}:{window}:{window_start}", window, window_start


def _budget_window(budget_reset: Optional[str]) -> tuple[str, int]:
    normalized = (budget_reset or "none").strip().lower()
    now = int(time.time())
    if normalized in {"hour", "hourly", "1h"}:
        return "hourly", now - (now % 3600)
    if normalized in {"day", "daily", "24h"}:
        return "daily", now - (now % 86400)
    if normalized in {"month", "monthly", "30d"}:
        # Month-length reset is approximated as a calendar-independent 30-day
        # operational window to avoid timezone/database dependencies.
        return "monthly", now - (now % (86400 * 30))
    return "all_time", 0
