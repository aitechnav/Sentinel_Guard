"""Admin dashboard state and client-token management for the gateway."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sentinelguard.gateway.config import GatewayConfig, normalize_policy_actions
from sentinelguard.gateway.operations import GatewayClient

ADMIN_COOKIE_NAME = "sentinelguard_admin_session"
ADMIN_ROLE = "admin"
VIEWER_ROLE = "viewer"
_PASSWORD_ITERATIONS = 200_000
_ADMIN_STORE_CACHE: dict[str, "GatewayAdminStore"] = {}


@dataclass(frozen=True)
class AdminIdentity:
    """Authenticated dashboard user identity."""

    username: str
    role: str


@dataclass(frozen=True)
class StoredGatewayToken:
    """One gateway client token record without raw token material."""

    id: str
    name: str
    enabled: bool
    token_prefix: str
    tenant_id: Optional[str] = None
    team_id: Optional[str] = None
    user_id: Optional[str] = None
    allowed_models: tuple[str, ...] = ()
    policy_actions: dict[str, str] = field(default_factory=dict)
    max_requests: Optional[int] = None
    max_tokens: Optional[int] = None
    max_budget: Optional[float] = None
    budget_reset: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0
    rotated_at: Optional[int] = None
    last_used_at: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key_id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "token_prefix": self.token_prefix,
            "tenant_id": self.tenant_id,
            "team_id": self.team_id,
            "user_id": self.user_id,
            "allowed_models": list(self.allowed_models),
            "policy_actions": normalize_policy_actions(self.policy_actions),
            "max_requests": self.max_requests,
            "max_tokens": self.max_tokens,
            "max_budget": self.max_budget,
            "budget_reset": self.budget_reset,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "rotated_at": self.rotated_at,
            "last_used_at": self.last_used_at,
            "source": "dashboard",
            "managed": True,
        }


class GatewayAdminStore:
    """SQLite-backed dashboard users, sessions, and managed gateway tokens."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.path = _admin_state_path(config)
        self._lock = threading.RLock()
        self._sessions: dict[str, tuple[AdminIdentity, int]] = {}
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_default_users()

    def verify_user(self, username: str, password: str) -> Optional[AdminIdentity]:
        username = username.strip()
        if not username or not password:
            return None
        with self._lock:
            row = self._conn().execute(
                "SELECT username, password_hash, role FROM gateway_admin_users WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None or not _verify_password(password, str(row["password_hash"])):
            return None
        return AdminIdentity(username=str(row["username"]), role=str(row["role"]))

    def create_session(self, identity: AdminIdentity) -> str:
        token = secrets.token_urlsafe(32)
        ttl = max(300, int(getattr(self.config, "admin_session_ttl_seconds", 28800) or 28800))
        expires_at = int(time.time()) + ttl
        with self._lock:
            self._sessions[token] = (identity, expires_at)
        return token

    def get_session(self, token: Optional[str]) -> Optional[AdminIdentity]:
        if not token:
            return None
        now = int(time.time())
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            identity, expires_at = session
            if expires_at <= now:
                self._sessions.pop(token, None)
                return None
            return identity

    def delete_session(self, token: Optional[str]) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn().execute(
                "SELECT username, role, created_at FROM gateway_admin_users ORDER BY username"
            ).fetchall()
        return [
            {
                "username": str(row["username"]),
                "role": str(row["role"]),
                "created_at": int(row["created_at"]),
            }
            for row in rows
        ]

    def has_clients(self) -> bool:
        with self._lock:
            count = self._conn().execute(
                "SELECT COUNT(*) FROM gateway_clients"
            ).fetchone()[0]
        return int(count) > 0

    def list_clients(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn().execute(
                "SELECT * FROM gateway_clients ORDER BY name"
            ).fetchall()
        return [_stored_token_from_row(row).to_dict() for row in rows]

    def get_client(self, client_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn().execute(
                "SELECT * FROM gateway_clients WHERE id = ?",
                (client_id,),
            ).fetchone()
        return _stored_token_from_row(row).to_dict() if row is not None else None

    def client_from_token(self, token: str) -> Optional[GatewayClient]:
        token_hash = _hash_token(token)
        now = int(time.time())
        with self._lock:
            row = self._conn().execute(
                "SELECT * FROM gateway_clients WHERE token_hash = ? AND enabled = 1",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            self._conn().execute(
                "UPDATE gateway_clients SET last_used_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            self._conn().commit()
        stored = _stored_token_from_row(row)
        return GatewayClient(
            key_id=stored.id,
            name=stored.name,
            tenant_id=stored.tenant_id,
            team_id=stored.team_id,
            user_id=stored.user_id,
            allowed_models=stored.allowed_models,
            policy_actions=normalize_policy_actions(stored.policy_actions),
            max_requests=stored.max_requests,
            max_tokens=stored.max_tokens,
            max_budget=stored.max_budget,
            budget_reset=stored.budget_reset,
        )

    def create_client(
        self,
        *,
        name: str,
        tenant_id: Optional[str] = None,
        team_id: Optional[str] = None,
        user_id: Optional[str] = None,
        allowed_models: Optional[list[str]] = None,
        policy_actions: Optional[dict[str, str]] = None,
        max_requests: Optional[int] = None,
        max_tokens: Optional[int] = None,
        max_budget: Optional[float] = None,
        budget_reset: Optional[str] = None,
    ) -> tuple[dict[str, Any], str]:
        name = name.strip()
        if not name:
            raise ValueError("Client name is required")
        raw_token = generate_gateway_token()
        client_id = _client_id()
        now = int(time.time())
        allowed = _normalize_allowed_models(allowed_models)
        policy = normalize_policy_actions(policy_actions)
        with self._lock:
            try:
                self._conn().execute(
                    """
                    INSERT INTO gateway_clients (
                        id, name, token_hash, token_prefix, enabled,
                        tenant_id, team_id, user_id, allowed_models_json, policy_actions_json,
                        max_requests, max_tokens, max_budget, budget_reset,
                        created_at, updated_at, rotated_at, last_used_at
                    )
                    VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        client_id,
                        name,
                        _hash_token(raw_token),
                        _token_prefix(raw_token),
                        _blank_to_none(tenant_id),
                        _blank_to_none(team_id),
                        _blank_to_none(user_id),
                        json.dumps(allowed, sort_keys=True),
                        json.dumps(policy, sort_keys=True),
                        max_requests,
                        max_tokens,
                        max_budget,
                        _blank_to_none(budget_reset),
                        now,
                        now,
                        now,
                    ),
                )
                self._conn().commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError("A client with that name already exists") from exc
        client = self.get_client(client_id)
        if client is None:
            raise RuntimeError("Failed to create gateway client")
        return client, raw_token

    def rotate_client(self, client_id: str) -> tuple[dict[str, Any], str]:
        raw_token = generate_gateway_token()
        now = int(time.time())
        with self._lock:
            cursor = self._conn().execute(
                """
                UPDATE gateway_clients
                SET token_hash = ?, token_prefix = ?, rotated_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (_hash_token(raw_token), _token_prefix(raw_token), now, now, client_id),
            )
            self._conn().commit()
            if cursor.rowcount != 1:
                raise KeyError("Gateway client not found")
        client = self.get_client(client_id)
        if client is None:
            raise KeyError("Gateway client not found")
        return client, raw_token

    def update_client(
        self,
        client_id: str,
        *,
        enabled: Optional[bool] = None,
        tenant_id: Optional[str] = None,
        team_id: Optional[str] = None,
        user_id: Optional[str] = None,
        allowed_models: Optional[list[str]] = None,
        policy_actions: Optional[dict[str, str]] = None,
        max_requests: Optional[int] = None,
        max_tokens: Optional[int] = None,
        max_budget: Optional[float] = None,
        budget_reset: Optional[str] = None,
    ) -> dict[str, Any]:
        existing = self.get_client(client_id)
        if existing is None:
            raise KeyError("Gateway client not found")

        updates: dict[str, Any] = {"updated_at": int(time.time())}
        if enabled is not None:
            updates["enabled"] = 1 if enabled else 0
        if tenant_id is not None:
            updates["tenant_id"] = _blank_to_none(tenant_id)
        if team_id is not None:
            updates["team_id"] = _blank_to_none(team_id)
        if user_id is not None:
            updates["user_id"] = _blank_to_none(user_id)
        if allowed_models is not None:
            updates["allowed_models_json"] = json.dumps(
                _normalize_allowed_models(allowed_models),
                sort_keys=True,
            )
        if policy_actions is not None:
            updates["policy_actions_json"] = json.dumps(
                normalize_policy_actions(policy_actions),
                sort_keys=True,
            )
        if max_requests is not None:
            updates["max_requests"] = max_requests
        if max_tokens is not None:
            updates["max_tokens"] = max_tokens
        if max_budget is not None:
            updates["max_budget"] = max_budget
        if budget_reset is not None:
            updates["budget_reset"] = _blank_to_none(budget_reset)

        assignments = ", ".join(f"{column} = ?" for column in updates)
        values = list(updates.values()) + [client_id]
        with self._lock:
            self._conn().execute(
                f"UPDATE gateway_clients SET {assignments} WHERE id = ?",
                values,
            )
            self._conn().commit()
        updated = self.get_client(client_id)
        if updated is None:
            raise KeyError("Gateway client not found")
        return updated

    def security_warnings(self) -> list[str]:
        warnings = []
        admin_password_env = getattr(
            self.config,
            "admin_password_env",
            "SENTINELGUARD_ADMIN_PASSWORD",
        )
        viewer_password_env = getattr(
            self.config,
            "admin_viewer_password_env",
            "SENTINELGUARD_VIEWER_PASSWORD",
        )
        if not os.getenv(admin_password_env):
            warnings.append(
                f"Admin dashboard is using the built-in local password. Set {admin_password_env}."
            )
        if not os.getenv(viewer_password_env):
            warnings.append(
                f"Read-only dashboard user is using the built-in local password. Set {viewer_password_env}."
            )
        return warnings

    def _seed_default_users(self) -> None:
        admin_username_env = getattr(
            self.config,
            "admin_username_env",
            "SENTINELGUARD_ADMIN_USERNAME",
        )
        admin_password_env = getattr(
            self.config,
            "admin_password_env",
            "SENTINELGUARD_ADMIN_PASSWORD",
        )
        viewer_username_env = getattr(
            self.config,
            "admin_viewer_username_env",
            "SENTINELGUARD_VIEWER_USERNAME",
        )
        viewer_password_env = getattr(
            self.config,
            "admin_viewer_password_env",
            "SENTINELGUARD_VIEWER_PASSWORD",
        )
        admin_username = os.getenv(admin_username_env, "admin")
        admin_password = os.getenv(admin_password_env, "sentinelguard")
        viewer_username = os.getenv(viewer_username_env, "viewer")
        viewer_password = os.getenv(viewer_password_env, "sentinelguard-readonly")
        now = int(time.time())
        self._insert_user_if_missing(admin_username, admin_password, ADMIN_ROLE, now)
        if viewer_username != admin_username:
            self._insert_user_if_missing(viewer_username, viewer_password, VIEWER_ROLE, now)

    def _insert_user_if_missing(
        self,
        username: str,
        password: str,
        role: str,
        created_at: int,
    ) -> None:
        with self._lock:
            existing = self._conn().execute(
                "SELECT username FROM gateway_admin_users WHERE username = ?",
                (username,),
            ).fetchone()
            if existing is not None:
                return
            self._conn().execute(
                """
                INSERT INTO gateway_admin_users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, _hash_password(password), role, created_at),
            )
            self._conn().commit()

    def _init_db(self) -> None:
        with self._lock:
            self._conn().execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_admin_users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            self._conn().execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_clients (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    token_hash TEXT NOT NULL UNIQUE,
                    token_prefix TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    tenant_id TEXT,
                    team_id TEXT,
                    user_id TEXT,
                    allowed_models_json TEXT NOT NULL,
                    policy_actions_json TEXT NOT NULL DEFAULT '{}',
                    max_requests INTEGER,
                    max_tokens INTEGER,
                    max_budget REAL,
                    budget_reset TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    rotated_at INTEGER,
                    last_used_at INTEGER
                )
                """
            )
            self._ensure_column(
                "gateway_clients",
                "policy_actions_json",
                "TEXT NOT NULL DEFAULT '{}'",
            )
            self._conn().commit()

    def _ensure_column(self, table_name: str, column_name: str, definition: str) -> None:
        columns = {
            str(row["name"])
            for row in self._conn().execute(f"PRAGMA table_info({table_name})")
        }
        if column_name not in columns:
            self._conn().execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
            )

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self, "_connection", None)
        if conn is None:
            conn = sqlite3.connect(self.path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._connection = conn
        return conn


def gateway_admin_store(config: GatewayConfig) -> GatewayAdminStore:
    """Return a cached dashboard/admin state store for the configured gateway."""
    path = _admin_state_path(config)
    if path not in _ADMIN_STORE_CACHE:
        _ADMIN_STORE_CACHE[path] = GatewayAdminStore(config)
    return _ADMIN_STORE_CACHE[path]


def generate_gateway_token(prefix: str = "sgw", nbytes: int = 32) -> str:
    """Generate a local client-facing gateway token."""
    safe_prefix = (prefix or "sgw").strip().replace("-", "_") or "sgw"
    return f"{safe_prefix}_{secrets.token_urlsafe(nbytes)}"


def _admin_state_path(config: GatewayConfig) -> str:
    configured = getattr(config, "admin_state_path", None) or config.state_path
    return str(configured or "/tmp/sentinelguard_gateway_state.sqlite3")


def _stored_token_from_row(row: sqlite3.Row) -> StoredGatewayToken:
    allowed_models = tuple(json.loads(row["allowed_models_json"] or "[]"))
    policy_actions = normalize_policy_actions(json.loads(row["policy_actions_json"] or "{}"))
    return StoredGatewayToken(
        id=str(row["id"]),
        name=str(row["name"]),
        enabled=bool(row["enabled"]),
        token_prefix=str(row["token_prefix"]),
        tenant_id=row["tenant_id"],
        team_id=row["team_id"],
        user_id=row["user_id"],
        allowed_models=allowed_models,
        policy_actions=policy_actions,
        max_requests=row["max_requests"],
        max_tokens=row["max_tokens"],
        max_budget=row["max_budget"],
        budget_reset=row["budget_reset"],
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
        rotated_at=row["rotated_at"],
        last_used_at=row["last_used_at"],
    )


def _normalize_allowed_models(values: Optional[list[str]]) -> list[str]:
    normalized = []
    for value in values or ["*"]:
        text = str(value).strip()
        if text and text not in normalized:
            normalized.append(text)
    return normalized or ["*"]


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PASSWORD_ITERATIONS,
    )
    return "pbkdf2_sha256${}${}${}".format(
        _PASSWORD_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(digest_b64.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _token_prefix(token: str) -> str:
    return f"{token[:12]}...{token[-4:]}"


def _client_id() -> str:
    return f"sgc_{secrets.token_urlsafe(12).replace('-', '_')}"


def _blank_to_none(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
