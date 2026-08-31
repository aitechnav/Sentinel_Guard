"""Prompt-aware model routing for the SentinelGuard gateway."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

from sentinelguard.gateway.config import GatewayConfig, ProviderConfig


COMPLEXITY_KEYWORDS = (
    "analyze",
    "analysis",
    "architecture",
    "benchmark",
    "compare",
    "debug",
    "derive",
    "design",
    "explain why",
    "formal",
    "migration",
    "optimize",
    "plan",
    "proof",
    "prove",
    "reason",
    "refactor",
    "root cause",
    "security review",
    "test plan",
    "threat model",
    "tradeoff",
)

CODE_OR_DATA_MARKERS = (
    "```",
    "traceback",
    "stack trace",
    "exception:",
    "def ",
    "class ",
    "function ",
    "import ",
    "select ",
    "create table",
    "kubectl ",
    "terraform ",
    "docker ",
)


@dataclass(frozen=True)
class ComplexityRouteDecision:
    """Model routing result for one gateway request."""

    model: Optional[str]
    original_model: str
    route_type: str
    score: float = 0.0
    reasons: tuple[str, ...] = ()
    applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "original_model": self.original_model,
            "route_type": self.route_type,
            "score": round(self.score, 3),
            "reasons": list(self.reasons),
            "applied": self.applied,
        }


def resolve_complexity_route(
    payload: Mapping[str, Any],
    prompt_text: str,
    config: GatewayConfig,
    *,
    route_constraint: str = "any",
    highest_risk: str = "low",
) -> ComplexityRouteDecision:
    """Choose a public model alias for a prompt when complexity routing is enabled."""
    requested_model = str(payload.get("model") or "").strip()
    router = config.complexity_router
    if not router.enabled:
        return ComplexityRouteDecision(
            model=requested_model or None,
            original_model=requested_model,
            route_type="disabled",
        )

    if _normalize_strategy(router.strategy) != "rule-based":
        return ComplexityRouteDecision(
            model=requested_model or None,
            original_model=requested_model,
            route_type="unsupported_strategy",
            reasons=(f"unsupported_strategy:{router.strategy}",),
        )

    auto_requested = _is_auto_model(requested_model, config)
    if route_constraint == "private":
        target_model = router.private_model or _first_configured_model(config, private=True)
        if target_model:
            return ComplexityRouteDecision(
                model=target_model,
                original_model=requested_model,
                route_type="private",
                score=1.0,
                reasons=("private_route_constraint",),
                applied=target_model != requested_model,
            )

    if router.preserve_explicit_model and requested_model and not auto_requested:
        return ComplexityRouteDecision(
            model=requested_model,
            original_model=requested_model,
            route_type="explicit",
            reasons=("explicit_model_preserved",),
        )

    score, reasons = score_prompt_complexity(payload, prompt_text, highest_risk=highest_risk)
    threshold = max(0.0, min(1.0, float(router.complexity_threshold)))
    if score >= threshold:
        target_model = (
            router.complex_model
            or router.default_model
            or _first_configured_model(config, private=False)
        )
        route_type = "complex"
    else:
        target_model = (
            router.simple_model
            or router.default_model
            or _first_configured_model(config, private=False)
        )
        route_type = "simple"

    if not target_model:
        return ComplexityRouteDecision(
            model=requested_model or None,
            original_model=requested_model,
            route_type="unresolved",
            score=score,
            reasons=tuple(reasons + ["no_target_model_configured"]),
        )

    return ComplexityRouteDecision(
        model=target_model,
        original_model=requested_model,
        route_type=route_type,
        score=score,
        reasons=tuple(reasons),
        applied=target_model != requested_model,
    )


def apply_complexity_route(
    payload: Mapping[str, Any],
    decision: ComplexityRouteDecision,
) -> dict[str, Any]:
    """Return a copy of the payload with the routed model alias applied."""
    updated = dict(payload)
    if decision.applied and decision.model:
        updated["model"] = decision.model
    return updated


def score_prompt_complexity(
    payload: Mapping[str, Any],
    prompt_text: str,
    *,
    highest_risk: str = "low",
) -> tuple[float, list[str]]:
    """Score prompt complexity with deterministic, low-latency signals."""
    text = prompt_text or ""
    lower = text.lower()
    word_count = len(text.split())
    char_count = len(text)
    score = 0.0
    reasons: list[str] = []

    if char_count >= 3000:
        score += 0.45
        reasons.append("long_prompt")
    elif char_count >= 1200:
        score += 0.30
        reasons.append("medium_long_prompt")
    elif char_count >= 600:
        score += 0.15
        reasons.append("moderate_prompt_length")

    if word_count >= 600:
        score += 0.30
        reasons.append("many_words")
    elif word_count >= 200:
        score += 0.20
        reasons.append("multi_paragraph_request")
    elif word_count >= 80:
        score += 0.10
        reasons.append("detailed_request")

    keyword_hits = [keyword for keyword in COMPLEXITY_KEYWORDS if keyword in lower]
    if keyword_hits:
        score += min(0.45, len(keyword_hits) * 0.08)
        reasons.append("complexity_keywords")
    if len(keyword_hits) >= 4:
        score += 0.15
        reasons.append("multiple_complexity_signals")

    if any(marker in lower for marker in CODE_OR_DATA_MARKERS):
        score += 0.22
        reasons.append("code_or_data_context")

    messages = payload.get("messages")
    if isinstance(messages, list):
        if len(messages) >= 10:
            score += 0.18
            reasons.append("long_conversation")
        elif len(messages) >= 5:
            score += 0.10
            reasons.append("multi_turn_context")

    if payload.get("tools") or payload.get("functions"):
        score += 0.18
        reasons.append("tool_calling_request")

    max_tokens = _numeric(payload.get("max_tokens"))
    if max_tokens >= 4000:
        score += 0.18
        reasons.append("large_completion_budget")
    elif max_tokens >= 1500:
        score += 0.10
        reasons.append("larger_completion_budget")

    risk = (highest_risk or "low").strip().lower()
    if risk == "critical":
        score += 0.20
        reasons.append("critical_scanner_risk")
    elif risk == "high":
        score += 0.14
        reasons.append("high_scanner_risk")
    elif risk == "medium":
        score += 0.08
        reasons.append("medium_scanner_risk")

    if lower.count("?") >= 3:
        score += 0.06
        reasons.append("multiple_questions")

    return min(1.0, score), reasons


def is_auto_model(model: str, config: GatewayConfig) -> bool:
    """Return True when a requested model name should be resolved by the gateway."""
    return _is_auto_model(model, config)


def _is_auto_model(model: str, config: GatewayConfig) -> bool:
    normalized_model = (model or "").strip().lower()
    configured_names = config.complexity_router.auto_model_names or []
    auto_model_names = (
        [configured_names] if isinstance(configured_names, str) else configured_names
    )
    return normalized_model in {name.strip().lower() for name in auto_model_names}


def _normalize_strategy(strategy: str) -> str:
    return (strategy or "rule-based").strip().lower().replace("_", "-")


def _first_configured_model(config: GatewayConfig, *, private: bool) -> Optional[str]:
    for provider in config.providers:
        if not provider.enabled:
            continue
        if private and not provider.private:
            continue
        if not private and provider.private:
            continue
        model = _provider_public_model(provider)
        if model:
            return model
    return None


def _provider_public_model(provider: ProviderConfig) -> Optional[str]:
    return provider.model_name or provider.upstream_model


def _numeric(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
