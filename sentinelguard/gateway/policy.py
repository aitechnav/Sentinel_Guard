"""Gateway policy decisions for prompt and response enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Mapping, Optional

from sentinelguard.core.scanner import AggregatedResult, ScanResult
from sentinelguard.gateway.config import GatewayConfig
from sentinelguard.monitoring import scanner_category


class PolicyAction(str, Enum):
    """Actions the gateway can take after scanner evaluation."""

    ALLOW = "allow"
    AUDIT = "audit"
    REDACT = "redact"
    BLOCK = "block"
    REVIEW = "review"


@dataclass(frozen=True)
class PolicyDecision:
    """Structured gateway decision produced from scanner results."""

    action: PolicyAction
    direction: str
    reason_codes: List[str] = field(default_factory=list)
    failed_scanners: List[str] = field(default_factory=list)
    warning_scanners: List[str] = field(default_factory=list)
    sanitized_text: Optional[str] = None
    route_constraint: str = "any"
    highest_risk: str = "low"

    @property
    def allowed(self) -> bool:
        return self.action in {PolicyAction.ALLOW, PolicyAction.AUDIT, PolicyAction.REDACT}


def evaluate_prompt_policy(
    text: str,
    result: AggregatedResult,
    config: GatewayConfig,
    client_policy: Optional[Mapping[str, str]] = None,
) -> PolicyDecision:
    """Convert prompt scan results into an explicit gateway decision."""
    return _evaluate_policy(
        text,
        result,
        config,
        direction="prompt",
        block_on_fail=config.block_on_prompt_fail,
        redact_pii=config.redact_pii,
        client_policy=client_policy,
    )


def evaluate_output_policy(
    text: str,
    result: AggregatedResult,
    config: GatewayConfig,
    client_policy: Optional[Mapping[str, str]] = None,
) -> PolicyDecision:
    """Convert output scan results into an explicit gateway decision."""
    return _evaluate_policy(
        text,
        result,
        config,
        direction="output",
        block_on_fail=config.block_on_output_fail,
        redact_pii=config.redact_output_pii,
        client_policy=client_policy,
    )


def _evaluate_policy(
    text: str,
    result: AggregatedResult,
    config: GatewayConfig,
    *,
    direction: str,
    block_on_fail: bool,
    redact_pii: bool,
    client_policy: Optional[Mapping[str, str]],
) -> PolicyDecision:
    categories = _failed_categories(result)
    reason_codes = _reason_codes(result)
    sensitive_categories = {"pii", "secret"}
    route_constraint = (
        "private"
        if (
            direction == "prompt"
            and (
                (config.route_pii_to_private_provider and "pii" in categories)
                or (config.route_sensitive_to_private_provider and categories & sensitive_categories)
            )
        )
        else "any"
    )

    sanitized_text = result.sanitized_output
    actions = _category_actions(
        categories,
        result,
        client_policy,
        block_on_fail=block_on_fail,
        redact_pii=redact_pii,
    )
    if any(action == PolicyAction.REDACT for action in actions.values()):
        if sanitized_text and sanitized_text != text:
            reason_codes.append(_redaction_reason(categories))
        else:
            redacted_text = _redact_sensitive_text(text, categories)
            if redacted_text != text:
                sanitized_text = redacted_text
                reason_codes.append(_redaction_reason(categories))
            else:
                sanitized_text = None
                reason_codes.append("redaction_unavailable")

    reason_codes.extend(
        f"policy:{category}_{action.value}"
        for category, action in sorted(actions.items())
        if action != PolicyAction.ALLOW
    )

    if any(action == PolicyAction.BLOCK for action in actions.values()):
        return PolicyDecision(
            action=PolicyAction.BLOCK,
            direction=direction,
            reason_codes=_dedupe(reason_codes),
            failed_scanners=list(result.failed_scanners),
            warning_scanners=list(result.warning_scanners),
            route_constraint=route_constraint,
            highest_risk=result.highest_risk.value,
        )

    if sanitized_text and sanitized_text != text and any(
        action == PolicyAction.REDACT for action in actions.values()
    ):
        return PolicyDecision(
            action=PolicyAction.REDACT,
            direction=direction,
            reason_codes=_dedupe(reason_codes),
            failed_scanners=list(result.failed_scanners),
            warning_scanners=list(result.warning_scanners),
            sanitized_text=sanitized_text,
            route_constraint=route_constraint,
            highest_risk=result.highest_risk.value,
        )

    if any(action == PolicyAction.REDACT for action in actions.values()):
        return PolicyDecision(
            action=PolicyAction.BLOCK,
            direction=direction,
            reason_codes=_dedupe(reason_codes or ["redaction_unavailable"]),
            failed_scanners=list(result.failed_scanners),
            warning_scanners=list(result.warning_scanners),
            route_constraint=route_constraint,
            highest_risk=result.highest_risk.value,
        )

    if any(action == PolicyAction.AUDIT for action in actions.values()):
        return PolicyDecision(
            action=PolicyAction.AUDIT,
            direction=direction,
            reason_codes=_dedupe(reason_codes),
            failed_scanners=list(result.failed_scanners),
            warning_scanners=list(result.warning_scanners),
            route_constraint=route_constraint,
            highest_risk=result.highest_risk.value,
        )

    if categories and all(action == PolicyAction.ALLOW for action in actions.values()):
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            direction=direction,
            reason_codes=_dedupe(reason_codes),
            failed_scanners=list(result.failed_scanners),
            warning_scanners=list(result.warning_scanners),
            route_constraint=route_constraint,
            highest_risk=result.highest_risk.value,
        )

    if not result.is_valid and block_on_fail:
        if "pii" in categories and categories <= {"pii"} and sanitized_text:
            return PolicyDecision(
                action=PolicyAction.REDACT,
                direction=direction,
                reason_codes=_dedupe(reason_codes),
                failed_scanners=list(result.failed_scanners),
                warning_scanners=list(result.warning_scanners),
                sanitized_text=sanitized_text,
                route_constraint=route_constraint,
                highest_risk=result.highest_risk.value,
            )
        return PolicyDecision(
            action=PolicyAction.BLOCK,
            direction=direction,
            reason_codes=_dedupe(reason_codes),
            failed_scanners=list(result.failed_scanners),
            warning_scanners=list(result.warning_scanners),
            route_constraint=route_constraint,
            highest_risk=result.highest_risk.value,
        )

    if sanitized_text and sanitized_text != text:
        return PolicyDecision(
            action=PolicyAction.REDACT,
            direction=direction,
            reason_codes=_dedupe(reason_codes or ["sanitized"]),
            failed_scanners=list(result.failed_scanners),
            warning_scanners=list(result.warning_scanners),
            sanitized_text=sanitized_text,
            route_constraint=route_constraint,
            highest_risk=result.highest_risk.value,
        )

    return PolicyDecision(
        action=PolicyAction.ALLOW,
        direction=direction,
        reason_codes=_dedupe(reason_codes),
        failed_scanners=list(result.failed_scanners),
        warning_scanners=list(result.warning_scanners),
        route_constraint=route_constraint,
        highest_risk=result.highest_risk.value,
    )


def _failed_categories(result: AggregatedResult) -> set[str]:
    categories = set()
    for scan in result.results:
        if not scan.is_valid:
            category = scanner_category(scan.scanner_name)
            categories.add(category)
            if category == "pii":
                categories.update(_sensitive_data_subcategories(scan))
    return categories


def _category_actions(
    categories: set[str],
    result: AggregatedResult,
    client_policy: Optional[Mapping[str, str]],
    *,
    block_on_fail: bool,
    redact_pii: bool,
) -> dict[str, PolicyAction]:
    policy = _normalize_client_policy(client_policy)
    return {
        category: _policy_action_for_category(
            category,
            result,
            policy,
            block_on_fail=block_on_fail,
            redact_pii=redact_pii,
        )
        for category in categories
    }


def _policy_action_for_category(
    category: str,
    result: AggregatedResult,
    policy: Mapping[str, PolicyAction],
    *,
    block_on_fail: bool,
    redact_pii: bool,
) -> PolicyAction:
    if category in policy:
        return policy[category]
    if category in {"pii", "pci", "phi"} and redact_pii:
        return PolicyAction.REDACT
    if result.is_valid:
        return PolicyAction.ALLOW
    return PolicyAction.BLOCK if block_on_fail else PolicyAction.ALLOW


def _normalize_client_policy(
    policy: Optional[Mapping[str, str]],
) -> dict[str, PolicyAction]:
    normalized = {}
    for raw_category, raw_action in (policy or {}).items():
        category = str(raw_category or "").strip().lower().replace("-", "_")
        category = {"secrets": "secret", "prompt_attack": "attack"}.get(category, category)
        action = str(raw_action or "").strip().lower().replace("-", "_")
        action = {
            "audit_only": "audit",
            "log": "audit",
            "log_only": "audit",
            "mask": "redact",
            "monitor": "audit",
            "sanitize": "redact",
            "warn": "audit",
        }.get(action, action)
        if category in {"attack", "secret", "pii", "pci", "phi", "other"} and action in {
            "allow",
            "audit",
            "block",
            "redact",
        }:
            normalized[category] = PolicyAction(action)
    return normalized


def _sensitive_data_subcategories(scan: ScanResult) -> set[str]:
    entity_types = {str(entity).upper() for entity in scan.details.get("entity_types", []) or []}
    found = set()
    if entity_types & {"CREDIT_CARD", "IBAN_CODE", "US_BANK_NUMBER", "CRYPTO"}:
        found.add("pci")
    if entity_types & {"MEDICAL_LICENSE", "UK_NHS", "US_NPI"}:
        found.add("phi")
    return found


def _reason_codes(result: AggregatedResult) -> List[str]:
    codes = []
    for scan in result.results:
        if not scan.is_valid:
            codes.append(_reason_code(scan))
    return codes


def _reason_code(scan: ScanResult) -> str:
    category = scanner_category(scan.scanner_name)
    return f"{category}:{scan.scanner_name}"


def _redact_pii(text: str) -> str:
    try:
        from sentinelguard.pii import PIIDetector, PIIAnonymizer

        detector = PIIDetector(score_threshold=0.3)
        entities = detector.detect(text)
        if not entities:
            return text
        return PIIAnonymizer(default_strategy="replace").anonymize(text, entities).text
    except Exception:
        return text


def _redact_sensitive_text(text: str, categories: set[str]) -> str:
    if categories & {"pii", "pci", "phi"}:
        return _redact_pii(text)
    return text


def _redaction_reason(categories: set[str]) -> str:
    if "pii" in categories:
        return "pii_redacted"
    return "content_redacted"


def _dedupe(values: List[str]) -> List[str]:
    return list(dict.fromkeys(values))
