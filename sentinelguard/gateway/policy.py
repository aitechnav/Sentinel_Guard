"""Gateway policy decisions for prompt and response enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from sentinelguard.core.scanner import AggregatedResult, ScanResult
from sentinelguard.gateway.config import GatewayConfig
from sentinelguard.monitoring import scanner_category


class PolicyAction(str, Enum):
    """Actions the gateway can take after scanner evaluation."""

    ALLOW = "allow"
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
        return self.action in {PolicyAction.ALLOW, PolicyAction.REDACT}


def evaluate_prompt_policy(
    text: str,
    result: AggregatedResult,
    config: GatewayConfig,
) -> PolicyDecision:
    """Convert prompt scan results into an explicit gateway decision."""
    return _evaluate_policy(
        text,
        result,
        config,
        direction="prompt",
        block_on_fail=config.block_on_prompt_fail,
        redact_pii=config.redact_pii,
    )


def evaluate_output_policy(
    text: str,
    result: AggregatedResult,
    config: GatewayConfig,
) -> PolicyDecision:
    """Convert output scan results into an explicit gateway decision."""
    return _evaluate_policy(
        text,
        result,
        config,
        direction="output",
        block_on_fail=config.block_on_output_fail,
        redact_pii=config.redact_output_pii,
    )


def _evaluate_policy(
    text: str,
    result: AggregatedResult,
    config: GatewayConfig,
    *,
    direction: str,
    block_on_fail: bool,
    redact_pii: bool,
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
    if redact_pii and "pii" in categories:
        if sanitized_text and sanitized_text != text:
            reason_codes.append("pii_redacted")
        else:
            redacted_text = _redact_pii(text)
            if redacted_text != text:
                sanitized_text = redacted_text
                reason_codes.append("pii_redacted")
            else:
                sanitized_text = None
                reason_codes.append("pii_redaction_unavailable")

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
            categories.add(scanner_category(scan.scanner_name))
    return categories


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


def _dedupe(values: List[str]) -> List[str]:
    return list(dict.fromkeys(values))
