"""Secrets detection scanner.

Detects API keys, tokens, passwords, and other credentials in text
using pattern matching for 12+ secret types.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])"),
    "aws_secret_key": re.compile(
        r"(?<![A-Za-z0-9/+=])[0-9a-zA-Z/+=]{40}(?![A-Za-z0-9/+=])"
    ),
    "github_token": re.compile(
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"
    ),
    "github_fine_grained": re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
    "openai_api_key": re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"),
    "slack_token": re.compile(r"xox[boaprs]-[0-9A-Za-z\-]{10,250}"),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"
    ),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "stripe_key": re.compile(r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}"),
    "jwt_token": re.compile(
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    ),
    "private_key": re.compile(
        r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "generic_api_key": re.compile(
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"
    ),
    "generic_password": re.compile(
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"
    ),
    "generic_secret": re.compile(
        r"(?i)(?:secret|token|credential|auth)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"
    ),
    "connection_string": re.compile(
        r"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s]+"
    ),
}


@register_scanner
class SecretsScanner(PromptScanner):
    """Detects API keys, tokens, passwords, and credentials.

    Scans for 12+ types of secrets including AWS, GitHub, OpenAI, Stripe,
    Slack, Google, and generic patterns.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        secret_types: List of secret types to check. None = all.
    """

    scanner_name: ClassVar[str] = "secrets"

    def __init__(
        self,
        threshold: float = 0.5,
        secret_types: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.secret_types = secret_types

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found_secrets: Dict[str, int] = {}

        patterns = SECRET_PATTERNS
        if self.secret_types:
            patterns = {
                k: v for k, v in SECRET_PATTERNS.items()
                if k in self.secret_types
            }

        for secret_type, pattern in patterns.items():
            matches = pattern.findall(text)
            if matches:
                found_secrets[secret_type] = len(matches)

        if not found_secrets:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"secrets_found": {}},
            )

        # High-sensitivity secrets get higher scores
        high_sensitivity = {
            "aws_access_key", "aws_secret_key", "private_key",
            "connection_string", "stripe_key",
        }
        medium_sensitivity = {
            "github_token", "github_fine_grained", "openai_api_key",
            "slack_token", "jwt_token",
        }

        max_score = 0.0
        for secret_type in found_secrets:
            if secret_type in high_sensitivity:
                max_score = max(max_score, 1.0)
            elif secret_type in medium_sensitivity:
                max_score = max(max_score, 0.8)
            else:
                max_score = max(max_score, 0.6)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.CRITICAL if max_score >= 0.8 else RiskLevel.HIGH,
            details={
                "secrets_found": found_secrets,
                "secret_types": list(found_secrets.keys()),
                "total_secrets": sum(found_secrets.values()),
            },
        )
