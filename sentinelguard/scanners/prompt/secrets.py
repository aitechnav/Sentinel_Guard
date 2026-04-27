"""Secrets detection scanner.

Detects API keys, tokens, passwords, and other credentials in text
using three detection methods:
1. Vendor-specific patterns (AWS, GitHub, Stripe, etc.)
2. Generic keyword + value patterns (any password=, key=, token=, etc.)
3. High-entropy string detection (catches unknown/custom secrets)
"""

from __future__ import annotations

import math
import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

# ── Vendor-specific patterns ──
VENDOR_PATTERNS = {
    "aws_access_key": re.compile(r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])"),
    "aws_secret_key": re.compile(r"(?<![A-Za-z0-9/+=])[0-9a-zA-Z/+=]{40}(?![A-Za-z0-9/+=])"),
    "github_token": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
    "github_fine_grained": re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
    "openai_api_key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "anthropic_api_key": re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),
    "slack_token": re.compile(r"xox[boaprs]-[0-9A-Za-z\-]{10,250}"),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"
    ),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "stripe_key": re.compile(r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}"),
    "sendgrid_api_key": re.compile(r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}"),
    "twilio_api_key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "mailgun_api_key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "azure_key": re.compile(r"(?i)(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,}"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "private_key": re.compile(r"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "ssh_public_key": re.compile(r"ssh-(?:rsa|ed25519|dss|ecdsa)\s+AAAA[0-9A-Za-z+/]+"),
    "connection_string": re.compile(r"(?i)(?:mongodb|postgres|mysql|redis|amqp|sqlite)://[^\s]+"),
}

# ── Generic keyword patterns (catches ANY vendor) ──
# These match: keyword = value, keyword: value, keyword="value", etc.
KEYWORD_PATTERNS = {
    "generic_password": re.compile(
        r"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?"
    ),
    "generic_api_key": re.compile(
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|access[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
    "generic_secret": re.compile(
        r"(?i)(?:secret[_-]?key|client[_-]?secret|app[_-]?secret|private[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
    "generic_token": re.compile(
        r"(?i)(?:token|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|session[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
    "generic_credential": re.compile(
        r"(?i)(?:credential|auth|authorization|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
    "generic_username": re.compile(
        r"(?i)(?:username|user[_-]?name|user[_-]?id|login)\s*[:=]\s*['\"]?([^\s'\"]{3,})['\"]?"
    ),
    "bearer_header": re.compile(
        r"(?i)(?:bearer|authorization)\s*[:=]?\s*['\"]?([A-Za-z0-9_\-./+=]{20,})['\"]?"
    ),
    "database_password": re.compile(
        r"(?i)(?:db[_-]?pass|db[_-]?password|database[_-]?password|mysql[_-]?pwd|pg[_-]?password)\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?"
    ),
    "encryption_key": re.compile(
        r"(?i)(?:encrypt[_-]?key|encryption[_-]?key|aes[_-]?key|signing[_-]?key|hmac[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
}

# Sensitivity tiers
HIGH_SENSITIVITY = {
    "aws_access_key", "aws_secret_key", "private_key",
    "connection_string", "stripe_key", "azure_key",
    "generic_password", "generic_secret", "database_password",
    "encryption_key",
}
MEDIUM_SENSITIVITY = {
    "github_token", "github_fine_grained", "openai_api_key",
    "anthropic_api_key", "slack_token", "jwt_token", "ssh_public_key",
    "sendgrid_api_key", "twilio_api_key", "mailgun_api_key",
    "google_api_key", "bearer_header", "generic_api_key",
    "generic_token", "generic_credential",
}
LOW_SENSITIVITY = {
    "generic_username", "high_entropy_hex", "high_entropy_base64",
}


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# Regex to find candidate high-entropy strings (quoted or standalone long tokens)
_HEX_CANDIDATE = re.compile(r"\b([0-9a-fA-F]{16,})\b")
_BASE64_CANDIDATE = re.compile(r"\b([A-Za-z0-9+/=]{20,})\b")

# Entropy thresholds (from detect-secrets)
HEX_ENTROPY_THRESHOLD = 3.0
BASE64_ENTROPY_THRESHOLD = 4.5

# Common words/patterns to exclude from entropy checks
_ENTROPY_EXCLUDE = re.compile(
    r"(?i)^(the|and|for|are|but|not|you|all|can|had|her|was|one|our|"
    r"function|return|import|class|def|var|let|const|true|false|null|"
    r"undefined|string|number|boolean|object|array|https?|www|com|org|"
    r"0{16,}|f{16,}|a{16,}|1{16,})$"
)


@register_scanner
class SecretsScanner(PromptScanner):
    """Detects API keys, tokens, passwords, and credentials.

    Uses three detection methods:
    1. Vendor-specific patterns (AWS, GitHub, Stripe, etc.)
    2. Generic keyword patterns (password=, key=, token=, etc.)
    3. High-entropy string detection (catches unknown secrets)

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        secret_types: List of secret types to check. None = all.
        detect_entropy: Enable high-entropy string detection. Default True.
    """

    scanner_name: ClassVar[str] = "secrets"

    def __init__(
        self,
        threshold: float = 0.5,
        secret_types: Optional[List[str]] = None,
        detect_entropy: bool = True,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.secret_types = secret_types
        self.detect_entropy = detect_entropy

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found_secrets: Dict[str, int] = {}

        # Method 1: Vendor-specific patterns
        for secret_type, pattern in VENDOR_PATTERNS.items():
            if self.secret_types and secret_type not in self.secret_types:
                continue
            if pattern.findall(text):
                found_secrets[secret_type] = len(pattern.findall(text))

        # Method 2: Generic keyword patterns
        for secret_type, pattern in KEYWORD_PATTERNS.items():
            if self.secret_types and secret_type not in self.secret_types:
                continue
            if pattern.findall(text):
                found_secrets[secret_type] = len(pattern.findall(text))

        # Method 3: High-entropy string detection
        if self.detect_entropy:
            for match in _HEX_CANDIDATE.finditer(text):
                candidate = match.group(1)
                if _ENTROPY_EXCLUDE.match(candidate):
                    continue
                if _shannon_entropy(candidate) > HEX_ENTROPY_THRESHOLD:
                    found_secrets["high_entropy_hex"] = found_secrets.get("high_entropy_hex", 0) + 1

            for match in _BASE64_CANDIDATE.finditer(text):
                candidate = match.group(1)
                if _ENTROPY_EXCLUDE.match(candidate):
                    continue
                if len(candidate) >= 20 and _shannon_entropy(candidate) > BASE64_ENTROPY_THRESHOLD:
                    found_secrets["high_entropy_base64"] = found_secrets.get("high_entropy_base64", 0) + 1

        if not found_secrets:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"secrets_found": {}},
            )

        max_score = 0.0
        for secret_type in found_secrets:
            if secret_type in HIGH_SENSITIVITY:
                max_score = max(max_score, 1.0)
            elif secret_type in MEDIUM_SENSITIVITY:
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
