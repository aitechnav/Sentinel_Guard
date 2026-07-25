"""Secrets detection scanner.

Detects API keys, tokens, passwords, and other credentials in text.

Detection methods (in order):
1. detect-secrets library (Yelp) — industry-standard secrets detection with
   20+ built-in plugins (AWS, GitHub, Stripe, high-entropy, keyword, etc.)
2. Vendor-specific regex patterns (fallback if detect-secrets unavailable)
3. Generic keyword + value patterns (password=, key=, token=, etc.)
4. Contextual credential disclosure inference ("my password <value>")
5. Optional local Hugging Face zero-shot model for ambiguous disclosure context
"""

from __future__ import annotations

import logging
import math
import re
from typing import Any, ClassVar, Dict, List, Optional, Union

from sentinelguard.core.scanner import (
    BaseScanner,
    ScannerType,
    RiskLevel,
    ScanResult,
    register_scanner,
)
from sentinelguard.models import resolve_model

logger = logging.getLogger(__name__)

# ── Vendor-specific patterns ──
VENDOR_PATTERNS = {
    "aws_access_key": re.compile(r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])"),
    "aws_secret_key": re.compile(r"(?<![A-Za-z0-9/+=])[0-9a-zA-Z/+=]{40}(?![A-Za-z0-9/+=])"),
    "github_token": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
    "github_fine_grained": re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
    "openai_api_key": re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
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
        r"(?i)(?:\w*password|\w*passwd|\w*pwd|\w*pass)\s*(?:is|:|=)\s*['\"]?([^\s'\"]{4,})['\"]?"
    ),
    "generic_api_key": re.compile(
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|access[_-]?key)\s*(?:is|:|=)\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
    "generic_secret": re.compile(
        r"(?i)(?:secret[_-]?key|client[_-]?secret|app[_-]?secret|private[_-]?key)\s*(?:is|:|=)\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
    "generic_token": re.compile(
        r"(?i)(?:token|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|session[_-]?token)\s*(?:is|:|=)\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
    "generic_credential": re.compile(
        r"(?i)(?:credential|auth|authorization|secret)\s*(?:is|:|=)\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
    "generic_username": re.compile(
        r"(?i)(?:username|user[_-]?name|user[_-]?id|login)\s*[:=]\s*['\"]?([^\s'\"]{3,})['\"]?"
    ),
    "bearer_header": re.compile(
        r"(?i)(?:bearer|authorization)\s*[:=]?\s*['\"]?([A-Za-z0-9_\-./+=]{20,})['\"]?"
    ),
    "encryption_key": re.compile(
        r"(?i)(?:encrypt[_-]?key|encryption[_-]?key|aes[_-]?key|signing[_-]?key|hmac[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{8,})['\"]?"
    ),
}

# Contextual disclosure patterns catch natural chat phrasing that is not shaped
# like a vendor token, assignment, or header. Examples:
#   "my password hunter2!"
#   "admin password @@!E@#@#"
#   "api token is !@ASASD"
CONTEXTUAL_SECRET_PATTERN = re.compile(r"""(?ix)
    \b(?P<label>
        (?:admin|database|db|root|service|app|client|api|auth|access|refresh|session|bearer)?[\s_-]*
        (?:password|passwd|pwd|passphrase|api[\s_-]?key|api[\s_-]?token|access[\s_-]?key|
           access[\s_-]?token|auth[\s_-]?token|refresh[\s_-]?token|session[\s_-]?token|
           bearer[\s_-]?token|client[\s_-]?secret|secret[\s_-]?key|private[\s_-]?key|
           credential|credentials|creds|secret|token)
    )\b
    (?:
        \s*(?P<symbol_connector>[=:])
        |
        \s+(?P<word_connector>is|are|was|were|as|to|for|value|equals?)
    )?
    \s+
    (?P<value>
        "[^"\r\n]{4,}" |
        '[^'\r\n]{4,}' |
        `[^`\r\n]{4,}` |
        [^"'`\s,;]{4,}
    )
    """)

_SECRETS_MODEL_ID = "valhalla/distilbart-mnli-12-1"

MODEL_SECRET_LABELS = [
    "credential or secret disclosure",
    "password or passphrase disclosure",
    "api key or token disclosure",
    "private key or access credential disclosure",
]

# Sensitivity tiers
HIGH_SENSITIVITY = {
    "aws_access_key",
    "aws_secret_key",
    "private_key",
    "connection_string",
    "stripe_key",
    "azure_key",
    "generic_password",
    "generic_secret",
    "encryption_key",
    "contextual_password",
    "contextual_secret",
    "model_contextual_secret",
}
MEDIUM_SENSITIVITY = {
    "github_token",
    "github_fine_grained",
    "openai_api_key",
    "anthropic_api_key",
    "slack_token",
    "jwt_token",
    "ssh_public_key",
    "sendgrid_api_key",
    "twilio_api_key",
    "mailgun_api_key",
    "google_api_key",
    "bearer_header",
    "generic_api_key",
    "generic_token",
    "generic_credential",
    "contextual_api_key",
    "contextual_token",
    "contextual_credential",
}
LOW_SENSITIVITY = {
    "generic_username",
    "high_entropy_hex",
    "high_entropy_base64",
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

_CONTEXTUAL_PLACEHOLDER_VALUES = {
    "hidden",
    "masked",
    "none",
    "null",
    "redacted",
    "unknown",
}

_CONTEXTUAL_SAFE_VALUES = {
    "again",
    "appears",
    "best",
    "can",
    "change",
    "changed",
    "check",
    "create",
    "debug",
    "default",
    "does",
    "doesnt",
    "doesn't",
    "example",
    "expired",
    "expires",
    "field",
    "forgot",
    "help",
    "invalid",
    "issue",
    "limit",
    "login",
    "manager",
    "must",
    "not",
    "please",
    "policy",
    "present",
    "prompt",
    "requirements",
    "reset",
    "rotate",
    "rotated",
    "rotation",
    "rules",
    "secret",
    "should",
    "token",
    "true",
    "false",
    "value",
    "work",
    "working",
    "wrong",
}

_CONTEXTUAL_TRAILING_PUNCT = ".,;:!?)]}"


def _redact_value(value: str) -> str:
    """Return a non-sensitive preview suitable for scan details."""
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def _normalize_contextual_value(value: str) -> str:
    """Strip wrappers and sentence punctuation from a contextual value."""
    value = value.strip().strip("\"'`")
    return value.rstrip(_CONTEXTUAL_TRAILING_PUNCT)


def _is_safe_secret_value(value: str) -> bool:
    """Return True for benign words/placeholders commonly found near secret terms."""
    value = _normalize_contextual_value(value)
    lower = value.lower()
    return (
        lower in _CONTEXTUAL_PLACEHOLDER_VALUES
        or lower in _CONTEXTUAL_SAFE_VALUES
        or bool(re.fullmatch(r"<[^>]+>", value))
    )


def _contextual_secret_type(label: str) -> str:
    normalized = re.sub(r"[\s_-]+", "_", label.lower())
    if any(part in normalized for part in ("password", "passwd", "pwd", "passphrase")):
        return "contextual_password"
    if "api_key" in normalized or "access_key" in normalized or "private_key" in normalized:
        return "contextual_api_key"
    if "secret" in normalized:
        return "contextual_secret"
    if "credential" in normalized or "creds" in normalized:
        return "contextual_credential"
    return "contextual_token"


def _looks_like_contextual_secret(label: str, value: str, has_connector: bool = False) -> bool:
    """Infer whether a nearby value is credential-like enough to block.

    This intentionally favors explicit credential context over pure entropy.
    It still rejects common non-secret words so phrases like "password reset"
    or "token limit" are not treated as leaks.
    """
    value = _normalize_contextual_value(value)
    if len(value) < 4:
        return False

    if _is_safe_secret_value(value) and not has_connector:
        return False

    has_letter = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_symbol = any(not c.isalnum() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)

    label_type = _contextual_secret_type(label)
    if label_type == "contextual_password":
        return True

    # Tokens/keys/secrets are usually non-dictionary-looking. This catches
    # values such as "!@ASASD" while avoiding "token limit" or "secret policy".
    return (
        (has_symbol and (has_letter or has_digit or len(value) >= 6))
        or (has_digit and has_letter and len(value) >= 6)
        or (has_upper and has_lower and len(value) >= 8)
        or _shannon_entropy(value) >= 3.0
    )


def _sanitize_text(text: str, matches: List[Dict[str, Any]]) -> str:
    sanitized = text
    for match in sorted(matches, key=lambda m: m["start"], reverse=True):
        replacement = f"<SECRET:{match['type']}>"
        sanitized = sanitized[: match["start"]] + replacement + sanitized[match["end"] :]
    return sanitized


@register_scanner
class SecretsScanner(BaseScanner):
    """Detects API keys, tokens, passwords, and credentials.

    Primary detection via detect-secrets (Yelp) with 20+ plugins.
    Falls back to built-in regex patterns if detect-secrets is unavailable.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        secret_types: List of secret types to check. None = all.
        detect_entropy: Enable high-entropy string detection. Default True.
        model_weight: How much model-only findings contribute to score. Default 0.35.
        model_threshold: Minimum model confidence for a model-only finding. Default 0.8.
        use_model: "auto" uses background-warmed local model if ready, True loads
            synchronously, False disables model scoring.
    """

    scanner_name: ClassVar[str] = "secrets"
    scanner_type: ClassVar[ScannerType] = ScannerType.BOTH

    def __init__(
        self,
        threshold: float = 0.5,
        secret_types: Optional[List[str]] = None,
        detect_entropy: bool = True,
        redact_details: bool = True,
        model_weight: float = 0.35,
        model_threshold: float = 0.8,
        use_model: Union[bool, str] = "auto",
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.secret_types = secret_types
        self.detect_entropy = detect_entropy
        self.redact_details = redact_details
        self.model_weight = max(0.0, min(1.0, model_weight))
        self.model_threshold = max(0.0, min(1.0, model_threshold))
        self.use_model = use_model
        self._detect_secrets_available = None
        self._model = None

    def _load_model(self) -> None:
        self._model = resolve_model(self.scanner_name, self.use_model)

    def _try_detect_secrets(self, text: str) -> tuple[Dict[str, int], List[Dict[str, Any]]]:
        """Use detect-secrets library for primary detection."""
        if self._detect_secrets_available is False:
            return {}, []

        try:
            from detect_secrets.core.secrets_collection import SecretsCollection
            from detect_secrets.settings import transient_settings
            import tempfile
            import os
        except ImportError:
            self._detect_secrets_available = False
            logger.debug("detect-secrets not installed, using built-in patterns")
            return {}, []

        self._detect_secrets_available = True
        found: Dict[str, int] = {}
        matches: List[Dict[str, Any]] = []

        # Write text to temp file for full-context scanning
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        temp_file.write(text.encode("utf-8"))
        temp_file.close()

        try:
            secrets = SecretsCollection()
            with transient_settings(
                {
                    "plugins_used": [
                        {"name": "ArtifactoryDetector"},
                        {"name": "AWSKeyDetector"},
                        {"name": "AzureStorageKeyDetector"},
                        {"name": "BasicAuthDetector"},
                        {"name": "CloudantDetector"},
                        {"name": "DiscordBotTokenDetector"},
                        {"name": "GitHubTokenDetector"},
                        {"name": "IbmCloudIamDetector"},
                        {"name": "IbmCosHmacDetector"},
                        {"name": "JwtTokenDetector"},
                        {"name": "KeywordDetector"},
                        {"name": "MailchimpDetector"},
                        {"name": "NpmDetector"},
                        {"name": "PrivateKeyDetector"},
                        {"name": "SendGridDetector"},
                        {"name": "SlackDetector"},
                        {"name": "SoftlayerDetector"},
                        {"name": "SquareOAuthDetector"},
                        {"name": "StripeDetector"},
                        {"name": "TwilioKeyDetector"},
                        {"name": "Base64HighEntropyString", "limit": 4.5},
                        {"name": "HexHighEntropyString", "limit": 3.0},
                    ]
                }
            ):
                secrets.scan_file(str(temp_file.name))

            for file in secrets.files:
                for secret in secrets[file]:
                    if secret.secret_value is None:
                        continue
                    secret_val = secret.secret_value
                    if len(secret_val) < 6:
                        continue

                    secret_type = secret.type
                    found[secret_type] = found.get(secret_type, 0) + 1

                    # Find position in original text
                    try:
                        val_start = text.index(secret_val)
                    except ValueError:
                        continue
                    matches.append(
                        {
                            "type": secret_type,
                            "start": val_start,
                            "end": val_start + len(secret_val),
                            "text": secret_val,
                        }
                    )
        finally:
            os.remove(temp_file.name)

        return found, matches

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found_secrets: Dict[str, int] = {}
        secret_matches: List[Dict[str, Any]] = []
        self._load_model()
        model_score, model_label_scores = self._model_scan(text) if self._model else (0.0, {})

        # Method 1: detect-secrets library (primary)
        ds_found, ds_matches = self._try_detect_secrets(text)
        found_secrets.update(ds_found)
        secret_matches.extend(ds_matches)

        # Method 2: Built-in vendor-specific patterns (supplement detect-secrets)
        for secret_type, pattern in VENDOR_PATTERNS.items():
            if self.secret_types and secret_type not in self.secret_types:
                continue
            for match in pattern.finditer(text):
                # Avoid duplicates with detect-secrets findings
                match_text = match.group(0)
                already_found = any(
                    m["text"] == match_text or (m["start"] <= match.start() < m["end"])
                    for m in secret_matches
                )
                if not already_found:
                    found_secrets[secret_type] = found_secrets.get(secret_type, 0) + 1
                    secret_matches.append(
                        {
                            "type": secret_type,
                            "start": match.start(),
                            "end": match.end(),
                            "text": match.group(0),
                        }
                    )

        # Method 3: Generic keyword patterns (supplement)
        for secret_type, pattern in KEYWORD_PATTERNS.items():
            if self.secret_types and secret_type not in self.secret_types:
                continue
            for match in pattern.finditer(text):
                try:
                    value = (
                        match.group(2)
                        if match.lastindex and match.lastindex >= 2
                        else match.group(1)
                    )
                    val_start = match.start() + match.group(0).index(value)
                except (IndexError, ValueError):
                    value = match.group(0)
                    val_start = match.start()
                if _is_safe_secret_value(value):
                    continue
                # Avoid duplicates
                already_found = any(
                    m["text"] == value or (m["start"] <= val_start < m["end"])
                    for m in secret_matches
                )
                if not already_found:
                    found_secrets[secret_type] = found_secrets.get(secret_type, 0) + 1
                    secret_matches.append(
                        {
                            "type": secret_type,
                            "start": val_start,
                            "end": val_start + len(value),
                            "text": value,
                        }
                    )

        # Method 4: Contextual credential disclosure inference
        for match in CONTEXTUAL_SECRET_PATTERN.finditer(text):
            label = match.group("label")
            value = _normalize_contextual_value(match.group("value"))
            secret_type = _contextual_secret_type(label)
            has_connector = bool(match.group("symbol_connector") or match.group("word_connector"))
            if self.secret_types and secret_type not in self.secret_types:
                continue
            if not _looks_like_contextual_secret(label, value, has_connector=has_connector):
                continue
            val_start = match.start("value")
            raw_value = match.group("value")
            leading_trim = len(raw_value) - len(raw_value.lstrip("\"'`"))
            val_start += leading_trim
            val_end = val_start + len(value)
            already_found = any(
                m["text"] == value or (m["start"] <= val_start < m["end"]) for m in secret_matches
            )
            if not already_found:
                found_secrets[secret_type] = found_secrets.get(secret_type, 0) + 1
                secret_matches.append(
                    {
                        "type": secret_type,
                        "start": val_start,
                        "end": val_end,
                        "text": value,
                    }
                )

        # Method 5: High-entropy string detection
        if self.detect_entropy:
            for match in _HEX_CANDIDATE.finditer(text):
                candidate = match.group(1)
                if _ENTROPY_EXCLUDE.match(candidate):
                    continue
                if _shannon_entropy(candidate) > HEX_ENTROPY_THRESHOLD:
                    found_secrets["high_entropy_hex"] = found_secrets.get("high_entropy_hex", 0) + 1
                    secret_matches.append(
                        {
                            "type": "high_entropy_hex",
                            "start": match.start(1),
                            "end": match.end(1),
                            "text": candidate,
                        }
                    )

            for match in _BASE64_CANDIDATE.finditer(text):
                candidate = match.group(1)
                if _ENTROPY_EXCLUDE.match(candidate):
                    continue
                if len(candidate) >= 20 and _shannon_entropy(candidate) > BASE64_ENTROPY_THRESHOLD:
                    found_secrets["high_entropy_base64"] = (
                        found_secrets.get("high_entropy_base64", 0) + 1
                    )
                    secret_matches.append(
                        {
                            "type": "high_entropy_base64",
                            "start": match.start(1),
                            "end": match.end(1),
                            "text": candidate,
                        }
                    )

        # Method 6: Optional local zero-shot model for ambiguous disclosure context
        if (
            model_score >= self.model_threshold
            and not found_secrets
            and (not self.secret_types or "model_contextual_secret" in self.secret_types)
        ):
            found_secrets["model_contextual_secret"] = 1

        if not found_secrets:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={
                    "secrets_found": {},
                    "secret_matches": [],
                    "model_score": model_score,
                    "model_label_scores": model_label_scores,
                    "model_name": _SECRETS_MODEL_ID,
                    "use_model": self.use_model,
                },
            )

        max_score = 0.0
        for secret_type in found_secrets:
            if secret_type in HIGH_SENSITIVITY:
                max_score = max(max_score, 1.0)
            elif secret_type in MEDIUM_SENSITIVITY:
                max_score = max(max_score, 0.8)
            else:
                max_score = max(max_score, 0.6)

        if model_score >= self.model_threshold:
            max_score = max(max_score, min(1.0, model_score * self.model_weight + 0.6))

        is_valid = max_score < self.threshold

        public_matches = [
            {
                **match,
                "text": _redact_value(match["text"]) if self.redact_details else match["text"],
            }
            for match in secret_matches
        ]
        sanitized_output = (
            _sanitize_text(text, secret_matches)
            if secret_matches
            else "<SECRET:model_contextual_secret>"
        )

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.CRITICAL if max_score >= 0.8 else RiskLevel.HIGH,
            sanitized_output=sanitized_output,
            details={
                "secrets_found": found_secrets,
                "secret_types": list(found_secrets.keys()),
                "total_secrets": sum(found_secrets.values()),
                "secret_matches": public_matches,
                "model_score": model_score,
                "model_label_scores": model_label_scores,
                "model_name": _SECRETS_MODEL_ID,
                "use_model": self.use_model,
            },
        )

    def _model_scan(self, text: str) -> tuple[float, Dict[str, float]]:
        """Return local model confidence for credential disclosure context."""
        try:
            result = self._model(
                text[:512],
                candidate_labels=MODEL_SECRET_LABELS,
                hypothesis_template="This message contains {}.",
                multi_label=True,
            )
            labels = result.get("labels", [])
            scores = result.get("scores", [])
            label_scores = {str(label): float(score) for label, score in zip(labels, scores)}
            return (max(label_scores.values()) if label_scores else 0.0), label_scores
        except Exception as exc:
            logger.warning("Secrets model inference failed: %s", exc)
            return 0.0, {}
