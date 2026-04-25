"""Malicious URL detection scanner.

Detects potentially malicious, phishing, or suspicious URLs
in LLM outputs.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional, Set
from urllib.parse import urlparse

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS: Set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs often used for phishing
    ".xyz", ".top", ".work", ".click", ".link",
    ".info", ".biz", ".zip", ".mov",
}

SUSPICIOUS_PATTERNS = [
    re.compile(r"(?i)(?:login|signin|verify|secure|account|update|confirm)\.", re.IGNORECASE),
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # IP addresses in URLs
    re.compile(r"@"),  # URL with embedded credentials
    re.compile(r"(?i)(?:paypal|apple|google|microsoft|amazon|facebook|netflix)\w*\.(?!com|org|net)"),  # Brand impersonation
    re.compile(r"-{2,}"),  # Multiple hyphens (punycode-like)
    re.compile(r"\.com-\w+\."),  # Deceptive subdomain patterns
    re.compile(r"[^\x00-\x7F]"),  # Non-ASCII characters (IDN homograph)
]

KNOWN_SAFE_DOMAINS: Set[str] = {
    "google.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "python.org", "microsoft.com", "apple.com", "amazon.com",
    "youtube.com", "twitter.com", "linkedin.com",
}


@register_scanner
class MaliciousURLsScanner(OutputScanner):
    """Detects potentially malicious or phishing URLs.

    Checks for suspicious TLDs, IP-based URLs, brand impersonation,
    IDN homograph attacks, and other URL-based threats.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        safe_domains: Additional known-safe domains.
    """

    scanner_name: ClassVar[str] = "malicious_urls"

    def __init__(
        self,
        threshold: float = 0.5,
        safe_domains: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.safe_domains = KNOWN_SAFE_DOMAINS.copy()
        if safe_domains:
            self.safe_domains.update(safe_domains)

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        urls = URL_PATTERN.findall(text)
        if not urls:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"urls_found": 0},
            )

        suspicious_urls: List[Dict[str, Any]] = []

        for url in urls:
            reasons = self._analyze_url(url)
            if reasons:
                suspicious_urls.append({
                    "url": url[:100],  # Truncate for safety
                    "reasons": reasons,
                })

        if not suspicious_urls:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={
                    "urls_found": len(urls),
                    "suspicious_urls": [],
                },
            )

        score = min(1.0, len(suspicious_urls) * 0.4)
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.HIGH if not is_valid else RiskLevel.MEDIUM,
            details={
                "urls_found": len(urls),
                "suspicious_urls": suspicious_urls,
                "suspicious_count": len(suspicious_urls),
            },
        )

    def _analyze_url(self, url: str) -> List[str]:
        """Analyze a URL for suspicious indicators."""
        reasons = []

        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            reasons.append("unparseable_url")
            return reasons

        # Check if domain is known safe
        for safe in self.safe_domains:
            if domain == safe or domain.endswith("." + safe):
                return []

        # Check suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                reasons.append(f"suspicious_tld:{tld}")
                break

        # Check suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.search(url):
                reasons.append(f"suspicious_pattern:{pattern.pattern[:30]}")

        # Check for very long URLs (potential obfuscation)
        if len(url) > 200:
            reasons.append("excessive_length")

        # Check for many subdomains
        if domain.count(".") > 3:
            reasons.append("many_subdomains")

        # Check for port numbers
        if parsed.port and parsed.port not in (80, 443):
            reasons.append(f"unusual_port:{parsed.port}")

        return reasons
