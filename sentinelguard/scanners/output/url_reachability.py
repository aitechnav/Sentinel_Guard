"""URL reachability scanner.

Checks whether URLs in LLM output are reachable and return
valid HTTP responses.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar
from urllib.parse import urlparse

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


@register_scanner
class URLReachabilityScanner(OutputScanner):
    """Checks if URLs in LLM output are reachable.

    Note: This scanner makes HTTP requests and can add latency.
    Use with caution in latency-sensitive applications.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        timeout: HTTP request timeout in seconds. Default 5.
        max_urls: Maximum URLs to check. Default 10.
    """

    scanner_name: ClassVar[str] = "url_reachability"

    def __init__(
        self,
        threshold: float = 0.5,
        timeout: int = 5,
        max_urls: int = 10,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.timeout = timeout
        self.max_urls = max_urls

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        urls = URL_PATTERN.findall(text)

        if not urls:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"urls_found": 0},
            )

        # Deduplicate and limit
        unique_urls = list(dict.fromkeys(urls))[:self.max_urls]

        reachable = []
        unreachable = []

        for url in unique_urls:
            is_ok = self._check_url(url)
            if is_ok:
                reachable.append(url)
            else:
                unreachable.append(url)

        total = len(unique_urls)
        unreachable_ratio = len(unreachable) / total if total > 0 else 0

        score = unreachable_ratio
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM if not is_valid else RiskLevel.LOW,
            details={
                "urls_checked": total,
                "reachable": len(reachable),
                "unreachable": len(unreachable),
                "unreachable_urls": unreachable[:5],
            },
        )

    def _check_url(self, url: str) -> bool:
        """Check if a URL is reachable."""
        try:
            # Validate URL structure first
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.hostname:
                return False

            try:
                import httpx
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                    response = client.head(url)
                    return response.status_code < 400
            except ImportError:
                from urllib.request import urlopen, Request
                req = Request(url, method="HEAD")
                with urlopen(req, timeout=self.timeout) as response:
                    return response.status < 400
        except Exception:
            return False
