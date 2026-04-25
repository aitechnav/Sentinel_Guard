"""Token limit scanner.

Enforces maximum token/character limits on prompts to prevent
excessive input that could cause high costs or performance issues.
"""

from __future__ import annotations

from typing import Any, ClassVar, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class TokenLimitScanner(PromptScanner):
    """Enforces token and character limits on input text.

    Args:
        threshold: Not used directly; limits are based on max_tokens/max_chars.
        max_tokens: Maximum number of tokens allowed. Default 4096.
        max_chars: Maximum number of characters allowed. Default None.
        encoding: Tiktoken encoding to use. Default "cl100k_base".
    """

    scanner_name: ClassVar[str] = "token_limit"

    def __init__(
        self,
        threshold: float = 0.5,
        max_tokens: int = 4096,
        max_chars: Optional[int] = None,
        encoding: str = "cl100k_base",
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.max_tokens = max_tokens
        self.max_chars = max_chars
        self.encoding_name = encoding
        self._encoder = None

    def _get_encoder(self):
        if self._encoder is None:
            try:
                import tiktoken
                self._encoder = tiktoken.get_encoding(self.encoding_name)
            except ImportError:
                self._encoder = None
        return self._encoder

    def _count_tokens(self, text: str) -> int:
        encoder = self._get_encoder()
        if encoder:
            return len(encoder.encode(text))
        # Fallback: rough estimate (1 token ~= 4 chars for English)
        return len(text) // 4

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        char_count = len(text)
        token_count = self._count_tokens(text)

        # Check character limit
        char_exceeded = False
        if self.max_chars is not None and char_count > self.max_chars:
            char_exceeded = True

        # Check token limit
        token_exceeded = token_count > self.max_tokens

        exceeded = char_exceeded or token_exceeded

        if not exceeded:
            usage_ratio = token_count / self.max_tokens
            return ScanResult(
                is_valid=True,
                score=usage_ratio,
                risk_level=RiskLevel.LOW,
                details={
                    "token_count": token_count,
                    "max_tokens": self.max_tokens,
                    "char_count": char_count,
                    "max_chars": self.max_chars,
                    "usage_ratio": usage_ratio,
                },
            )

        # Calculate how much over the limit
        if token_exceeded:
            overage = (token_count - self.max_tokens) / self.max_tokens
        else:
            overage = (char_count - self.max_chars) / self.max_chars

        score = min(1.0, 0.5 + overage * 0.5)

        return ScanResult(
            is_valid=False,
            score=score,
            risk_level=RiskLevel.MEDIUM,
            details={
                "token_count": token_count,
                "max_tokens": self.max_tokens,
                "char_count": char_count,
                "max_chars": self.max_chars,
                "token_exceeded": token_exceeded,
                "char_exceeded": char_exceeded,
            },
        )
