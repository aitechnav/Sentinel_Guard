"""SentinelGuard - Comprehensive LLM Security & Guardrails Framework.

A production-ready framework for securing LLM applications with:
- 19 prompt scanners for input validation (OWASP LLM Top 10 aligned)
- 17 output scanners for response validation (OWASP LLM Top 10 aligned)
- Full OWASP LLM Top 10 (2025) compliance checking
- Enterprise-grade PII detection (Presidio integration)
- Advanced adversarial attack detection
- Embedding-based semantic guardrails
- FastAPI server and CLI tool

Usage:
    from sentinelguard import SentinelGuard, GuardConfig, ScannerConfig

    # Simple usage
    guard = SentinelGuard()
    result = guard.scan_prompt("User input here")

    if not result.is_valid:
        print(f"Blocked: {result.failed_scanners}")

    # OWASP compliance check
    from sentinelguard.owasp import OWASPComplianceChecker
    checker = OWASPComplianceChecker()
    report = checker.check(guard)
    print(report.summary())

    # With configuration
    config = GuardConfig(
        mode="strict",
        prompt_scanners={
            "prompt_injection": ScannerConfig(enabled=True, threshold=0.7),
            "pii": ScannerConfig(enabled=True, threshold=0.5),
        }
    )
    guard = SentinelGuard(config=config)
"""

__version__ = "0.0.2"
__author__ = "SentinelGuard Contributors"

from sentinelguard.core.guard import SentinelGuard
from sentinelguard.core.config import GuardConfig, GuardMode, ScannerConfig, Settings, settings
from sentinelguard.core.scanner import (
    BaseScanner,
    PromptScanner,
    OutputScanner,
    ScanResult,
    AggregatedResult,
    RiskLevel,
    ScannerRegistry,
    register_scanner,
)
from sentinelguard.core.pipeline import ScannerPipeline

# Import all scanners to trigger registration
import sentinelguard.scanners.prompt  # noqa: F401
import sentinelguard.scanners.output  # noqa: F401

__all__ = [
    # Main class
    "SentinelGuard",
    # Configuration
    "GuardConfig",
    "GuardMode",
    "ScannerConfig",
    "Settings",
    "settings",
    # Scanner base classes
    "BaseScanner",
    "PromptScanner",
    "OutputScanner",
    "ScanResult",
    "AggregatedResult",
    "RiskLevel",
    "ScannerRegistry",
    "register_scanner",
    # Pipeline
    "ScannerPipeline",
]
