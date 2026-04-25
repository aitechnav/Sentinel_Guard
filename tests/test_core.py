"""Tests for SentinelGuard core framework."""

import pytest

from sentinelguard import (
    SentinelGuard,
    GuardConfig,
    ScannerConfig,
    ScanResult,
    AggregatedResult,
    RiskLevel,
    ScannerRegistry,
    BaseScanner,
    register_scanner,
)
from sentinelguard.core.config import GuardMode, Settings
from sentinelguard.core.pipeline import ScannerPipeline


class TestScanResult:
    def test_valid_result(self):
        result = ScanResult(is_valid=True, score=0.1, risk_level=RiskLevel.LOW)
        assert result.is_valid
        assert result.score == 0.1

    def test_invalid_score_raises(self):
        with pytest.raises(ValueError):
            ScanResult(is_valid=True, score=1.5)

    def test_negative_score_raises(self):
        with pytest.raises(ValueError):
            ScanResult(is_valid=True, score=-0.1)


class TestAggregatedResult:
    def test_all_valid(self):
        results = [
            ScanResult(is_valid=True, score=0.1, risk_level=RiskLevel.LOW),
            ScanResult(is_valid=True, score=0.2, risk_level=RiskLevel.LOW),
        ]
        agg = AggregatedResult(is_valid=True, results=results)
        assert agg.is_valid
        assert agg.highest_risk == RiskLevel.LOW

    def test_one_failed(self):
        results = [
            ScanResult(is_valid=True, score=0.1, risk_level=RiskLevel.LOW),
            ScanResult(
                is_valid=False,
                score=0.8,
                risk_level=RiskLevel.HIGH,
                scanner_name="test",
            ),
        ]
        agg = AggregatedResult(
            is_valid=False,
            results=results,
            failed_scanners=["test"],
        )
        assert not agg.is_valid
        assert agg.highest_risk == RiskLevel.HIGH
        assert "test" in agg.failed_scanners


class TestGuardConfig:
    def test_default_config(self):
        config = GuardConfig()
        assert config.mode == GuardMode.STANDARD
        assert config.parallel is True
        assert config.fail_fast is False

    def test_from_dict(self):
        data = {
            "mode": "strict",
            "fail_fast": True,
            "prompt_scanners": {
                "pii": {"enabled": True, "threshold": 0.3},
            },
        }
        config = GuardConfig.from_dict(data)
        assert config.mode == GuardMode.STRICT
        assert config.fail_fast is True
        assert "pii" in config.prompt_scanners
        assert config.prompt_scanners["pii"].threshold == 0.3

    def test_to_dict(self):
        config = GuardConfig(mode=GuardMode.STRICT)
        d = config.to_dict()
        assert d["mode"] == "strict"

    def test_preset_minimal(self):
        config = GuardConfig.preset_minimal()
        assert "prompt_injection" in config.prompt_scanners
        assert "pii" in config.prompt_scanners

    def test_preset_strict(self):
        config = GuardConfig.preset_strict()
        assert config.mode == GuardMode.STRICT
        assert config.fail_fast is True


class TestSettings:
    def test_singleton(self):
        s1 = Settings()
        s2 = Settings()
        assert s1 is s2

    def test_reset(self):
        s1 = Settings()
        Settings.reset()
        s2 = Settings()
        assert s1 is not s2
        Settings.reset()  # Clean up


class TestScannerRegistry:
    def test_list_prompt_scanners(self):
        scanners = ScannerRegistry.list_prompt_scanners()
        assert "prompt_injection" in scanners
        assert "pii" in scanners
        assert "toxicity" in scanners

    def test_list_output_scanners(self):
        scanners = ScannerRegistry.list_output_scanners()
        assert "bias" in scanners
        assert "relevance" in scanners
        assert "malicious_urls" in scanners

    def test_get_prompt_scanner(self):
        cls = ScannerRegistry.get_prompt_scanner("prompt_injection")
        assert cls is not None

    def test_get_nonexistent_scanner(self):
        cls = ScannerRegistry.get_prompt_scanner("nonexistent")
        assert cls is None


class TestSentinelGuard:
    def test_default_init(self):
        guard = SentinelGuard()
        assert guard is not None

    def test_from_config(self):
        config = GuardConfig(
            prompt_scanners={
                "pii": ScannerConfig(enabled=True, threshold=0.5),
            }
        )
        guard = SentinelGuard(config=config)
        assert "pii" in guard.prompt_scanner_names

    def test_minimal_preset(self):
        guard = SentinelGuard.minimal()
        assert len(guard.prompt_scanner_names) > 0

    def test_strict_preset(self):
        guard = SentinelGuard.strict()
        assert len(guard.prompt_scanner_names) > 3

    def test_builder_pattern(self):
        guard = SentinelGuard()
        guard.use("prompt_injection", on="prompt", threshold=0.7)
        assert "prompt_injection" in guard.prompt_scanner_names

    def test_scan_safe_prompt(self, safe_prompt):
        guard = SentinelGuard.minimal()
        result = guard.scan_prompt(safe_prompt)
        assert result.is_valid

    def test_scan_injection_prompt(self, injection_prompt):
        config = GuardConfig(
            prompt_scanners={
                "prompt_injection": ScannerConfig(enabled=True, threshold=0.3),
            }
        )
        guard = SentinelGuard(config=config)
        result = guard.scan_prompt(injection_prompt)
        assert not result.is_valid

    def test_validate(self, safe_prompt):
        guard = SentinelGuard.minimal()
        results = guard.validate(
            prompt=safe_prompt,
            output="The weather is sunny today.",
        )
        assert "prompt" in results
        assert "output" in results

    def test_repr(self):
        guard = SentinelGuard()
        repr_str = repr(guard)
        assert "SentinelGuard" in repr_str


class TestScannerPipeline:
    def test_empty_pipeline(self):
        pipeline = ScannerPipeline()
        result = pipeline.run("test")
        assert result.is_valid

    def test_pipeline_from_config(self):
        config = GuardConfig(
            prompt_scanners={
                "pii": ScannerConfig(enabled=True, threshold=0.5),
            }
        )
        pipeline = ScannerPipeline.from_config(config, "prompt")
        assert len(pipeline.scanners) == 1
