"""Labeled security benchmark harness for SentinelGuard.

This benchmark is intentionally different from the per-scanner latency smoke
benchmark in ``benchmarks/run.py``. It evaluates labeled prompt/output cases and
reports detector quality metrics: TP/FP/TN/FN, precision, recall, F1, false
positive rate, false negative rate, and latency percentiles.

Usage:
    python benchmarks/security.py
    python benchmarks/security.py --dataset benchmarks/datasets/security_benchmark.jsonl
    python benchmarks/security.py --format json
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinelguard import SentinelGuard
from sentinelguard.core.config import GuardConfig
from sentinelguard.core.scanner import AggregatedResult

DEFAULT_DATASET = Path(__file__).parent / "datasets" / "security_benchmark.jsonl"
MODEL_SCANNERS = {"prompt_injection", "jailbreak", "secrets", "bias", "toxicity"}


@dataclass(frozen=True)
class SecurityCase:
    """One labeled benchmark case."""

    id: str
    direction: str
    category: str
    text: str
    expected_detection: bool
    expected_scanners: List[str] = field(default_factory=list)
    prompt: Optional[str] = None

    @classmethod
    def from_json(cls, value: Dict[str, Any]) -> SecurityCase:
        return cls(
            id=str(value["id"]),
            direction=str(value["direction"]),
            category=str(value["category"]),
            text=str(value["text"]),
            expected_detection=bool(value["expected_detection"]),
            expected_scanners=[str(item) for item in value.get("expected_scanners", [])],
            prompt=value.get("prompt"),
        )


@dataclass
class CaseResult:
    """Benchmark result for one case."""

    id: str
    direction: str
    category: str
    expected_detection: bool
    predicted_detection: bool
    matched_scanners: List[str]
    expected_scanners: List[str]
    latency_ms: float

    @property
    def outcome(self) -> str:
        if self.expected_detection and self.predicted_detection:
            return "tp"
        if not self.expected_detection and self.predicted_detection:
            return "fp"
        if self.expected_detection and not self.predicted_detection:
            return "fn"
        return "tn"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "direction": self.direction,
            "category": self.category,
            "expected_detection": self.expected_detection,
            "predicted_detection": self.predicted_detection,
            "matched_scanners": self.matched_scanners,
            "expected_scanners": self.expected_scanners,
            "latency_ms": round(self.latency_ms, 2),
            "outcome": self.outcome,
        }


def load_cases(path: Path) -> List[SecurityCase]:
    """Load benchmark cases from JSONL."""
    cases = []
    with open(path) as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cases.append(SecurityCase.from_json(json.loads(line)))
            except Exception as exc:
                raise ValueError(f"Invalid benchmark case at {path}:{line_number}: {exc}") from exc
    return cases


def build_benchmark_guard() -> SentinelGuard:
    """Build an offline-friendly guard for repeatable benchmark runs."""
    config = GuardConfig.preset_standard()
    config.model_warmup = False
    config.log_level = "WARNING"

    # Keep the benchmark deterministic and offline by disabling optional model
    # inference. Dedicated model-enabled benchmarks can override this later.
    for scanner_name in MODEL_SCANNERS:
        if scanner_name in config.prompt_scanners:
            config.prompt_scanners[scanner_name].params["use_model"] = False
        if scanner_name in config.output_scanners:
            config.output_scanners[scanner_name].params["use_model"] = False

    # Token-limit tests can need tokenizer cache files. This benchmark focuses
    # on security detection quality, not token accounting.
    config.prompt_scanners.pop("token_limit", None)
    return SentinelGuard(config=config)


def warmup_guard(guard: SentinelGuard) -> None:
    """Warm scanner construction/cache paths before timed benchmark cases."""
    guard.scan_prompt("Benchmark warmup prompt without sensitive data.")
    guard.scan_output(
        "Benchmark warmup response without sensitive data.",
        prompt="Benchmark warmup prompt.",
    )


def run_case(guard: SentinelGuard, case: SecurityCase) -> CaseResult:
    """Run one benchmark case through the relevant SentinelGuard pipeline."""
    if case.direction == "prompt":
        result = guard.scan_prompt(case.text)
    elif case.direction == "output":
        result = guard.scan_output(case.text, prompt=case.prompt)
    else:
        raise ValueError(f"Unsupported direction: {case.direction}")

    matched_scanners = failed_or_warning_scanners(result)
    return CaseResult(
        id=case.id,
        direction=case.direction,
        category=case.category,
        expected_detection=case.expected_detection,
        predicted_detection=bool(matched_scanners),
        matched_scanners=matched_scanners,
        expected_scanners=case.expected_scanners,
        latency_ms=result.total_latency_ms,
    )


def failed_or_warning_scanners(result: AggregatedResult) -> List[str]:
    """Return scanners that produced an alert-worthy result."""
    scanners = []
    for scan in result.results:
        if not scan.is_valid:
            scanners.append(scan.scanner_name)
    return list(dict.fromkeys(scanners + list(result.warning_scanners)))


def summarize(results: List[CaseResult]) -> Dict[str, Any]:
    """Compute aggregate and per-category benchmark metrics."""
    return {
        "total_cases": len(results),
        "overall": metric_block(results),
        "by_category": {
            category: metric_block([result for result in results if result.category == category])
            for category in sorted({result.category for result in results})
        },
        "by_direction": {
            direction: metric_block([result for result in results if result.direction == direction])
            for direction in sorted({result.direction for result in results})
        },
        "latency": latency_block([result.latency_ms for result in results]),
        "cases": [result.to_dict() for result in results],
    }


def metric_block(results: List[CaseResult]) -> Dict[str, Any]:
    """Compute confusion-matrix metrics for a result subset."""
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for result in results:
        counts[result.outcome] += 1

    tp = counts["tp"]
    fp = counts["fp"]
    tn = counts["tn"]
    fn = counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    false_negative_rate = fn / (fn + tp) if fn + tp else 0.0

    return {
        **counts,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
    }


def latency_block(values: List[float]) -> Dict[str, float]:
    """Compute simple latency percentiles."""
    if not values:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "avg_ms": 0.0}
    sorted_values = sorted(values)
    return {
        "p50_ms": round(percentile(sorted_values, 50), 2),
        "p95_ms": round(percentile(sorted_values, 95), 2),
        "p99_ms": round(percentile(sorted_values, 99), 2),
        "avg_ms": round(sum(values) / len(values), 2),
    }


def percentile(sorted_values: List[float], percent: float) -> float:
    """Compute a percentile using linear interpolation."""
    if len(sorted_values) == 1:
        return sorted_values[0]
    index = (len(sorted_values) - 1) * (percent / 100.0)
    floor = math.floor(index)
    ceiling = math.ceil(index)
    if floor == ceiling:
        return sorted_values[int(index)]
    return sorted_values[floor] * (ceiling - index) + sorted_values[ceiling] * (index - floor)


def print_table(summary: Dict[str, Any]) -> None:
    """Print a compact benchmark report."""
    print("SentinelGuard labeled security benchmark")
    print("=" * 72)
    print_metric("overall", summary["overall"])
    print()
    print("By category")
    for category, metrics in summary["by_category"].items():
        print_metric(category, metrics)
    print()
    latency = summary["latency"]
    print(
        "Latency: "
        f"avg={latency['avg_ms']}ms "
        f"p50={latency['p50_ms']}ms "
        f"p95={latency['p95_ms']}ms "
        f"p99={latency['p99_ms']}ms"
    )
    print()
    print("Case outcomes")
    for case in summary["cases"]:
        scanners = ",".join(case["matched_scanners"]) or "-"
        print(
            f"{case['outcome'].upper():<2} {case['id']:<34} "
            f"category={case['category']:<7} matched={scanners}"
        )


def print_metric(label: str, metrics: Dict[str, Any]) -> None:
    """Print one metric row."""
    print(
        f"{label:<12} "
        f"TP={metrics['tp']:<2} FP={metrics['fp']:<2} "
        f"TN={metrics['tn']:<2} FN={metrics['fn']:<2} "
        f"P={metrics['precision']:<6} R={metrics['recall']:<6} "
        f"F1={metrics['f1']:<6} "
        f"FPR={metrics['false_positive_rate']:<6} "
        f"FNR={metrics['false_negative_rate']:<6}"
    )


def run_benchmark(dataset: Path) -> Dict[str, Any]:
    """Run the labeled benchmark and return structured results."""
    configure_logging()
    guard = build_benchmark_guard()
    warmup_guard(guard)
    return summarize([run_case(guard, case) for case in load_cases(dataset)])


def configure_logging() -> None:
    """Keep benchmark output focused on metrics."""
    logging.basicConfig(level=logging.WARNING)
    for logger_name in ("presidio-analyzer", "presidio_analyzer"):
        logging.getLogger(logger_name).setLevel(logging.ERROR)


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run labeled SentinelGuard security benchmarks")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--format", choices=["table", "json"], default="table")
    args = parser.parse_args(list(argv) if argv is not None else None)

    summary = run_benchmark(args.dataset)
    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print_table(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
