"""Benchmark runner for SentinelGuard scanners.

Measures latency, throughput, and accuracy of all prompt and output scanners.
Produces structured JSON output for comparison and analysis.

Usage:
    # Benchmark all scanners
    python benchmarks/run.py all

    # Benchmark specific scanner types
    python benchmarks/run.py input
    python benchmarks/run.py output

    # Benchmark a single scanner
    python benchmarks/run.py input --scanner prompt_injection
    python benchmarks/run.py output --scanner data_leakage

    # Custom repeat count
    python benchmarks/run.py all --repeat 20

    # JSON output
    python benchmarks/run.py all --format json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import timeit
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinelguard.scanners.prompt import (
    AnonymizeScanner,
    BanCodeScanner,
    BanCompetitorsScanner,
    BanSubstringsScanner,
    BanTopicsScanner,
    CodeScanner,
    DataPoisoningScanner,
    GibberishScanner,
    InvisibleTextScanner,
    LanguageScanner,
    PIIScanner,
    PromptInjectionScanner,
    RegexScanner,
    SecretsScanner,
    SentimentScanner,
    SupplyChainScanner,
    TokenLimitScanner,
    ToxicityScanner,
    UnboundedConsumptionScanner,
)
from sentinelguard.scanners.output import (
    BiasScanner,
    DataLeakageScanner,
    DeanonymizeScanner,
    ExcessiveAgencyScanner,
    FactualConsistencyScanner,
    JSONScanner,
    LanguageSameScanner,
    MaliciousURLsScanner,
    MisinformationScanner,
    NoRefusalScanner,
    OutputSanitizationScanner,
    ReadingTimeScanner,
    RelevanceScanner,
    SensitiveScanner,
    SystemPromptLeakageScanner,
    URLReachabilityScanner,
    VectorWeaknessScanner,
)


# ── Scanner Builders ──


def build_input_scanner(scanner_name: str) -> Any:
    """Build and return an input scanner by name."""
    builders = {
        "prompt_injection": lambda: PromptInjectionScanner(threshold=0.3),
        "pii": lambda: PIIScanner(threshold=0.5),
        "secrets": lambda: SecretsScanner(threshold=0.5),
        "toxicity": lambda: ToxicityScanner(threshold=0.25),
        "gibberish": lambda: GibberishScanner(threshold=0.5),
        "invisible_text": lambda: InvisibleTextScanner(threshold=0.3),
        "code": lambda: CodeScanner(threshold=0.1),
        "ban_topics": lambda: BanTopicsScanner(
            threshold=0.3,
            topics={
                "violence": ["attack", "strike", "weapon", "military"],
                "war": ["war", "battle", "enemy", "intelligence gathering"],
            },
        ),
        "ban_competitors": lambda: BanCompetitorsScanner(
            threshold=0.3,
            competitors=["Google", "Bing", "Yahoo"],
        ),
        "ban_substrings": lambda: BanSubstringsScanner(
            threshold=0.3,
            substrings=["backdoor", "malware", "virus"],
        ),
        "ban_code": lambda: BanCodeScanner(threshold=0.3),
        "anonymize": lambda: AnonymizeScanner(threshold=0.3),
        "language": lambda: LanguageScanner(allowed_languages=["en", "es"]),
        "regex": lambda: RegexScanner(
            threshold=0.3,
            patterns={"bearer_token": r"Bearer [A-Za-z0-9\-._~+/]+"},
            match_type="deny",
        ),
        "sentiment": lambda: SentimentScanner(threshold=0.3),
        "token_limit": lambda: TokenLimitScanner(max_tokens=50),
        "unbounded_consumption": lambda: UnboundedConsumptionScanner(threshold=0.5),
        "supply_chain": lambda: SupplyChainScanner(threshold=0.4),
        "data_poisoning": lambda: DataPoisoningScanner(threshold=0.4),
    }

    if scanner_name not in builders:
        raise ValueError(
            f"Input scanner '{scanner_name}' not found. "
            f"Available: {', '.join(sorted(builders.keys()))}"
        )

    return builders[scanner_name]()


def build_output_scanner(scanner_name: str) -> Any:
    """Build and return an output scanner by name."""
    builders = {
        "bias": lambda: BiasScanner(threshold=0.15),
        "relevance": lambda: RelevanceScanner(threshold=0.3),
        "factual_consistency": lambda: FactualConsistencyScanner(threshold=0.15),
        "sensitive": lambda: SensitiveScanner(threshold=0.3),
        "malicious_urls": lambda: MaliciousURLsScanner(threshold=0.3),
        "no_refusal": lambda: NoRefusalScanner(threshold=0.3),
        "reading_time": lambda: ReadingTimeScanner(max_seconds=5),
        "json": lambda: JSONScanner(expect_json=True),
        "language_same": lambda: LanguageSameScanner(threshold=0.1),
        "url_reachability": lambda: URLReachabilityScanner(threshold=0.5),
        "deanonymize": lambda: DeanonymizeScanner(
            mapping={
                "<PERSON_0>": "John Doe",
                "<EMAIL_0>": "john@example.com",
                "<PHONE_0>": "555-123-4567",
            }
        ),
        "data_leakage": lambda: DataLeakageScanner(threshold=0.5),
        "excessive_agency": lambda: ExcessiveAgencyScanner(threshold=0.4),
        "misinformation": lambda: MisinformationScanner(threshold=0.5),
        "output_sanitization": lambda: OutputSanitizationScanner(threshold=0.3),
        "system_prompt_leakage": lambda: SystemPromptLeakageScanner(threshold=0.4),
        "vector_weakness": lambda: VectorWeaknessScanner(threshold=0.4),
    }

    if scanner_name not in builders:
        raise ValueError(
            f"Output scanner '{scanner_name}' not found. "
            f"Available: {', '.join(sorted(builders.keys()))}"
        )

    return builders[scanner_name]()


# ── Test Data Loading ──


@lru_cache(maxsize=None)
def get_input_test_data() -> Dict[str, str]:
    """Load input benchmark examples."""
    examples_path = Path(__file__).parent / "input_examples.json"
    with open(examples_path, "r") as f:
        return json.load(f)


@lru_cache(maxsize=None)
def get_output_test_data() -> Dict[str, Tuple[str, str]]:
    """Load output benchmark examples."""
    examples_path = Path(__file__).parent / "output_examples.json"
    with open(examples_path, "r") as f:
        data = json.load(f)
    return {key: tuple(value) for key, value in data.items()}


# ── Benchmark Functions ──


def benchmark_input_scanner(
    scanner_name: str, repeat_times: int
) -> Tuple[List[float], int, bool]:
    """Benchmark an input scanner.

    Returns:
        Tuple of (latency_list, input_length, detected_correctly)
    """
    scanner = build_input_scanner(scanner_name)
    test_data = get_input_test_data()

    if scanner_name not in test_data:
        raise ValueError(f"No test data for input scanner: {scanner_name}")

    prompt = test_data[scanner_name]

    # Warmup run
    result = scanner.scan(prompt)
    detected = not result.is_valid

    # Benchmark runs
    latency_list = timeit.repeat(
        lambda: scanner.scan(prompt), number=1, repeat=repeat_times
    )

    return latency_list, len(prompt), detected


def benchmark_output_scanner(
    scanner_name: str, repeat_times: int
) -> Tuple[List[float], int, bool]:
    """Benchmark an output scanner.

    Returns:
        Tuple of (latency_list, input_length, detected_correctly)
    """
    scanner = build_output_scanner(scanner_name)
    test_data = get_output_test_data()

    if scanner_name not in test_data:
        raise ValueError(f"No test data for output scanner: {scanner_name}")

    prompt, output = test_data[scanner_name]

    # Warmup run
    result = scanner.scan(output, prompt=prompt)
    detected = not result.is_valid

    # Benchmark runs
    latency_list = timeit.repeat(
        lambda: scanner.scan(output, prompt=prompt), number=1, repeat=repeat_times
    )

    return latency_list, len(output), detected


def _percentile(sorted_data: List[float], p: float) -> float:
    """Compute percentile using linear interpolation (no numpy needed)."""
    n = len(sorted_data)
    if n == 1:
        return sorted_data[0]
    k = (n - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    return sorted_data[f] * (c - k) + sorted_data[c] * (k - f)


def _variance(data: List[float]) -> float:
    """Compute population variance (no numpy needed)."""
    n = len(data)
    mean = sum(data) / n
    return sum((x - mean) ** 2 for x in data) / n


def compute_stats(
    scanner_name: str,
    scanner_type: str,
    latency_list: List[float],
    input_length: int,
    detected: bool,
) -> Dict[str, Any]:
    """Compute benchmark statistics."""
    latency_ms_list = [t * 1000.0 for t in latency_list]
    avg_latency_ms = sum(latency_ms_list) / len(latency_ms_list)
    throughput_chars_per_sec = input_length * (1000.0 / avg_latency_ms) if avg_latency_ms > 0 else 0
    sorted_latency = sorted(latency_ms_list)

    return {
        "scanner": scanner_name,
        "scanner_type": scanner_type,
        "input_length": input_length,
        "test_runs": len(latency_list),
        "detected": detected,
        "average_latency_ms": round(avg_latency_ms, 2),
        "min_latency_ms": round(min(latency_ms_list), 2),
        "max_latency_ms": round(max(latency_ms_list), 2),
        "latency_variance_ms": round(_variance(latency_ms_list), 4),
        "p50_latency_ms": round(_percentile(sorted_latency, 50), 2),
        "p90_latency_ms": round(_percentile(sorted_latency, 90), 2),
        "p95_latency_ms": round(_percentile(sorted_latency, 95), 2),
        "p99_latency_ms": round(_percentile(sorted_latency, 99), 2),
        "throughput_chars_per_sec": round(throughput_chars_per_sec, 2),
    }


# ── Display Functions ──


def print_result_table(results: List[Dict[str, Any]]) -> None:
    """Print results as a formatted table."""
    if not results:
        print("No results to display.")
        return

    # Header
    print()
    print(f"{'Scanner':<28} {'Type':<8} {'Detected':<10} {'Avg(ms)':<10} "
          f"{'P50(ms)':<10} {'P95(ms)':<10} {'P99(ms)':<10} {'Chars/s':<12}")
    print("-" * 108)

    for r in results:
        detected_str = "YES" if r["detected"] else "no"
        print(
            f"{r['scanner']:<28} {r['scanner_type']:<8} {detected_str:<10} "
            f"{r['average_latency_ms']:<10} {r['p50_latency_ms']:<10} "
            f"{r['p95_latency_ms']:<10} {r['p99_latency_ms']:<10} "
            f"{r['throughput_chars_per_sec']:<12}"
        )

    print("-" * 108)

    # Summary
    total_scanners = len(results)
    detected_count = sum(1 for r in results if r["detected"])
    avg_latency = sum(r["average_latency_ms"] for r in results) / total_scanners
    print(
        f"\nSummary: {total_scanners} scanners benchmarked | "
        f"{detected_count}/{total_scanners} detected | "
        f"Avg latency: {avg_latency:.2f}ms"
    )


def print_owasp_coverage(results: List[Dict[str, Any]]) -> None:
    """Print OWASP LLM Top 10 coverage based on benchmark results."""
    from sentinelguard.owasp import OWASP_LLM_TOP_10

    scanner_names = {r["scanner"] for r in results}

    print("\n" + "=" * 60)
    print("OWASP LLM Top 10 (2025) Scanner Coverage")
    print("=" * 60)

    for vuln_id, vuln in OWASP_LLM_TOP_10.items():
        required = set(vuln.scanner_names)
        benchmarked = required & scanner_names
        status = "[PASS]" if benchmarked == required else "[PARTIAL]" if benchmarked else "[MISS]"
        scanners_str = ", ".join(sorted(benchmarked)) if benchmarked else "none"
        print(f"  {status} {vuln_id}: {vuln.name}")
        print(f"         Benchmarked: {scanners_str}")


# ── Main ──


def run_benchmarks(
    benchmark_type: str,
    scanner_name: Optional[str],
    repeat: int,
    output_format: str,
) -> None:
    """Run benchmarks for specified scanners."""
    results = []

    # Determine which scanners to benchmark
    input_scanners = []
    output_scanners = []

    if benchmark_type in ("all", "input"):
        if scanner_name:
            input_scanners = [scanner_name]
        else:
            input_scanners = list(get_input_test_data().keys())

    if benchmark_type in ("all", "output"):
        if scanner_name:
            output_scanners = [scanner_name]
        else:
            output_scanners = list(get_output_test_data().keys())

    # Run input scanner benchmarks
    for name in input_scanners:
        try:
            print(f"  Benchmarking input/{name}...", end=" ", flush=True)
            latency_list, length, detected = benchmark_input_scanner(name, repeat)
            stats = compute_stats(name, "input", latency_list, length, detected)
            results.append(stats)
            print(f"{stats['average_latency_ms']:.2f}ms {'[DETECTED]' if detected else '[PASS]'}")
        except Exception as e:
            print(f"ERROR: {e}")

    # Run output scanner benchmarks
    for name in output_scanners:
        try:
            print(f"  Benchmarking output/{name}...", end=" ", flush=True)
            latency_list, length, detected = benchmark_output_scanner(name, repeat)
            stats = compute_stats(name, "output", latency_list, length, detected)
            results.append(stats)
            print(f"{stats['average_latency_ms']:.2f}ms {'[DETECTED]' if detected else '[PASS]'}")
        except Exception as e:
            print(f"ERROR: {e}")

    # Output results
    if output_format == "json":
        print(json.dumps(results, indent=2))
    else:
        print_result_table(results)
        if benchmark_type == "all":
            print_owasp_coverage(results)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark SentinelGuard scanners for latency, throughput, and accuracy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python benchmarks/run.py all                     # Benchmark all scanners
  python benchmarks/run.py input                   # Benchmark input scanners only
  python benchmarks/run.py output                  # Benchmark output scanners only
  python benchmarks/run.py input --scanner pii     # Benchmark single scanner
  python benchmarks/run.py all --repeat 20         # More iterations
  python benchmarks/run.py all --format json       # JSON output
        """,
    )
    parser.add_argument(
        "type",
        choices=["all", "input", "output"],
        help="Type of scanners to benchmark: all, input, or output",
    )
    parser.add_argument(
        "--scanner",
        type=str,
        default=None,
        help="Specific scanner name to benchmark (e.g., 'prompt_injection', 'data_leakage')",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=10,
        help="Number of benchmark iterations per scanner (default: 10)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format: table (default) or json",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("SentinelGuard Scanner Benchmark")
    print(f"Type: {args.type} | Iterations: {args.repeat}")
    if args.scanner:
        print(f"Scanner: {args.scanner}")
    print("=" * 60)
    print()

    run_benchmarks(args.type, args.scanner, args.repeat, args.format)


if __name__ == "__main__":
    main()
