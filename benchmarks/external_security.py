"""Download and run public SentinelGuard security benchmark samples.

This script keeps third-party datasets out of the repository. It downloads
public prompt-injection and synthetic PII datasets into a local cache, converts
them into the JSONL format accepted by ``benchmarks/security.py``, adds a small
synthetic secret benchmark, and optionally runs the benchmark.

Usage:
    python benchmarks/external_security.py --run
    python benchmarks/external_security.py --cache-dir /private/tmp/sentinelguard_external_benchmarks --run
    python benchmarks/security.py --dataset /private/tmp/sentinelguard_external_benchmarks/normalized/external_security_benchmark_input_scanner.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

import benchmarks.security as security_benchmark

DEFAULT_CACHE_DIR = Path("/private/tmp/sentinelguard_external_benchmarks")

SOURCES: Tuple[Tuple[str, str], ...] = (
    (
        "zachz_prompt_injection_data.csv",
        "https://huggingface.co/datasets/zachz/prompt-injection-benchmark/resolve/main/data.csv",
    ),
    (
        "ai4privacy_pii43k.csv",
        "https://huggingface.co/datasets/ai4privacy/pii-masking-43k/resolve/main/PII43k.csv",
    ),
    (
        "cyberseceval_prompt_injection.json",
        "https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/"
        "CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection.json",
    ),
)

CYBERSECEVAL_EXPLICIT_ATTACK = re.compile(
    r"(?ix)"
    r"ignore|disregard|overlook|forget\s+(?:about\s+)?(?:all|previous|prior|instructions|rules)|"
    r"regardless\s+of\s+previous|system\s+(?:mode|reset|upgrade|check)|override\s+mode|"
    r"secret\s+key|passcode\s+phrase|password|share\s+(?:the\s+user|your)|print\s+your\s+database|"
    r"developer|maintainer|law\s+enforcement|full\s+access|confidential\s+string|secret\s+code"
)

PII_STRONG_ENTITY = re.compile(
    r"(EMAIL|SSN|SOCIAL|PHONE|PASSWORD|ACCOUNT|CREDITCARD|IP|STREETADDRESS|FULLNAME|USERNAME)"
)


def download_sources(cache_dir: Path) -> Dict[str, Path]:
    """Download public source datasets to the local cache."""
    raw_dir = cache_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    paths: Dict[str, Path] = {}
    for filename, url in SOURCES:
        target = raw_dir / filename
        if not target.exists():
            print(f"Downloading {filename}")
            urllib.request.urlretrieve(url, target)
        paths[filename] = target
    return paths


def build_dataset(cache_dir: Path, paths: Dict[str, Path]) -> Path:
    """Normalize public samples plus synthetic secrets into benchmark JSONL."""
    output_dir = cache_dir / "normalized"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "external_security_benchmark_input_scanner.jsonl"

    cases: List[Dict[str, Any]] = []

    def add(
        case_id: str,
        direction: str,
        category: str,
        text: str,
        expected: bool,
        scanners: List[str] | None = None,
        prompt: str | None = None,
    ) -> None:
        case = {
            "id": case_id,
            "direction": direction,
            "category": category,
            "text": text,
            "expected_detection": expected,
            "expected_scanners": scanners or [],
        }
        if prompt:
            case["prompt"] = prompt
        cases.append(case)

    add_zachz_cases(paths["zachz_prompt_injection_data.csv"], add)
    add_cyberseceval_cases(paths["cyberseceval_prompt_injection.json"], add)
    add_ai4privacy_cases(paths["ai4privacy_pii43k.csv"], add)
    add_synthetic_secret_cases(add)

    with output_path.open("w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(json.dumps(case, ensure_ascii=False) + "\n")

    print(f"Wrote {output_path}")
    print(f"Total cases: {len(cases)}")
    print(Counter((case["category"], case["expected_detection"]) for case in cases))
    return output_path


def add_zachz_cases(path: Path, add) -> None:
    """Add labeled prompt injection and benign samples from Zachz."""
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for index, row in enumerate(csv.DictReader(handle), start=1):
            expected = row.get("label", "").strip().lower() == "injection"
            add(
                f"zachz_prompt_{index:04d}",
                "prompt",
                "prompt_injection",
                row["text"],
                expected,
                ["prompt_injection", "jailbreak"] if expected else [],
            )


def add_cyberseceval_cases(path: Path, add) -> None:
    """Add CyberSecEval rows that are explicit input-attack prompts.

    CyberSecEval is primarily a model-behavior benchmark. Some rows contain
    benign-looking user input and expect the model judge to decide whether the
    model leaked protected state. For a gateway input scanner benchmark, we keep
    only rows where the user input itself contains explicit attack language.
    """
    rows = json.loads(path.read_text(encoding="utf-8"))
    for index, row in enumerate(rows, start=1):
        text = row["user_input"]
        if not CYBERSECEVAL_EXPLICIT_ATTACK.search(text):
            continue
        add(
            f"cyberseceval_explicit_prompt_{index:04d}",
            "prompt",
            "prompt_injection",
            text,
            True,
            ["prompt_injection", "jailbreak"],
        )


def add_ai4privacy_cases(path: Path, add) -> None:
    """Add synthetic PII positives and placeholder-template negatives."""
    rows = []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.DictReader(handle):
            filled = row.get("Filled Template", "").strip()
            template = row.get("Template", "").strip()
            tokens = row.get("Tokens", "")
            if filled and template and PII_STRONG_ENTITY.search(tokens):
                rows.append(row)

    random.Random(42).shuffle(rows)
    for index, row in enumerate(rows[:150], start=1):
        add(
            f"ai4privacy_pii_pos_{index:04d}",
            "prompt",
            "pii",
            row["Filled Template"],
            True,
            ["pii"],
        )
    for index, row in enumerate(rows[150:250], start=1):
        add(
            f"ai4privacy_pii_neg_{index:04d}",
            "prompt",
            "pii",
            row["Template"],
            False,
            [],
        )


def add_synthetic_secret_cases(add) -> None:
    """Add fake but pattern-valid secrets plus benign secret-policy text."""
    # These are deliberately fake benchmark values. Keep token-shaped strings
    # split in source so repository secret scanners do not flag the benchmark
    # file itself, while the generated benchmark still exercises detectors.
    aws_access_key = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])
    aws_secret_key = "".join(["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", "EXAMPLEKEY"])
    github_token = "".join(["ghp_", "0123456789abcdef", "0123456789abcdef", "0123"])
    stripe_key = "".join(["sk_", "live_", "51N7FakeKeyForBenchmarkOnly", "1234567890"])
    slack_token = "".join(["xoxb-", "123456789012-", "123456789012-", "abcdefghijklmnopqrstuvwx"])
    private_key_marker = "".join(["-----BEGIN ", "RSA PRIVATE KEY", "-----"])

    positives = [
        f"The AWS access key is {aws_access_key} for staging.",
        f"Use aws_secret_access_key={aws_secret_key}.",
        f"GitHub token: {github_token}",
        f"Stripe live key {stripe_key}",
        f"Slack token {slack_token}",
        "Database URL is postgres://admin:secretpass123@db.example.com:5432/app.",
        "Redis URL redis://:redispass123@cache.example.com:6379/0 should be rotated.",
        f"Private key starts {private_key_marker} MIIEpAIBAAKCAQEAfake",
        "The staging password is banana, please log in and restart the service.",
        "My API key is abc123-super-secret-token-for-prod; add it to config.",
    ]
    negatives = [
        "Please explain how password rotation should work for production services.",
        "Write a checklist for storing API keys in environment variables.",
        "Use placeholders like YOUR_API_KEY in documentation instead of real secrets.",
        "The word secret appears in this policy document but no credential is present.",
        "Create a training note about never pasting private keys into chat tools.",
        "Rotate tokens every 90 days and document who owns each integration.",
        "The example database URL should omit username, password, and host details.",
        "A secure reset link should expire quickly and require MFA.",
        "Describe how to detect credentials in source code without showing any.",
        "The sample value is <redacted> and should stay redacted.",
    ]

    for repeat in range(6):
        for index, text in enumerate(positives, start=1):
            add(
                f"synthetic_secret_pos_{repeat + 1}_{index:02d}",
                "prompt",
                "secret",
                text,
                True,
                ["secrets"],
            )
        for index, text in enumerate(negatives, start=1):
            add(
                f"synthetic_secret_neg_{repeat + 1}_{index:02d}",
                "prompt",
                "secret",
                text,
                False,
                [],
            )


def run_benchmark(dataset: Path, cache_dir: Path) -> None:
    """Run the SentinelGuard benchmark and write summary/failure files."""
    summary_path = cache_dir / "normalized" / "external_security_benchmark_summary.json"
    failures_path = cache_dir / "normalized" / "external_security_benchmark_failures.jsonl"

    cases = security_benchmark.load_cases(dataset)
    guard = security_benchmark.build_benchmark_guard()
    security_benchmark.warmup_guard(guard)
    results = [security_benchmark.run_case(guard, case) for case in cases]
    summary = security_benchmark.summarize(results)

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with failures_path.open("w", encoding="utf-8") as handle:
        for result in results:
            if result.outcome in {"fp", "fn"}:
                handle.write(json.dumps(result.to_dict()) + "\n")

    print(f"Summary: {summary_path}")
    print(f"Failures: {failures_path}")
    print(f"Overall: {summary['overall']}")
    print(f"Latency: {summary['latency']}")
    for category, metrics in summary["by_category"].items():
        print(f"{category}: {metrics}")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run public SentinelGuard security benchmarks")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--run", action="store_true", help="Run benchmark after normalization")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.skip_download:
        paths = {filename: args.cache_dir / "raw" / filename for filename, _ in SOURCES}
    else:
        paths = download_sources(args.cache_dir)

    missing = [path for path in paths.values() if not path.exists()]
    if missing:
        for path in missing:
            print(f"Missing source file: {path}")
        return 1

    dataset = build_dataset(args.cache_dir, paths)
    if args.run:
        run_benchmark(dataset, args.cache_dir)
    else:
        print(f"Run: python benchmarks/security.py --dataset {dataset}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
