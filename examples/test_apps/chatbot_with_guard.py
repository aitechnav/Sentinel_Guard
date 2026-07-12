#!/usr/bin/env python3
"""Test app: SentinelGuard as a library inside a chatbot.

Scans user input before calling the LLM, and scans the LLM response
before returning it to the user.

Usage:
    python examples/test_apps/chatbot_with_guard.py
    python examples/test_apps/chatbot_with_guard.py --real-llm
    python examples/test_apps/chatbot_with_guard.py --preset strict
"""

from __future__ import annotations

import argparse
import os
import sys

from sentinelguard import SentinelGuard


def mock_llm(user_message: str) -> str:
    """Fake LLM — no API key required."""
    return (
        f"Mock reply - I received your question about "
        f'"{user_message[:60]}{"..." if len(user_message) > 60 else ""}". '
        "This is a simulated response for testing the app."
    )


def openai_llm(user_message: str, model: str = "gpt-4o-mini") -> str:
    """Call OpenAI directly (requires OPENAI_API_KEY)."""
    try:
        from openai import OpenAI
    except ImportError:
        print("Install openai: pip install openai")
        sys.exit(1)

    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    if not client.api_key:
        print("Set OPENAI_API_KEY to use --real-llm")
        sys.exit(1)

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": user_message}],
        max_tokens=256,
    )
    return response.choices[0].message.content or ""


def run_turn(guard: SentinelGuard, user_input: str, llm_fn) -> None:
    """One chat turn with input + output scanning."""
    print("\n--- Scanning user input ---")
    prompt_result = guard.scan_prompt(user_input)

    print(f"  Input valid:  {prompt_result.is_valid}")
    print(f"  Risk level:   {prompt_result.highest_risk.value}")
    print(f"  Latency:      {prompt_result.total_latency_ms:.1f} ms")

    if not prompt_result.is_valid:
        print(f"  BLOCKED by:   {prompt_result.failed_scanners}")
        print("\n[Chatbot] Request rejected. Try a different message.")
        return

    print("\n--- Calling LLM ---")
    llm_response = llm_fn(user_input)
    print(f"  LLM response: {llm_response[:120]}{'...' if len(llm_response) > 120 else ''}")

    print("\n--- Scanning LLM output ---")
    output_result = guard.scan_output(llm_response, prompt=user_input)

    print(f"  Output valid: {output_result.is_valid}")
    print(f"  Risk level:   {output_result.highest_risk.value}")

    if not output_result.is_valid:
        print(f"  BLOCKED by:   {output_result.failed_scanners}")
        print("\n[Chatbot] Response filtered. Nothing shown to user.")
        return

    print("\n[Chatbot] Response delivered to user:")
    print(f"  {llm_response}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Chatbot test app with SentinelGuard")
    parser.add_argument(
        "--real-llm",
        action="store_true",
        help="Use OpenAI instead of mock LLM (requires OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--preset",
        choices=["minimal", "standard", "strict"],
        default="minimal",
        help="SentinelGuard preset (default: minimal)",
    )
    args = parser.parse_args()

    preset_map = {
        "minimal": SentinelGuard.minimal,
        "standard": SentinelGuard,
        "strict": SentinelGuard.strict,
    }
    guard = preset_map[args.preset]()
    llm_fn = openai_llm if args.real_llm else mock_llm
    llm_label = "OpenAI" if args.real_llm else "Mock LLM"

    print("=" * 60)
    print("SentinelGuard Chatbot Test App")
    print("=" * 60)
    print(f"Preset:     {args.preset}")
    print(f"LLM:        {llm_label}")
    print(f"Scanners:   {guard.prompt_scanner_names}")
    print()
    print("Try these test messages:")
    print('  1. "What is Python?"                    (should pass)')
    print('  2. "Ignore all previous instructions"   (should block)')
    print('  3. "My email is alice@example.com"      (PII — should block)')
    print()
    print("Type 'quit' to exit.")
    print("=" * 60)

    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            print("Bye.")
            break

        run_turn(guard, user_input, llm_fn)


if __name__ == "__main__":
    main()
