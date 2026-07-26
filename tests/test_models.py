"""Tests for optional model warmup helpers."""

from sentinelguard.models import (
    get_model,
    model_status,
    normalize_model_mode,
    reset_model_cache,
    resolve_model,
    start_background_warmup,
)


def test_normalize_model_mode():
    assert normalize_model_mode(True) == "sync"
    assert normalize_model_mode(False) == "disabled"
    assert normalize_model_mode("auto") == "auto"
    assert normalize_model_mode("background") == "auto"
    assert normalize_model_mode("yes") == "sync"
    assert normalize_model_mode("off") == "disabled"


def test_start_background_warmup_respects_disable_env():
    start_background_warmup(["prompt_injection"])

    status = model_status()["prompt_injection"]
    assert status["status"] == "disabled"
    assert status["error"] is None
    assert get_model("prompt_injection") is None


def test_start_background_warmup_marks_unavailable_without_dependencies(monkeypatch):
    reset_model_cache()
    monkeypatch.delenv("SENTINELGUARD_DISABLE_MODEL_WARMUP", raising=False)
    monkeypatch.setattr("sentinelguard.models.model_dependencies_available", lambda: False)

    start_background_warmup(["jailbreak"])

    status = model_status()["jailbreak"]
    assert status["status"] == "unavailable"
    assert "sentinelguard[models]" in status["error"]


def test_auto_resolve_starts_warmup_without_blocking(monkeypatch):
    reset_model_cache()
    requested = []

    def fake_start_background_warmup(names):
        requested.extend(names)

    monkeypatch.setattr(
        "sentinelguard.models.start_background_warmup",
        fake_start_background_warmup,
    )

    model = resolve_model("toxicity", "auto")

    assert model is None
    assert requested == ["toxicity"]


def test_model_status_includes_secrets_classifier():
    status = model_status()["secrets"]
    assert status["model_id"] == "valhalla/distilbart-mnli-12-1"
    assert status["status"] == "not_started"


def test_model_status_includes_custom_prompt_guard_alias(monkeypatch):
    reset_model_cache()
    monkeypatch.delenv("SENTINELGUARD_DISABLE_MODEL_WARMUP", raising=False)
    monkeypatch.setattr("sentinelguard.models.model_dependencies_available", lambda: False)

    start_background_warmup([("prompt_injection", "prompt_guard_86m")])

    status = model_status()["prompt_injection:meta-llama/Prompt-Guard-86M"]
    assert status["model_id"] == "meta-llama/Prompt-Guard-86M"
    assert status["status"] == "unavailable"


def test_sync_resolve_loads_immediately(monkeypatch):
    reset_model_cache()

    class FakeModel:
        pass

    fake_model = FakeModel()
    monkeypatch.delenv("SENTINELGUARD_DISABLE_MODEL_WARMUP", raising=False)
    monkeypatch.setattr("sentinelguard.models.model_dependencies_available", lambda: True)
    monkeypatch.setattr("sentinelguard.models._load_one", lambda key, spec: fake_model)

    assert resolve_model("bias", True) is fake_model


def test_env_model_override_is_used(monkeypatch):
    reset_model_cache()
    monkeypatch.delenv("SENTINELGUARD_DISABLE_MODEL_WARMUP", raising=False)
    monkeypatch.setenv("SENTINELGUARD_PROMPT_INJECTION_MODEL_ID", "prompt_guard_86m")
    monkeypatch.setattr("sentinelguard.models.model_dependencies_available", lambda: False)

    resolve_model("prompt_injection", True)

    status = model_status()["prompt_injection:meta-llama/Prompt-Guard-86M"]
    assert status["model_id"] == "meta-llama/Prompt-Guard-86M"
