"""Optional model warmup and cache helpers for SentinelGuard.

The core package works without Hugging Face model dependencies. When users
install ``sentinelguard[models]``, this module can warm classifiers in the
background so scanners can use them once ready without blocking requests.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModelSpec:
    """Definition for an optional Hugging Face classifier."""

    name: str
    model_id: str
    task: str = "text-classification"
    pipeline_kwargs: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class ModelState:
    """Current warmup status for one optional model."""

    status: str = "not_started"
    error: Optional[str] = None


MODEL_SPECS: Dict[str, ModelSpec] = {
    "prompt_injection": ModelSpec(
        name="prompt_injection",
        model_id="protectai/deberta-v3-base-prompt-injection-v2",
    ),
    "jailbreak": ModelSpec(
        name="jailbreak",
        model_id="jackhhao/jailbreak-classifier",
    ),
    "toxicity": ModelSpec(
        name="toxicity",
        model_id="unitary/toxic-bert",
        pipeline_kwargs={"top_k": None},
    ),
    "bias": ModelSpec(
        name="bias",
        model_id="facebook/roberta-hate-speech-dynabench-r4-target",
    ),
    "secrets": ModelSpec(
        name="secrets",
        model_id="valhalla/distilbart-mnli-12-1",
        task="zero-shot-classification",
    ),
}

_MODELS: Dict[str, Any] = {}
_STATES: Dict[str, ModelState] = {name: ModelState() for name in MODEL_SPECS}
_LOCK = threading.RLock()


def normalize_model_mode(value: Any) -> str:
    """Normalize scanner ``use_model`` values to disabled, auto, or sync."""
    if isinstance(value, bool):
        return "sync" if value else "disabled"

    text = str(value).strip().lower()
    if text in {"auto", "background", "warmup"}:
        return "auto"
    if text in {"1", "true", "yes", "on", "sync", "blocking"}:
        return "sync"
    return "disabled"


def model_dependencies_available() -> bool:
    """Return True when optional Hugging Face runtime dependencies exist."""
    return (
        importlib.util.find_spec("transformers") is not None
        and importlib.util.find_spec("torch") is not None
    )


def warmup_disabled() -> bool:
    """Return True when model warmup has been disabled through env config."""
    value = os.getenv("SENTINELGUARD_DISABLE_MODEL_WARMUP", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_model(name: str) -> Optional[Any]:
    """Return a ready model pipeline, or None if it is not ready."""
    with _LOCK:
        return _MODELS.get(name)


def model_status() -> Dict[str, Dict[str, Optional[str]]]:
    """Return current status for all optional models."""
    with _LOCK:
        return {
            name: {
                "model_id": MODEL_SPECS[name].model_id,
                "status": state.status,
                "error": state.error,
            }
            for name, state in _STATES.items()
        }


def reset_model_cache() -> None:
    """Clear cached models and warmup state.

    This is mainly useful for tests and for long-running processes that want
    to explicitly retry model warmup after changing their environment.
    """
    with _LOCK:
        _MODELS.clear()
        for name in MODEL_SPECS:
            _STATES[name] = ModelState()


def start_background_warmup(model_names: Optional[Iterable[str]] = None) -> None:
    """Start warming optional models in a daemon thread.

    This function returns immediately. If dependencies are missing or warmup is
    disabled, it records status and does not start network work.
    """
    if warmup_disabled():
        _mark_many(model_names or MODEL_SPECS, "disabled", None)
        return

    names = _requested_model_names(model_names)
    if not names:
        return

    if not model_dependencies_available():
        _mark_many(names, "unavailable", "Install sentinelguard[models] to enable models")
        return

    pending = []
    with _LOCK:
        for name in names:
            state = _STATES[name]
            if state.status in {"ready", "loading", "failed", "unavailable", "disabled"}:
                continue
            state.status = "loading"
            state.error = None
            pending.append(name)

    if not pending:
        return

    thread = threading.Thread(
        target=_warmup_many,
        args=(pending,),
        name="sentinelguard-model-warmup",
        daemon=True,
    )
    thread.start()


def resolve_model(name: str, mode: Any) -> Optional[Any]:
    """Resolve a model for scanner inference without blocking auto mode."""
    normalized = normalize_model_mode(mode)
    if normalized == "disabled":
        return None

    if normalized == "auto":
        model = get_model(name)
        if model is None:
            start_background_warmup([name])
        return model

    return load_model_now(name)


def load_model_now(name: str) -> Optional[Any]:
    """Load one optional model synchronously."""
    if warmup_disabled():
        _mark_one(name, "disabled", None)
        return None
    if not model_dependencies_available():
        _mark_one(name, "unavailable", "Install sentinelguard[models] to enable models")
        return None

    with _LOCK:
        if name in _MODELS:
            return _MODELS[name]
        if name not in MODEL_SPECS:
            return None
        _STATES[name].status = "loading"
        _STATES[name].error = None

    return _load_one(name)


def warmup_for_scanners(scanners: Iterable[Any]) -> None:
    """Warm models for scanner instances configured with auto model mode."""
    names = []
    for scanner in scanners:
        if normalize_model_mode(getattr(scanner, "use_model", False)) == "auto":
            name = getattr(scanner, "scanner_name", "")
            if name in MODEL_SPECS:
                names.append(name)
    start_background_warmup(names)


def _warmup_many(names: Iterable[str]) -> None:
    for name in names:
        _load_one(name)


def _load_one(name: str) -> Optional[Any]:
    spec = MODEL_SPECS.get(name)
    if spec is None:
        return None

    try:
        from transformers import pipeline as hf_pipeline

        logger.info("Warming SentinelGuard model: %s", spec.model_id)
        model = hf_pipeline(
            spec.task,
            model=spec.model_id,
            **dict(spec.pipeline_kwargs),
        )
    except Exception as exc:
        logger.warning("Model warmup failed for %s: %s", name, exc)
        _mark_one(name, "failed", str(exc))
        return None

    with _LOCK:
        _MODELS[name] = model
        _STATES[name].status = "ready"
        _STATES[name].error = None
    return model


def _requested_model_names(model_names: Optional[Iterable[str]]) -> list[str]:
    if model_names is None:
        return list(MODEL_SPECS)
    return [name for name in dict.fromkeys(model_names) if name in MODEL_SPECS]


def _mark_many(names: Iterable[str], status: str, error: Optional[str]) -> None:
    for name in _requested_model_names(names):
        _mark_one(name, status, error)


def _mark_one(name: str, status: str, error: Optional[str]) -> None:
    if name not in _STATES:
        return
    with _LOCK:
        _STATES[name].status = status
        _STATES[name].error = error
