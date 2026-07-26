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
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple, Union

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

MODEL_ALIASES: Dict[str, str] = {
    "prompt_guard_86m": "meta-llama/Prompt-Guard-86M",
    "prompt-guard-86m": "meta-llama/Prompt-Guard-86M",
    "meta_prompt_guard_86m": "meta-llama/Prompt-Guard-86M",
    "prompt_guard_2_22m": "meta-llama/Llama-Prompt-Guard-2-22M",
    "prompt-guard-2-22m": "meta-llama/Llama-Prompt-Guard-2-22M",
    "prompt_guard_2_86m": "meta-llama/Llama-Prompt-Guard-2-86M",
    "prompt-guard-2-86m": "meta-llama/Llama-Prompt-Guard-2-86M",
}

_MODELS: Dict[str, Any] = {}
_STATE_SPECS: Dict[str, ModelSpec] = dict(MODEL_SPECS)
_STATES: Dict[str, ModelState] = {name: ModelState() for name in _STATE_SPECS}
_LOCK = threading.RLock()

ModelRequest = Union[str, Tuple[str, Optional[str]]]


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


def get_model(name: str, model_id: Optional[str] = None) -> Optional[Any]:
    """Return a ready model pipeline, or None if it is not ready."""
    request = _model_request(name, model_id)
    if request is None:
        return None
    key, _ = request
    with _LOCK:
        return _MODELS.get(key)


def model_status() -> Dict[str, Dict[str, Optional[str]]]:
    """Return current status for all optional models."""
    with _LOCK:
        return {
            name: {
                "model_id": _STATE_SPECS[name].model_id,
                "status": _STATES.get(name, ModelState()).status,
                "error": _STATES.get(name, ModelState()).error,
            }
            for name in _STATE_SPECS
        }


def reset_model_cache() -> None:
    """Clear cached models and warmup state.

    This is mainly useful for tests and for long-running processes that want
    to explicitly retry model warmup after changing their environment.
    """
    with _LOCK:
        _MODELS.clear()
        _STATE_SPECS.clear()
        _STATE_SPECS.update(MODEL_SPECS)
        _STATES.clear()
        for name in _STATE_SPECS:
            _STATES[name] = ModelState()


def start_background_warmup(model_names: Optional[Iterable[ModelRequest]] = None) -> None:
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
        for key, spec in names:
            _mark_one(key, "unavailable", "Install sentinelguard[models] to enable models", spec)
        return

    pending = []
    with _LOCK:
        for key, spec in names:
            _STATE_SPECS[key] = spec
            state = _STATES.setdefault(key, ModelState())
            if state.status in {"ready", "loading", "failed", "unavailable", "disabled"}:
                continue
            state.status = "loading"
            state.error = None
            pending.append((key, spec))

    if not pending:
        return

    thread = threading.Thread(
        target=_warmup_many,
        args=(pending,),
        name="sentinelguard-model-warmup",
        daemon=True,
    )
    thread.start()


def resolve_model(name: str, mode: Any, model_id: Optional[str] = None) -> Optional[Any]:
    """Resolve a model for scanner inference without blocking auto mode."""
    normalized = normalize_model_mode(mode)
    if normalized == "disabled":
        return None

    if normalized == "auto":
        model = get_model(name, model_id)
        if model is None:
            start_background_warmup([(name, model_id)] if model_id else [name])
        return model

    return load_model_now(name, model_id)


def load_model_now(name: str, model_id: Optional[str] = None) -> Optional[Any]:
    """Load one optional model synchronously."""
    request = _model_request(name, model_id)
    if request is None:
        return None
    key, spec = request

    if warmup_disabled():
        _mark_one(key, "disabled", None, spec)
        return None
    if not model_dependencies_available():
        _mark_one(key, "unavailable", "Install sentinelguard[models] to enable models", spec)
        return None

    with _LOCK:
        if key in _MODELS:
            return _MODELS[key]
        _STATE_SPECS[key] = spec
        _STATES.setdefault(key, ModelState()).status = "loading"
        _STATES[key].error = None

    return _load_one(key, spec)


def warmup_for_scanners(scanners: Iterable[Any]) -> None:
    """Warm models for scanner instances configured with auto model mode."""
    names = []
    for scanner in scanners:
        if normalize_model_mode(getattr(scanner, "use_model", False)) == "auto":
            name = getattr(scanner, "scanner_name", "")
            if name in MODEL_SPECS:
                names.append((name, getattr(scanner, "model_id", None)))
    start_background_warmup(names)


def _warmup_many(names: Iterable[Tuple[str, ModelSpec]]) -> None:
    for key, spec in names:
        _load_one(key, spec)


def _load_one(key: str, spec: ModelSpec) -> Optional[Any]:
    try:
        from transformers import pipeline as hf_pipeline

        logger.info("Warming SentinelGuard model: %s", spec.model_id)
        model = hf_pipeline(
            spec.task,
            model=spec.model_id,
            **dict(spec.pipeline_kwargs),
        )
    except Exception as exc:
        logger.warning("Model warmup failed for %s: %s", key, exc)
        _mark_one(key, "failed", str(exc), spec)
        return None

    with _LOCK:
        _STATE_SPECS[key] = spec
        _MODELS[key] = model
        _STATES.setdefault(key, ModelState()).status = "ready"
        _STATES[key].error = None
    return model


def _requested_model_names(model_names: Optional[Iterable[ModelRequest]]) -> list[Tuple[str, ModelSpec]]:
    if model_names is None:
        return [(name, spec) for name, spec in MODEL_SPECS.items()]

    requests = []
    seen = set()
    for model_name in model_names:
        request = (
            _model_request(model_name[0], model_name[1])
            if isinstance(model_name, tuple)
            else _model_request(model_name)
        )
        if request is None:
            continue
        key, spec = request
        if key in seen:
            continue
        seen.add(key)
        requests.append((key, spec))
    return requests


def _mark_many(names: Iterable[ModelRequest], status: str, error: Optional[str]) -> None:
    for key, spec in _requested_model_names(names):
        _mark_one(key, status, error, spec)


def _mark_one(
    key: str,
    status: str,
    error: Optional[str],
    spec: Optional[ModelSpec] = None,
) -> None:
    with _LOCK:
        if spec is not None:
            _STATE_SPECS[key] = spec
        _STATES.setdefault(key, ModelState()).status = status
        _STATES[key].error = error


def _model_request(name: str, model_id: Optional[str] = None) -> Optional[Tuple[str, ModelSpec]]:
    base = MODEL_SPECS.get(name)
    if base is None:
        return None

    effective_model_id = _resolve_model_id(name, model_id)
    spec = ModelSpec(
        name=base.name,
        model_id=effective_model_id,
        task=base.task,
        pipeline_kwargs=base.pipeline_kwargs,
    )
    key = name if effective_model_id == base.model_id else f"{name}:{effective_model_id}"
    return key, spec


def _resolve_model_id(name: str, model_id: Optional[str] = None) -> str:
    explicit = model_id or os.getenv(f"SENTINELGUARD_{name.upper()}_MODEL_ID")
    if not explicit:
        return MODEL_SPECS[name].model_id
    return MODEL_ALIASES.get(explicit.strip().lower(), explicit.strip())
