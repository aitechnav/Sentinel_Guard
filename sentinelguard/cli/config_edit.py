"""Small YAML editing helpers for the SentinelGuard CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml_mapping(path: str | Path) -> dict[str, Any]:
    """Load a YAML file whose root value must be a mapping."""
    yaml_path = Path(path)
    if not yaml_path.exists():
        raise FileNotFoundError(f"Config file not found: {yaml_path}")

    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file root must be a mapping: {yaml_path}")
    return data


def save_yaml_mapping(path: str | Path, data: dict[str, Any]) -> None:
    """Write a YAML mapping with stable, readable key order."""
    yaml_path = Path(path)
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(
        yaml.safe_dump(data, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


def parse_cli_value(value: str) -> Any:
    """Parse a CLI value as YAML, so true/3/0.4/[a, b] become typed values."""
    parsed = yaml.safe_load(value)
    if parsed is None and value.strip().lower() not in {"null", "none", "~"}:
        return value
    return parsed


def format_cli_value(value: Any) -> str:
    """Format a value for compact CLI output."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        return yaml.safe_dump(value, sort_keys=False, default_flow_style=False).rstrip()
    return str(value)


def get_path(data: dict[str, Any], dotted_path: str) -> Any:
    """Read a value from a dotted YAML path with numeric list indexes."""
    current: Any = data
    for segment in _split_path(dotted_path):
        if isinstance(current, dict):
            if segment not in current:
                raise KeyError(f"Path not found: {dotted_path}")
            current = current[segment]
        elif isinstance(current, list):
            index = _list_index(segment, dotted_path)
            if index >= len(current):
                raise IndexError(f"List index out of range in path: {dotted_path}")
            current = current[index]
        else:
            raise KeyError(f"Path cannot continue through scalar value: {dotted_path}")
    return current


def set_path(data: dict[str, Any], dotted_path: str, value: Any) -> None:
    """Set a value in a dotted YAML path, creating mapping segments as needed."""
    segments = _split_path(dotted_path)
    current: Any = data

    for position, segment in enumerate(segments[:-1]):
        next_segment = segments[position + 1]
        if isinstance(current, dict):
            if segment not in current or current[segment] is None:
                current[segment] = [] if next_segment.isdigit() else {}
            child = current[segment]
            if not isinstance(child, (dict, list)):
                raise ValueError(f"Path segment is not editable: {segment}")
            current = child
        elif isinstance(current, list):
            index = _list_index(segment, dotted_path)
            if index >= len(current):
                raise IndexError(f"List index out of range in path: {dotted_path}")
            child = current[index]
            if child is None:
                child = [] if next_segment.isdigit() else {}
                current[index] = child
            if not isinstance(child, (dict, list)):
                raise ValueError(f"Path segment is not editable: {segment}")
            current = child
        else:
            raise ValueError(f"Path cannot continue through scalar value: {dotted_path}")

    final_segment = segments[-1]
    if isinstance(current, dict):
        current[final_segment] = value
        return

    if isinstance(current, list):
        index = _list_index(final_segment, dotted_path)
        if index >= len(current):
            raise IndexError(f"List index out of range in path: {dotted_path}")
        current[index] = value
        return

    raise ValueError(f"Path cannot be updated: {dotted_path}")


def set_scanner_enabled(
    data: dict[str, Any],
    *,
    scanner_type: str,
    scanner_name: str,
    enabled: bool,
) -> str:
    """Toggle a scanner in a SentinelGuard scanner config mapping."""
    scanner_group = f"{scanner_type}_scanners"
    scanners = data.setdefault(scanner_group, {})
    if not isinstance(scanners, dict):
        raise ValueError(f"{scanner_group} must be a mapping")

    current = scanners.get(scanner_name)
    if current is None or isinstance(current, bool):
        scanners[scanner_name] = {"enabled": enabled}
    elif isinstance(current, dict):
        current["enabled"] = enabled
    else:
        raise ValueError(f"{scanner_group}.{scanner_name} must be a mapping or boolean")

    return f"{scanner_group}.{scanner_name}.enabled"


def _split_path(dotted_path: str) -> list[str]:
    segments = [segment for segment in dotted_path.split(".") if segment]
    if not segments:
        raise ValueError("Path must not be empty")
    return segments


def _list_index(segment: str, dotted_path: str) -> int:
    try:
        index = int(segment)
    except ValueError as exc:
        raise KeyError(f"Expected list index in path: {dotted_path}") from exc
    if index < 0:
        raise IndexError(f"Negative list index is not supported in path: {dotted_path}")
    return index
