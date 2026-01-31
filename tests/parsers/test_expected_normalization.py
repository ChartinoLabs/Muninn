"""Ensure expected outputs use canonical interface names."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypeAlias

from netutils.interface import canonical_interface_name

PARSERS_TEST_DIR = Path(__file__).parent

JSONValue: TypeAlias = (
    dict[str, "JSONValue"] | list["JSONValue"] | str | int | float | bool | None
)


def _looks_like_interface(value: str) -> bool:
    return any(char.isdigit() for char in value) and any(
        char.isalpha() for char in value
    )


def _normalize_string(value: str) -> str:
    if _looks_like_interface(value):
        return canonical_interface_name(value)
    return value


def _normalize(value: JSONValue) -> JSONValue:
    if isinstance(value, dict):
        normalized: dict[str, JSONValue] = {}
        for key, item in value.items():
            norm_key = _normalize_string(key) if isinstance(key, str) else key
            normalized[norm_key] = _normalize(item)
        return normalized
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, str):
        return _normalize_string(value)
    return value


def _discover_expected_files() -> list[Path]:
    return sorted(PARSERS_TEST_DIR.glob("**/expected.json"))


def _find_null_paths(value: JSONValue, path: str = "") -> list[str]:
    """Find all paths in a JSON structure that have null values.

    Args:
        value: JSON value to search.
        path: Current path in the structure.

    Returns:
        List of paths to null values.
    """
    null_paths: list[str] = []

    if value is None:
        null_paths.append(path)
    elif isinstance(value, dict):
        for key, item in value.items():
            new_path = f"{path}.{key}" if path else key
            null_paths.extend(_find_null_paths(item, new_path))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            new_path = f"{path}[{i}]"
            null_paths.extend(_find_null_paths(item, new_path))

    return null_paths


def test_expected_outputs_contain_no_null_values() -> None:
    """Ensure expected outputs do not contain null values.

    Optional fields should be omitted entirely rather than set to null.
    This ensures parsers follow the convention of excluding optional
    fields when they have no value.
    """
    failures: dict[str, list[str]] = {}

    for expected_path in _discover_expected_files():
        expected = json.loads(expected_path.read_text())
        null_paths = _find_null_paths(expected)
        if null_paths:
            relative_path = str(expected_path.relative_to(PARSERS_TEST_DIR))
            failures[relative_path] = null_paths

    if failures:
        msg_parts = ["Expected outputs contain null values:"]
        for file_path, paths in sorted(failures.items()):
            msg_parts.append(f"  {file_path}:")
            for p in paths:
                msg_parts.append(f"    - {p}")
        raise AssertionError("\n".join(msg_parts))


def test_expected_outputs_use_canonical_interfaces() -> None:
    """Ensure expected outputs use canonical interface names."""
    failures: list[str] = []

    for expected_path in _discover_expected_files():
        expected = json.loads(expected_path.read_text())
        normalized = _normalize(expected)
        if normalized != expected:
            failures.append(str(expected_path.relative_to(PARSERS_TEST_DIR)))

    assert not failures, (
        "Expected outputs contain unnormalized interface names: "
        + ", ".join(sorted(failures))
    )
