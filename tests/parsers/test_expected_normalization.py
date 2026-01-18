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
