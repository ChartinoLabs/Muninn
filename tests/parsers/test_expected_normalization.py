"""Ensure expected outputs use canonical interface names."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypeAlias

from muninn.os import OS, resolve_os
from muninn.utils import canonical_interface_name

PARSERS_TEST_DIR = Path(__file__).parent


def _build_dir_to_os() -> dict[str, OS]:
    """Build mapping from test directory names to OS enum members."""
    mapping: dict[str, OS] = {}
    for child in sorted(PARSERS_TEST_DIR.iterdir()):
        if not child.is_dir():
            continue
        try:
            mapping[child.name] = resolve_os(child.name)
        except (ValueError, TypeError):
            continue
    return mapping


_DIR_TO_OS: dict[str, OS] = _build_dir_to_os()

JSONValue: TypeAlias = (
    dict[str, "JSONValue"] | list["JSONValue"] | str | int | float | bool | None
)


def _looks_like_interface(value: str) -> bool:
    """Check if a string looks like a network interface name.

    Matches common Cisco interface naming patterns like:
    - GigabitEthernet0/0/0, Gi0/0/0
    - FastEthernet0/1, Fa0/1
    - Ethernet1/1, Eth1/1
    - TenGigabitEthernet1/0/1, Te1/0/1
    - Management0, mgmt0
    - Loopback0, Lo0
    - Vlan100
    - Port-channel1, Po1
    - Tunnel1, Tu1
    - Virtual-Access2.1, Vi2.1
    - Virtual-Template1, Vt1
    - ATM0/2/0.20, AT0/2/0.20
    - Dialer1, Di1
    """
    import re

    # Pattern for common interface prefixes followed by numbers/slashes
    interface_pattern = re.compile(
        r"^(?:Gi(?:gabitEthernet)?|Fa(?:stEthernet)?|Eth(?:ernet)?|"
        r"Te(?:nGigabitEthernet)?|Fo(?:rtyGigabitEthernet)?|"
        r"Hu(?:ndredGigE)?|mgmt|Management|Lo(?:opback)?|"
        r"Vlan|Po(?:rt-channel)?|Tu(?:nnel)?|Se(?:rial)?|"
        r"nve|BDI|Twe(?:ntyFiveGigE)?|"
        r"Virtual-Access|Virtual-Template|Vi|Vt|"
        r"ATM|AT|Dialer|Di|"
        r"MgmtEth|Mg|Nu(?:ll)?|tunnel-te|tt)\d",
        re.IGNORECASE,
    )
    return bool(interface_pattern.match(value))


def _normalize_string(value: str, *, os: OS | None = None) -> str:
    if _looks_like_interface(value):
        return canonical_interface_name(value, os=os)
    return value


def _normalize(value: JSONValue, *, os: OS | None = None) -> JSONValue:
    if isinstance(value, dict):
        normalized: dict[str, JSONValue] = {}
        for key, item in value.items():
            norm_key = _normalize_string(key, os=os) if isinstance(key, str) else key
            normalized[norm_key] = _normalize(item, os=os)
        return normalized
    if isinstance(value, list):
        return [_normalize(item, os=os) for item in value]
    if isinstance(value, str):
        return _normalize_string(value, os=os)
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
        rel = expected_path.relative_to(PARSERS_TEST_DIR)
        os_dir = rel.parts[0] if rel.parts else ""
        if os_dir not in _DIR_TO_OS:
            continue
        os_val = _DIR_TO_OS[os_dir]
        normalized = _normalize(expected, os=os_val)
        if normalized != expected:
            failures.append(str(expected_path.relative_to(PARSERS_TEST_DIR)))

    assert not failures, (
        "Expected outputs contain unnormalized interface names: "
        + ", ".join(sorted(failures))
    )
