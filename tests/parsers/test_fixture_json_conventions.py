"""Conventions for ``expected.json`` parser fixtures.

Muninn prefers keyed dicts over lists of dicts when a natural identifier exists;
see ``docs/01-design-principles.md`` section 4. This module enforces that for new and
changed fixtures while allowing explicit exemptions in ``list_of_dicts_allowlist.yaml``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

JsonPath = tuple[str | int, ...]


def _path_to_json_pointer(path: JsonPath) -> str:
    r"""Encode a tuple path as RFC 6901 JSON Pointer (``/a/0/b``; root is ``""``)."""
    if not path:
        return ""
    parts: list[str] = []
    for seg in path:
        if isinstance(seg, int):
            parts.append(str(seg))
        else:
            s = str(seg).replace("~", "~0").replace("/", "~1")
            parts.append(s)
    return "/" + "/".join(parts)


def _find_list_of_dict_paths(obj: object, path: JsonPath = ()) -> list[JsonPath]:
    """Return paths to every non-empty list whose items are all dicts."""
    found: list[JsonPath] = []
    if isinstance(obj, list):
        if len(obj) >= 1 and all(isinstance(x, dict) for x in obj):
            found.append(path)
        for i, item in enumerate(obj):
            found.extend(_find_list_of_dict_paths(item, path + (i,)))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                msg = f"Expected string dict keys in JSON, got {type(k).__name__}"
                raise TypeError(msg)
            found.extend(_find_list_of_dict_paths(v, path + (k,)))
    return found


PARSERS_TEST_DIR = Path(__file__).parent
ALLOWLIST_PATH = PARSERS_TEST_DIR / "list_of_dicts_allowlist.yaml"


def _read_allowlist_from_disk() -> dict[str, Any]:
    """Load and validate ``list_of_dicts_allowlist.yaml`` once at import time."""
    raw = yaml.safe_load(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1:
        msg = f"Invalid allowlist schema in {ALLOWLIST_PATH}"
        raise ValueError(msg)
    allow = raw.get("allowlist")
    if not isinstance(allow, dict):
        msg = f"Missing allowlist mapping in {ALLOWLIST_PATH}"
        raise ValueError(msg)
    return raw


# Eager load so the suite does not re-read YAML thousands of times and so a
# missing file fails fast at collection/import (not mid-run if the path races).
_ALLOWLIST_RAW: dict[str, Any] = _read_allowlist_from_disk()


def _discover_expected_json_files() -> list[Path]:
    paths: list[Path] = []
    for p in sorted(PARSERS_TEST_DIR.rglob("expected.json")):
        rel = p.relative_to(PARSERS_TEST_DIR)
        if rel.parts and rel.parts[0].startswith("_"):
            continue
        paths.append(p)
    return paths


def _filter_violations(
    file_rel: str,
    violations: list[tuple[str | int, ...]],
    allowlist_raw: dict[str, Any],
) -> list[tuple[str | int, ...]]:
    entry = allowlist_raw["allowlist"].get(file_rel)
    if entry is None:
        return violations
    if isinstance(entry, dict):
        pointers = entry.get("pointers")
        if not isinstance(pointers, list):
            msg = f"Invalid pointers for allowlist entry {file_rel!r}"
            raise ValueError(msg)
        if not all(isinstance(p, str) for p in pointers):
            msg = f"Invalid pointers for allowlist entry {file_rel!r}"
            raise ValueError(msg)
        if "*" in pointers:
            return []
        exempt = set(pointers)
        return [v for v in violations if _path_to_json_pointer(v) not in exempt]
    msg = f"Allowlist entry for {file_rel!r} must be a mapping with pointers"
    raise ValueError(msg)


@pytest.mark.parametrize(
    "expected_path",
    _discover_expected_json_files(),
    ids=lambda p: p.relative_to(PARSERS_TEST_DIR).as_posix(),
)
def test_expected_json_avoids_list_of_dicts(
    expected_path: Path,
) -> None:
    r"""Fail when a fixture contains a list whose elements are all dicts.

    Exemptions are listed in ``list_of_dicts_allowlist.yaml`` (per file, with
    ``pointers: ["*"]`` to exempt all occurrences in that file, or specific
    JSON Pointers for partial exemptions).
    """
    allowlist_raw = _ALLOWLIST_RAW
    rel = expected_path.relative_to(PARSERS_TEST_DIR).as_posix()
    data = json.loads(expected_path.read_text(encoding="utf-8"))
    violations = _find_list_of_dict_paths(data)
    remaining = _filter_violations(rel, violations, allowlist_raw)

    if remaining:
        lines = "\n".join(
            f"  - {_path_to_json_pointer(p) or '(document root)'}"
            for p in remaining[:50]
        )
        more = ""
        if len(remaining) > 50:
            more = f"\n  ... and {len(remaining) - 50} more"
        msg = (
            f"{rel} contains list-of-dicts at JSON Pointer path(s). Prefer keyed "
            f"dicts per docs/01-design-principles.md section 4, or add an exemption "
            f"with a reason in {ALLOWLIST_PATH.name}.\n{lines}{more}"
        )
        pytest.fail(msg)
