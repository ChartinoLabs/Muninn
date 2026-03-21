"""Guardrails for CLI placeholder strings in ``expected.json`` fixtures.

When the device prints obvious “no value” sentinels, Muninn generally prefers
omitting the key (or using ``null`` if the schema uses optional fields) instead of
carrying strings like ``-`` or ``---`` through to structured output.

Some tokens are ambiguous: Cisco often prints ``NA`` / ``N/A`` as *meaningful*
labels (e.g. network-clocks ``SigType``, RADIUS statistics). Legacy fixtures that
still mirror those literals are listed below; **new** test cases are not exempt
unless their path is added explicitly (so new work does not silently reintroduce
placeholders).

Full-file exemptions are paths relative to ``tests/parsers/`` (same style as
``test_fixture_json_conventions.py``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

import pytest

JsonPath = tuple[str | int, ...]

_PLACEHOLDER_HYPHENS: Final[frozenset[str]] = frozenset({"-", "---"})
_PLACEHOLDER_NA_LIKE: Final[frozenset[str]] = frozenset({"NA", "N/A", "n/a"})

# Legacy fixtures still using hyphen / em-dash placeholders as string *values*.
_HYPHEN_PLACEHOLDER_EXEMPT_EXPECTED_FILES: Final[frozenset[str]] = frozenset(
    {
        "ios/show_mac_address-table/002_extended/expected.json",
        "iosxe/show_vpdn/001_basic/expected.json",
        "nxos/show_ip_arp_detail_vrf_all/002_incomplete_and_static/expected.json",
        "nxos/show_ip_ospf_neighbor/002_multi_vrf_with_roles/expected.json",
        "nxos/show_vpc/001_basic/expected.json",
    }
)

# Legacy fixtures where NA / N/A / n/a appear as CLI text (not always “null”).
_NA_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES: Final[frozenset[str]] = frozenset(
    {
        "ios/show_access-session/002_with_flags_and_unauth/expected.json",
        "ios/show_authentication_sessions/002_with_session_count/expected.json",
        "ios/show_ip_nat_translations/001_basic/expected.json",
        "iosxe/show_endpoint_tracker_records/001_basic/expected.json",
        "iosxe/show_network_clocks_synchronization/001_basic/expected.json",
        "iosxe/show_platform/003_asr903_chassis/expected.json",
        "iosxe/show_platform_nat_translations_active/001_basic/expected.json",
        "iosxe/show_power_inline_priority/002_with_oper_priority/expected.json",
        "iosxe/show_pppatm_session/001_basic/expected.json",
        "iosxe/show_radius_statistics/001_basic/expected.json",
    }
)

PARSERS_TEST_DIR = Path(__file__).parent


def _path_to_json_pointer(path: JsonPath) -> str:
    """Encode a tuple path as RFC 6901 JSON Pointer (``/a/0/b``; root is ``""``)."""
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


def _string_leaf_violations(
    obj: object,
    forbidden: frozenset[str],
    path: JsonPath = (),
) -> list[tuple[JsonPath, str]]:
    """Return (path, value) for string leaves equal to a forbidden sentinel."""
    out: list[tuple[JsonPath, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                msg = f"Expected string dict keys in JSON, got {type(k).__name__}"
                raise TypeError(msg)
            out.extend(_string_leaf_violations(v, forbidden, path + (k,)))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            out.extend(_string_leaf_violations(item, forbidden, path + (i,)))
    elif isinstance(obj, str):
        if obj in forbidden:
            out.append((path, obj))
    elif isinstance(obj, (bool, int, float)) or obj is None:
        pass
    else:
        msg = f"Unexpected JSON value type: {type(obj).__name__}"
        raise TypeError(msg)
    return out


def _discover_expected_json_files() -> list[Path]:
    """All ``expected.json`` paths under this directory (excluding ``_*`` OS dirs)."""
    paths: list[Path] = []
    for p in sorted(PARSERS_TEST_DIR.rglob("expected.json")):
        rel = p.relative_to(PARSERS_TEST_DIR)
        if rel.parts and rel.parts[0].startswith("_"):
            continue
        paths.append(p)
    return paths


@pytest.mark.parametrize(
    "expected_path",
    _discover_expected_json_files(),
    ids=lambda p: p.relative_to(PARSERS_TEST_DIR).as_posix(),
)
def test_expected_json_avoids_hyphen_placeholder_values(expected_path: Path) -> None:
    r"""Fail when a fixture uses ``-`` or ``---`` as a string value.

    Exempt entire ``expected.json`` files via
    ``_HYPHEN_PLACEHOLDER_EXEMPT_EXPECTED_FILES``.
    """
    rel = expected_path.relative_to(PARSERS_TEST_DIR).as_posix()
    data = json.loads(expected_path.read_text(encoding="utf-8"))
    violations = _string_leaf_violations(data, _PLACEHOLDER_HYPHENS)
    if rel in _HYPHEN_PLACEHOLDER_EXEMPT_EXPECTED_FILES:
        return
    if not violations:
        return
    lines = "\n".join(
        f"  - {_path_to_json_pointer(p)}: {value!r}" for p, value in violations[:50]
    )
    more = ""
    if len(violations) > 50:
        more = f"\n  ... and {len(violations) - 50} more"
    msg = (
        f"{rel} uses hyphen placeholder string value(s). Prefer omitting the key "
        f"(or null) instead of '-', or add the file to "
        f"_HYPHEN_PLACEHOLDER_EXEMPT_EXPECTED_FILES in "
        f"test_fixture_placeholder_sentinels.py.\n"
        f"{lines}{more}"
    )
    pytest.fail(msg)


@pytest.mark.parametrize(
    "expected_path",
    _discover_expected_json_files(),
    ids=lambda p: p.relative_to(PARSERS_TEST_DIR).as_posix(),
)
def test_expected_json_avoids_na_like_placeholder_values(expected_path: Path) -> None:
    r"""Fail when a fixture uses ``NA``, ``N/A``, or ``n/a`` as a string value.

    Many Cisco outputs use these tokens as *real* labels; exempt legacy files via
    ``_NA_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES``. Prefer omitting the key when the
    token means “no value” rather than a vendor-defined enum.
    """
    rel = expected_path.relative_to(PARSERS_TEST_DIR).as_posix()
    data = json.loads(expected_path.read_text(encoding="utf-8"))
    violations = _string_leaf_violations(data, _PLACEHOLDER_NA_LIKE)
    if rel in _NA_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES:
        return
    if not violations:
        return
    lines = "\n".join(
        f"  - {_path_to_json_pointer(p)}: {value!r}" for p, value in violations[:50]
    )
    more = ""
    if len(violations) > 50:
        more = f"\n  ... and {len(violations) - 50} more"
    msg = (
        f"{rel} uses NA/N/A-like placeholder string value(s). Prefer omitting the key "
        f"or modeling vendor-defined tokens explicitly; or add the file to "
        f"_NA_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES in "
        f"test_fixture_placeholder_sentinels.py.\n"
        f"{lines}{more}"
    )
    pytest.fail(msg)
