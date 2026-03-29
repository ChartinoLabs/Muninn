"""Guardrails for CLI placeholder strings in ``expected.json`` fixtures.

When the device prints obvious "no value" sentinels, Muninn generally prefers
omitting the key (or using ``null`` if the schema uses optional fields) instead of
carrying strings like ``-`` or ``---`` through to structured output.

Some Cisco outputs use ``NA`` / ``N/A`` as *meaningful* labels in specific
contexts. Legacy fixtures that still mirror those literals as string leaves are
listed below; **new** test cases are not exempt unless their path is added
explicitly (so new work does not silently reintroduce placeholders).

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
_PLACEHOLDER_NONE_LIKE: Final[frozenset[str]] = frozenset({"none", "None", "NONE"})
_PLACEHOLDER_EMPTY_STRING: Final[frozenset[str]] = frozenset({""})


# Legacy fixtures still using hyphen / em-dash placeholders as string *values*.
_HYPHEN_PLACEHOLDER_EXEMPT_EXPECTED_FILES: Final[frozenset[str]] = frozenset({})

# Legacy fixtures where NA / N/A / n/a appear as CLI text (not always "null").
_NA_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES: Final[frozenset[str]] = frozenset(
    {
        # Arista EOS "N/A" is a real age value for static/unlearned ARP entries.
        "arista_eos/show_ip_arp/001_basic/expected.json",
        "arista_eos/show_ip_arp/002_multi_vrf/expected.json",
        # Nokia SROS uses "n/a" as a vendor-defined token for port_sap_id
        # (no port/SAP association) and pfx_state (prefix state not applicable).
        "nokia_sros/show_router_interface/001_mixed_interfaces/expected.json",
    }
)

# Legacy fixtures where "none" / "None" / "NONE" appears as a meaningful enum value
# (e.g. OSPF authentication type, interface reason) rather than a null placeholder.
_NONE_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES: Final[frozenset[str]] = frozenset(
    {
        "arista_eos/show_version/004_ceos_lab/expected.json",
        "arista_eos/show_version/005_ceos_clab/expected.json",
        "ios/show_crypto_session_detail/001_basic/expected.json",
        "ios/show_license/001_basic/expected.json",
        "ios/show_snmp_user/001_basic/expected.json",
        "iosxe/show_netconf-yang_sessions/001_basic/expected.json",
        "iosxe/show_redundancy/001_basic/expected.json",
        "iosxe/show_redundancy/001_live_device/expected.json",
        "iosxe/show_redundancy/002_no_standby/expected.json",
        "iosxe/show_redundancy/003_asr1k/expected.json",
        "iosxe/show_switch_detail/002_single_switch/expected.json",
        "iosxe/show_switch_detail/003_unprovisioned_member/expected.json",
        "linux/ip_address_show/001_standard_linux/expected.json",
        "linux/ip_link_show/001_standard_linux/expected.json",
        "nxos/show_interface_brief/001_basic/expected.json",
        "nxos/show_interface_capabilities/001_basic/expected.json",
        "nxos/show_ip_ospf_interface/001_broadcast_loopback_shamlink/expected.json",
        "nxos/show_ip_ospf_interface/002_passive_bfd_md_auth/expected.json",
        "nxos/show_ip_ospf_interface/003_combined_ip_process_line/expected.json",
        "nxos/show_port-channel_summary/003_down_and_empty/expected.json",
        "paloalto_panos/show_system_info/001_pa_vm_basic/expected.json",
    }
)

# Legacy fixtures that still use empty strings as values. Prefer omitting the key
# (or using ``null`` if the schema uses optional fields) instead of ``""``.
_EMPTY_STRING_EXEMPT_EXPECTED_FILES: Final[frozenset[str]] = frozenset({})

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
    token means "no value" rather than a vendor-defined enum.
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


@pytest.mark.parametrize(
    "expected_path",
    _discover_expected_json_files(),
    ids=lambda p: p.relative_to(PARSERS_TEST_DIR).as_posix(),
)
def test_expected_json_avoids_none_like_placeholder_values(
    expected_path: Path,
) -> None:
    r"""Fail when a fixture uses ``none``, ``None``, or ``NONE`` as a string value.

    Many devices print "none" as a meaningful enum (e.g. OSPF authentication type).
    Exempt legacy files via ``_NONE_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES``.
    Prefer omitting the key when the token means "no value".
    """
    rel = expected_path.relative_to(PARSERS_TEST_DIR).as_posix()
    data = json.loads(expected_path.read_text(encoding="utf-8"))
    violations = _string_leaf_violations(data, _PLACEHOLDER_NONE_LIKE)
    if rel in _NONE_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES:
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
        f"{rel} uses none-like placeholder string value(s). Prefer omitting the key "
        f"(or null) instead of 'none'; or add the file to "
        f"_NONE_LIKE_PLACEHOLDER_EXEMPT_EXPECTED_FILES in "
        f"test_fixture_placeholder_sentinels.py.\n"
        f"{lines}{more}"
    )
    pytest.fail(msg)


@pytest.mark.parametrize(
    "expected_path",
    _discover_expected_json_files(),
    ids=lambda p: p.relative_to(PARSERS_TEST_DIR).as_posix(),
)
def test_expected_json_avoids_empty_string_values(expected_path: Path) -> None:
    r"""Fail when a fixture uses ``""`` as a string value.

    Empty strings are almost always a parser returning "no value" — prefer
    omitting the key entirely. Exempt legacy files via
    ``_EMPTY_STRING_EXEMPT_EXPECTED_FILES``.
    """
    rel = expected_path.relative_to(PARSERS_TEST_DIR).as_posix()
    data = json.loads(expected_path.read_text(encoding="utf-8"))
    violations = _string_leaf_violations(data, _PLACEHOLDER_EMPTY_STRING)
    if rel in _EMPTY_STRING_EXEMPT_EXPECTED_FILES:
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
        f"{rel} uses empty string value(s). Prefer omitting the key "
        f'(or null) instead of "", or add the file to '
        f"_EMPTY_STRING_EXEMPT_EXPECTED_FILES in "
        f"test_fixture_placeholder_sentinels.py.\n"
        f"{lines}{more}"
    )
    pytest.fail(msg)
