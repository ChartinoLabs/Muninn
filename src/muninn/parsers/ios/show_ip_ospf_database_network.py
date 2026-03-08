"""Parser for 'show ip ospf database network' command on IOS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class NetworkLsaEntry(TypedDict):
    """Schema for a single Network LSA entry."""

    ls_age: int
    options: str
    ls_type: str
    link_state_id: str
    advertising_router: str
    ls_seq_number: str
    checksum: str
    length: int
    network_mask: str
    attached_routers: dict[str, dict[str, object]]


class AreaEntry(TypedDict):
    """Schema for an OSPF area containing network LSAs."""

    lsas: dict[str, dict[str, NetworkLsaEntry]]


class ShowIpOspfDatabaseNetworkResult(TypedDict):
    """Schema for 'show ip ospf database network' parsed output."""

    router_id: str
    process_id: int
    areas: dict[str, AreaEntry]


# --- Header patterns ---
_ROUTER_PROCESS_RE = re.compile(
    r"^\s*OSPF Router with (?:ID|id)\s*\((\S+)\)"
    r"\s*\(Process ID (\d+)\)\s*$"
)
_AREA_RE = re.compile(r"^\s*Displaying Net Link States\s*\(Area (\S+)\)\s*$")

# --- LSA field patterns ---
_LS_AGE_RE = re.compile(r"^\s*LS age:\s*(\d+)\s*$")
_OPTIONS_RE = re.compile(r"^\s*Options:\s*\((.+?)\)\s*$")
_LS_TYPE_RE = re.compile(r"^\s*LS Type:\s*(.+?)\s*$")
_LINK_STATE_ID_RE = re.compile(r"^\s*Link State ID:\s*(\S+)\s*(?:\(.+\))?\s*$")
_ADV_ROUTER_RE = re.compile(r"^\s*Advertising Router:\s*(\S+)\s*$")
_LS_SEQ_RE = re.compile(r"^\s*LS Seq Number:\s*(\S+)\s*$")
_CHECKSUM_RE = re.compile(r"^\s*Checksum:\s*(\S+)\s*$")
_LENGTH_RE = re.compile(r"^\s*Length:\s*(\d+)\s*$")
_NETWORK_MASK_RE = re.compile(r"^\s*Network Mask:\s*(\S+)\s*$")
_ATTACHED_ROUTER_RE = re.compile(r"^\s*Attached Router:\s*(\S+)\s*$")

# Table-driven string field matchers: (pattern, field_name)
_STRING_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_OPTIONS_RE, "options"),
    (_LS_TYPE_RE, "ls_type"),
    (_LINK_STATE_ID_RE, "link_state_id"),
    (_ADV_ROUTER_RE, "advertising_router"),
    (_LS_SEQ_RE, "ls_seq_number"),
    (_CHECKSUM_RE, "checksum"),
    (_NETWORK_MASK_RE, "network_mask"),
)

# Table-driven integer field matchers: (pattern, field_name)
_INT_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_LS_AGE_RE, "ls_age"),
    (_LENGTH_RE, "length"),
)


def _match_string_field(line: str, entry: dict[str, object]) -> bool:
    """Try matching a string field pattern. Returns True if matched."""
    for pattern, field_name in _STRING_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[field_name] = m.group(1)
            return True
    return False


def _match_int_field(line: str, entry: dict[str, object]) -> bool:
    """Try matching an integer field pattern. Returns True if matched."""
    for pattern, field_name in _INT_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[field_name] = int(m.group(1))
            return True
    return False


def _parse_lsa_block(
    lines: list[str],
) -> NetworkLsaEntry | None:
    """Parse a single Network LSA block from its lines."""
    entry: dict[str, object] = {}
    attached_routers: dict[str, dict[str, object]] = {}

    for line in lines:
        if _match_int_field(line, entry):
            continue
        if _match_string_field(line, entry):
            continue
        m = _ATTACHED_ROUTER_RE.match(line)
        if m:
            attached_routers[m.group(1)] = {}

    if not entry:
        return None

    entry["attached_routers"] = attached_routers
    return entry  # type: ignore[return-value]


def _store_lsa(
    areas: dict[str, AreaEntry],
    area: str,
    lsa_lines: list[str],
    link_state_id: str,
    adv_router: str,
) -> None:
    """Parse and store an LSA block into the areas dict."""
    lsa = _parse_lsa_block(lsa_lines)
    if lsa is None:
        return
    area_entry = areas.setdefault(area, {"lsas": {}})
    lsid_entry = area_entry["lsas"].setdefault(link_state_id, {})
    lsid_entry[adv_router] = lsa


def _extract_header(
    output: str,
) -> tuple[str, int]:
    """Extract router ID and process ID from the output header."""
    for line in output.splitlines():
        m = _ROUTER_PROCESS_RE.match(line)
        if m:
            return m.group(1), int(m.group(2))
    msg = "Could not parse router ID or process ID from output"
    raise ValueError(msg)


def _parse_lsa_blocks(
    output: str,
) -> dict[str, AreaEntry]:
    """Parse all LSA blocks grouped by area."""
    areas: dict[str, AreaEntry] = {}
    current_area: str | None = None
    lsa_lines: list[str] = []
    link_state_id: str | None = None
    adv_router: str | None = None

    def flush() -> None:
        nonlocal lsa_lines, link_state_id, adv_router
        if current_area and lsa_lines and link_state_id and adv_router:
            _store_lsa(
                areas,
                current_area,
                lsa_lines,
                link_state_id,
                adv_router,
            )
        lsa_lines = []
        link_state_id = None
        adv_router = None

    for line in output.splitlines():
        m = _AREA_RE.match(line)
        if m:
            flush()
            current_area = m.group(1)
            continue

        if _LS_AGE_RE.match(line):
            flush()
            lsa_lines.append(line)
            continue

        m = _LINK_STATE_ID_RE.match(line)
        if m:
            link_state_id = m.group(1)

        m = _ADV_ROUTER_RE.match(line)
        if m:
            adv_router = m.group(1)

        if current_area is not None:
            lsa_lines.append(line)

    flush()
    return areas


@register(OS.CISCO_IOS, "show ip ospf database network")
class ShowIpOspfDatabaseNetworkParser(
    BaseParser["ShowIpOspfDatabaseNetworkResult"],
):
    """Parser for 'show ip ospf database network' on IOS."""

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseNetworkResult:
        """Parse 'show ip ospf database network' output."""
        router_id, process_id = _extract_header(output)
        areas = _parse_lsa_blocks(output)

        return {
            "router_id": router_id,
            "process_id": process_id,
            "areas": areas,
        }
