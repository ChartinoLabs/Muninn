"""Parser for 'show ip ospf database router' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class LinkEntry(TypedDict):
    """A single link within a router LSA."""

    type: str
    link_id: str
    link_data: str
    tos_metrics: int
    metric: int


class RouterLsaEntry(TypedDict):
    """A single router LSA entry."""

    ls_age: int
    options: str
    ls_type: str
    link_state_id: str
    advertising_router: str
    ls_seq_number: str
    checksum: str
    length: int
    num_links: int
    area_border_router: NotRequired[bool]
    as_boundary_router: NotRequired[bool]
    links: dict[str, LinkEntry]


class AreaEntry(TypedDict):
    """Router LSAs within a single OSPF area."""

    routers: dict[str, RouterLsaEntry]


class ShowIpOspfDatabaseRouterResult(TypedDict):
    """Schema for 'show ip ospf database router' parsed output."""

    router_id: str
    process_id: int
    areas: dict[str, AreaEntry]


# --- Header patterns ---
_ROUTER_HEADER_RE = re.compile(
    r"^\s*OSPF Router with ID\s*\((\S+)\)\s*\(Process ID (\d+)\)\s*$"
)
_AREA_HEADER_RE = re.compile(
    r"^\s*(?:Displaying\s+)?Router Link States\s*\(Area (\S+)\)\s*$"
)

# --- LSA field patterns ---
_LS_AGE_RE = re.compile(r"^\s*LS age:\s*(\d+)\s*$")
_OPTIONS_RE = re.compile(r"^\s*Options:\s*\((.+?)\)\s*$")
_LS_TYPE_RE = re.compile(r"^\s*LS Type:\s*(.+?)\s*$")
_LINK_STATE_ID_RE = re.compile(r"^\s*Link State ID:\s*(\S+)\s*$")
_ADV_ROUTER_RE = re.compile(r"^\s*Advertising Router:\s*(\S+)\s*$")
_LS_SEQ_RE = re.compile(r"^\s*LS Seq Number:\s*(\S+)\s*$")
_CHECKSUM_RE = re.compile(r"^\s*Checksum:\s*(\S+)\s*$")
_LENGTH_RE = re.compile(r"^\s*Length:\s*(\d+)\s*$")
_NUM_LINKS_RE = re.compile(r"^\s*(?:.*?)Number of Links:\s*(\d+)\s*$")
_ABR_RE = re.compile(r"^\s*Area Border Router\s*$")
_ASBR_RE = re.compile(r"^\s*AS Boundary Router\s*$")

# --- Link entry patterns ---
_LINK_TYPE_RE = re.compile(r"^\s*Link connected to:\s*(.+?)\s*$")
_LINK_ID_RE = re.compile(r"^\s*\((?:link|Link) ID\)\s*(.+?):\s*(\S+)\s*$")
_LINK_DATA_RE = re.compile(r"^\s*\(Link Data\)\s*(.+?):\s*(\S+)\s*$")
_TOS_COUNT_RE = re.compile(r"^\s*Number of TOS metrics:\s*(\d+)\s*$")
_TOS_METRIC_RE = re.compile(r"^\s*TOS \d+ Metrics:\s*(\d+)\s*$")

# Map raw link type text to normalized type names
_LINK_TYPE_MAP = {
    "a transit network": "transit",
    "a stub network": "stub",
    "another router (point-to-point)": "point-to-point",
    "a virtual link": "virtual_link",
}

# Ordered matchers for LSA header fields: (pattern, key, converter)
_LSA_FIELD_MATCHERS: tuple[tuple[re.Pattern[str], str, type], ...] = (
    (_LS_AGE_RE, "ls_age", int),
    (_OPTIONS_RE, "options", str),
    (_LS_TYPE_RE, "ls_type", str),
    (_LINK_STATE_ID_RE, "link_state_id", str),
    (_ADV_ROUTER_RE, "advertising_router", str),
    (_LS_SEQ_RE, "ls_seq_number", str),
    (_CHECKSUM_RE, "checksum", str),
    (_LENGTH_RE, "length", int),
    (_NUM_LINKS_RE, "num_links", int),
)


def _normalize_link_type(raw_type: str) -> str:
    """Normalize the link type string from CLI output."""
    normalized = _LINK_TYPE_MAP.get(raw_type.lower())
    if normalized is not None:
        return normalized
    return raw_type.lower().replace(" ", "_")


def _normalize_area(area: str) -> str:
    """Normalize area to dotted notation. '0' -> '0.0.0.0'."""
    if "." in area:
        return area
    num = int(area)
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"


def _split_lsa_blocks(lines: list[str]) -> list[list[str]]:
    """Split lines into individual LSA blocks based on LS age markers."""
    blocks: list[list[str]] = []
    current: list[str] | None = None

    for line in lines:
        if _LS_AGE_RE.match(line):
            if current is not None:
                blocks.append(current)
            current = [line]
        elif current is not None:
            current.append(line)

    if current is not None:
        blocks.append(current)

    return blocks


def _parse_lsa_header(lines: list[str], entry: dict) -> None:
    """Extract LSA header fields and router flags from lines."""
    for line in lines:
        for pattern, key, converter in _LSA_FIELD_MATCHERS:
            m = pattern.match(line)
            if m:
                entry[key] = converter(m.group(1))
                break
        else:
            if _ABR_RE.match(line):
                entry["area_border_router"] = True
            elif _ASBR_RE.match(line):
                entry["as_boundary_router"] = True


def _parse_lsa_links(lines: list[str]) -> dict[str, LinkEntry]:
    """Extract link entries from an LSA block's lines."""
    links: dict[str, LinkEntry] = {}
    current_type: str | None = None
    current_id: str | None = None
    current_data: str | None = None
    current_tos: int = 0
    current_metric: int = 0

    def _flush() -> None:
        nonlocal current_type, current_id, current_data
        nonlocal current_tos, current_metric
        if current_id is not None and current_type is not None:
            links[current_id] = {
                "type": current_type,
                "link_id": current_id,
                "link_data": current_data or "",
                "tos_metrics": current_tos,
                "metric": current_metric,
            }
        current_type = None
        current_id = None
        current_data = None
        current_tos = 0
        current_metric = 0

    for line in lines:
        m = _LINK_TYPE_RE.match(line)
        if m:
            _flush()
            current_type = _normalize_link_type(m.group(1))
            continue

        m = _LINK_ID_RE.match(line)
        if m:
            current_id = m.group(2)
            continue

        m = _LINK_DATA_RE.match(line)
        if m:
            current_data = m.group(2)
            continue

        m = _TOS_COUNT_RE.match(line)
        if m:
            current_tos = int(m.group(1))
            continue

        m = _TOS_METRIC_RE.match(line)
        if m:
            current_metric = int(m.group(1))
            continue

    _flush()
    return links


def _parse_single_lsa(lines: list[str]) -> RouterLsaEntry:
    """Parse a single router LSA block into a RouterLsaEntry."""
    entry: dict = {}
    _parse_lsa_header(lines, entry)
    entry["links"] = _parse_lsa_links(lines)
    return entry  # type: ignore[return-value]


def _parse_header(
    lines: list[str],
) -> tuple[str, int]:
    """Extract router ID and process ID from the output header."""
    for line in lines:
        m = _ROUTER_HEADER_RE.match(line)
        if m:
            return m.group(1), int(m.group(2))
    msg = "Could not find OSPF router header in output"
    raise ValueError(msg)


def _split_area_sections(
    lines: list[str],
) -> list[tuple[str, list[str]]]:
    """Split output lines into (area, lines) sections."""
    sections: list[tuple[str, list[str]]] = []
    current_area: str | None = None
    area_lines: list[str] = []

    for line in lines:
        m = _AREA_HEADER_RE.match(line)
        if m:
            if current_area is not None:
                sections.append((current_area, area_lines))
            current_area = _normalize_area(m.group(1))
            area_lines = []
        elif current_area is not None:
            area_lines.append(line)

    if current_area is not None:
        sections.append((current_area, area_lines))

    return sections


@register(OS.CISCO_IOS, "show ip ospf database router")
class ShowIpOspfDatabaseRouterParser(
    BaseParser["ShowIpOspfDatabaseRouterResult"],
):
    """Parser for 'show ip ospf database router' on IOS."""

    tags: ClassVar[frozenset[str]] = frozenset({"ospf", "routing"})

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseRouterResult:
        """Parse 'show ip ospf database router' output."""
        lines = output.splitlines()
        router_id, process_id = _parse_header(lines)
        areas: dict[str, AreaEntry] = {}

        for area, area_lines in _split_area_sections(lines):
            routers: dict[str, RouterLsaEntry] = {}
            for block in _split_lsa_blocks(area_lines):
                lsa = _parse_single_lsa(block)
                adv_router = lsa.get("advertising_router", "")
                if adv_router:
                    routers[adv_router] = lsa
            areas[area] = {"routers": routers}

        return {
            "router_id": router_id,
            "process_id": process_id,
            "areas": areas,
        }
