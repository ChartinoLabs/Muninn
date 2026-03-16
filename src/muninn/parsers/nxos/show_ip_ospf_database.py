"""Parser for 'show ip ospf database' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# --- LSA type name mapping from section headers ---
_LSA_TYPE_MAP: dict[str, str] = {
    "Router Link States": "router",
    "Network Link States": "network",
    "Summary Network Link States": "summary",
    "Summary ASB Link States": "asbr_summary",
    "Type-5 AS External Link States": "external",
    "Opaque Area Link States": "opaque_area",
    "Opaque Link States": "opaque_link",
}


class LsaEntry(TypedDict):
    """Schema for a single LSA entry."""

    age: int
    seq: str
    checksum: str
    link_count: NotRequired[int]
    tag: NotRequired[int]


class AreaEntry(TypedDict, total=False):
    """Schema for LSA entries within an area, keyed by LSA type."""

    router: dict[str, dict[str, LsaEntry]]
    network: dict[str, dict[str, LsaEntry]]
    summary: dict[str, dict[str, LsaEntry]]
    asbr_summary: dict[str, dict[str, LsaEntry]]
    opaque_area: dict[str, dict[str, LsaEntry]]
    opaque_link: dict[str, dict[str, LsaEntry]]


class ShowIpOspfDatabaseResult(TypedDict):
    """Schema for 'show ip ospf database' parsed output."""

    router_id: str
    process_id: str
    areas: dict[str, AreaEntry]
    external: NotRequired[dict[str, dict[str, LsaEntry]]]


# --- Header: OSPF Router with ID (x.x.x.x) (Process ID xxx) ---
_HEADER_RE = re.compile(r"^\s*OSPF Router with ID \((\S+)\)\s+\(Process ID (\S+)\)\s*$")

# --- Section header: LSA type (Area X) or Type-5 AS External ---
_AREA_SECTION_RE = re.compile(r"^\s*(\S.+?)\s+\(Area (\S+)\)\s*$")
_EXTERNAL_SECTION_RE = re.compile(r"^\s*(Type-5 AS External Link States)\s*$")

# --- Column header line (skip) ---
_COLUMN_HEADER_RE = re.compile(r"^\s*Link ID\s+ADV Router\s+Age\s+Seq#\s+Checksum")

# --- LSA entry: with link count ---
_LSA_WITH_COUNT_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+"
    r"(\d+\.\d+\.\d+\.\d+)\s+"
    r"(\d+)\s+"
    r"(0x[0-9a-fA-F]+)\s+"
    r"(0x[0-9a-fA-F]+)\s+"
    r"(\d+)\s*$"
)

# --- LSA entry: without link count (network, summary, external without tag) ---
_LSA_NO_COUNT_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+"
    r"(\d+\.\d+\.\d+\.\d+)\s+"
    r"(\d+)\s+"
    r"(0x[0-9a-fA-F]+)\s+"
    r"(0x[0-9a-fA-F]+)\s*$"
)


def _normalize_area(area: str) -> str:
    """Normalize area to dotted notation. '0' -> '0.0.0.0', '1' -> '0.0.0.1'."""
    if "." in area:
        return area
    num = int(area)
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"


def _parse_lsa_line(line: str, is_external: bool) -> tuple[str, str, LsaEntry] | None:
    """Parse a single LSA entry line.

    Returns (link_id, adv_router, entry) or None if the line doesn't match.
    """
    m = _LSA_WITH_COUNT_RE.match(line)
    if m:
        entry: LsaEntry = {
            "age": int(m.group(3)),
            "seq": m.group(4),
            "checksum": m.group(5),
        }
        count_or_tag = int(m.group(6))
        if is_external:
            entry["tag"] = count_or_tag
        else:
            entry["link_count"] = count_or_tag
        return m.group(1), m.group(2), entry

    m = _LSA_NO_COUNT_RE.match(line)
    if m:
        entry: LsaEntry = {
            "age": int(m.group(3)),
            "seq": m.group(4),
            "checksum": m.group(5),
        }
        return m.group(1), m.group(2), entry

    return None


def _insert_lsa(
    target: dict[str, dict[str, LsaEntry]],
    link_id: str,
    adv_router: str,
    entry: LsaEntry,
) -> None:
    """Insert an LSA entry into the nested dict structure."""
    if link_id not in target:
        target[link_id] = {}
    target[link_id][adv_router] = entry


def _check_area_section(
    line: str,
    areas: dict[str, AreaEntry],
) -> tuple[str, str | None] | None:
    """Check if line is an area section header.

    Returns (area, lsa_type) or None.
    """
    m = _AREA_SECTION_RE.match(line)
    if not m:
        return None
    area = _normalize_area(m.group(2))
    lsa_type = _LSA_TYPE_MAP.get(m.group(1))
    if area not in areas:
        areas[area] = {}
    return area, lsa_type


def _process_lsa_entry(
    line: str,
    *,
    is_external: bool,
    current_area: str | None,
    current_lsa_type: str | None,
    areas: dict[str, AreaEntry],
    external: dict[str, dict[str, LsaEntry]],
) -> None:
    """Parse and store an LSA entry line."""
    if current_lsa_type is None:
        return

    parsed = _parse_lsa_line(line, is_external)
    if parsed is None:
        return

    link_id, adv_router, entry = parsed

    if is_external:
        _insert_lsa(external, link_id, adv_router, entry)
    elif current_area is not None:
        area_data = areas[current_area]
        if current_lsa_type not in area_data:
            area_data[current_lsa_type] = {}  # type: ignore[literal-required]
        type_data: dict[str, dict[str, LsaEntry]] = area_data[current_lsa_type]  # type: ignore[literal-required]
        _insert_lsa(type_data, link_id, adv_router, entry)


def _parse_header(output: str) -> tuple[str, str]:
    """Extract router ID and process ID from the output header."""
    for line in output.splitlines():
        m = _HEADER_RE.match(line)
        if m:
            return m.group(1), m.group(2)
    msg = "Could not parse OSPF database header (router ID and process ID)"
    raise ValueError(msg)


def _parse_database(
    output: str,
) -> tuple[dict[str, AreaEntry], dict[str, dict[str, LsaEntry]]]:
    """Parse all LSA sections from the output."""
    areas: dict[str, AreaEntry] = {}
    external: dict[str, dict[str, LsaEntry]] = {}
    current_area: str | None = None
    current_lsa_type: str | None = None
    is_external = False

    for line in output.splitlines():
        if not line.strip() or _COLUMN_HEADER_RE.match(line):
            continue

        if _HEADER_RE.match(line):
            continue

        area_result = _check_area_section(line, areas)
        if area_result is not None:
            current_area, current_lsa_type = area_result
            is_external = False
            continue

        if _EXTERNAL_SECTION_RE.match(line):
            current_area = None
            current_lsa_type = "external"
            is_external = True
            continue

        _process_lsa_entry(
            line,
            is_external=is_external,
            current_area=current_area,
            current_lsa_type=current_lsa_type,
            areas=areas,
            external=external,
        )

    return areas, external


@register(OS.CISCO_NXOS, "show ip ospf database")
class ShowIpOspfDatabaseParser(BaseParser[ShowIpOspfDatabaseResult]):
    """Parser for 'show ip ospf database' on NX-OS."""

    tags: ClassVar[frozenset[str]] = frozenset({"ospf", "routing"})

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseResult:
        """Parse 'show ip ospf database' output."""
        router_id, process_id = _parse_header(output)
        areas, external = _parse_database(output)

        result: ShowIpOspfDatabaseResult = {
            "router_id": router_id,
            "process_id": process_id,
            "areas": areas,
        }

        if external:
            result["external"] = external

        return result
