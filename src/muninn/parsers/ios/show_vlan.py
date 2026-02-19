"""Parser for 'show vlan' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class VlanEntry(TypedDict):
    """Schema for a single VLAN entry."""

    vlan_id: int
    name: str
    status: str
    ports: list[str]
    type: str
    said: int
    mtu: int
    parent: NotRequired[int]
    ring_no: NotRequired[int]
    bridge_no: NotRequired[int]
    stp: NotRequired[str]
    bridge_mode: NotRequired[str]
    trans1: int
    trans2: int
    are_hops: NotRequired[int]
    ste_hops: NotRequired[int]
    backup_crf: NotRequired[str]


class PrivateVlanEntry(TypedDict):
    """Schema for a private VLAN association entry."""

    primary: NotRequired[int]
    secondary: int
    type: str
    ports: list[str]


class ShowVlanResult(TypedDict):
    """Schema for 'show vlan' parsed output."""

    vlans: dict[str, VlanEntry]
    remote_span_vlans: NotRequired[list[int]]
    private_vlans: NotRequired[list[PrivateVlanEntry]]


# Section header patterns
_BASIC_HEADER = re.compile(r"^VLAN\s+Name\s+Status\s+Ports\s*$")
_EXTENDED_HEADER = re.compile(r"^VLAN\s+Type\s+SAID\s+MTU\s+Parent")
_AREHOPS_HEADER = re.compile(r"^VLAN\s+AREHops\s+STEHops")
_REMOTE_SPAN_HEADER = re.compile(r"^Remote SPAN VLANs\s*$")
_PV_HEADER = re.compile(r"^Primary\s+Secondary\s+Type\s+Ports\s*$")
_SEPARATOR = re.compile(r"^[-\s]+$")

# Column positions for the basic VLAN table
_NAME_COL = 5
_STATUS_COL = 38
_PORTS_COL = 48

_VALID_STATUSES = {"active", "suspended", "act/unsup", "act/lshut"}

# Maps section header patterns to their key names
_SECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_BASIC_HEADER, "basic"),
    (_EXTENDED_HEADER, "extended"),
    (_AREHOPS_HEADER, "arehops"),
    (_REMOTE_SPAN_HEADER, "remote_span"),
    (_PV_HEADER, "private_vlan"),
]


def _normalize_ports(port_str: str) -> list[str]:
    """Split comma-separated ports and normalize to canonical names."""
    port_str = port_str.strip()
    if not port_str:
        return []
    return [
        canonical_interface_name(p.strip()) for p in port_str.split(",") if p.strip()
    ]


def _expand_vlan_ranges(text: str) -> list[int]:
    """Expand comma-separated VLAN IDs with range notation."""
    result: list[int] = []
    text = text.strip()
    if not text:
        return result
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(part))
    return sorted(result)


def _to_int_or_none(value: str) -> int | None:
    """Convert a string to int, returning None for '-' or empty."""
    value = value.strip()
    if not value or value == "-":
        return None
    return int(value)


def _col_field(line: str, start: int, end: int | None = None) -> str:
    """Extract and strip a column-position field from a line."""
    if end is None:
        return line[start:].strip() if len(line) > start else ""
    return line[start:end].strip() if len(line) > start else ""


def _is_section_end(line: str) -> bool:
    """Check if a line marks the start of a different section."""
    return bool(
        _EXTENDED_HEADER.match(line)
        or _AREHOPS_HEADER.match(line)
        or _REMOTE_SPAN_HEADER.match(line)
        or _PV_HEADER.match(line)
    )


def _handle_wrapped_name(
    line: str, lines: list[str], i: int
) -> tuple[str, str, str, int]:
    """Handle VLAN name that overflows into status column.

    Returns (name, status, ports_field, new_index).
    """
    next_line = lines[i + 1] if i + 1 < len(lines) else ""
    next_status = _col_field(next_line, _STATUS_COL, _PORTS_COL)
    if next_status:
        name = _col_field(line, _NAME_COL)
        ports = _col_field(next_line, _PORTS_COL)
        return name, next_status, ports, i + 1
    # Fallback: treat what we have as the name
    return _col_field(line, _NAME_COL), "", "", i


def _parse_vlan_line(line: str, lines: list[str], i: int) -> tuple[str, VlanEntry, int]:
    """Parse a new VLAN line, handling wrapped names.

    Returns (vlan_id, entry, new_index).
    """
    vlan_field = line[:4].strip()
    name = _col_field(line, _NAME_COL, _STATUS_COL)
    status = _col_field(line, _STATUS_COL, _PORTS_COL)
    ports_str = _col_field(line, _PORTS_COL)

    if name and status not in _VALID_STATUSES:
        name, status, ports_str, i = _handle_wrapped_name(line, lines, i)

    entry: VlanEntry = {
        "vlan_id": int(vlan_field),
        "name": name,
        "status": status,
        "ports": _normalize_ports(ports_str),
        "type": "",
        "said": 0,
        "mtu": 0,
        "trans1": 0,
        "trans2": 0,
    }
    return vlan_field, entry, i


def _parse_basic_table(lines: list[str]) -> dict[str, VlanEntry]:
    """Parse the basic VLAN table (Name/Status/Ports)."""
    vlans: dict[str, VlanEntry] = {}
    current_vlan_id: str | None = None

    i = 0
    while i < len(lines):
        line = lines[i]

        if _is_section_end(line):
            break
        if _SEPARATOR.match(line) or not line.strip():
            i += 1
            continue

        vlan_field = line[:4].strip()
        if vlan_field and vlan_field.isdigit():
            vlan_field, entry, i = _parse_vlan_line(line, lines, i)
            vlans[vlan_field] = entry
            current_vlan_id = vlan_field
        elif current_vlan_id is not None:
            ports_str = _col_field(line, _PORTS_COL)
            if ports_str:
                vlans[current_vlan_id]["ports"].extend(_normalize_ports(ports_str))

        i += 1

    return vlans


def _merge_extended_fields(entry: VlanEntry, parts: list[str]) -> None:
    """Merge extended table fields into a VLAN entry."""
    entry["type"] = parts[1]
    entry["said"] = int(parts[2])
    entry["mtu"] = int(parts[3])
    parent = _to_int_or_none(parts[4])
    if parent is not None:
        entry["parent"] = parent
    ring_no = _to_int_or_none(parts[5])
    if ring_no is not None:
        entry["ring_no"] = ring_no
    bridge_no = _to_int_or_none(parts[6])
    if bridge_no is not None:
        entry["bridge_no"] = bridge_no
    if parts[7] != "-":
        entry["stp"] = parts[7]
    if parts[8] != "-":
        entry["bridge_mode"] = parts[8]
    entry["trans1"] = int(parts[9])
    entry["trans2"] = int(parts[10])


def _parse_extended_table(lines: list[str], vlans: dict[str, VlanEntry]) -> None:
    """Parse the extended VLAN table and merge into vlans dict."""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _EXTENDED_HEADER.match(stripped):
            continue
        if _SEPARATOR.match(stripped):
            continue
        if _BASIC_HEADER.match(stripped):
            break

        parts = stripped.split()
        if len(parts) < 11 or not parts[0].isdigit():
            continue

        entry = vlans.get(parts[0])
        if entry is not None:
            _merge_extended_fields(entry, parts)


def _parse_arehops(lines: list[str], vlans: dict[str, VlanEntry]) -> None:
    """Parse the AREHops/STEHops/Backup CRF table."""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _AREHOPS_HEADER.match(stripped) or _SEPARATOR.match(stripped):
            continue

        parts = stripped.split()
        if len(parts) < 4 or not parts[0].isdigit():
            continue

        entry = vlans.get(parts[0])
        if entry is None:
            continue

        entry["are_hops"] = int(parts[1])
        entry["ste_hops"] = int(parts[2])
        entry["backup_crf"] = parts[3]


def _parse_remote_span(lines: list[str]) -> list[int]:
    """Parse Remote SPAN VLANs section."""
    result: list[int] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or _SEPARATOR.match(stripped):
            continue
        result.extend(_expand_vlan_ranges(stripped))
    return sorted(result)


def _parse_private_vlan_line(
    line: str, pri_col: int, sec_col: int, type_col: int, ports_col: int
) -> PrivateVlanEntry | None:
    """Parse a single private VLAN data line into an entry."""
    padded = line.ljust(ports_col + 80)
    pri_str = padded[pri_col:sec_col].strip()
    sec_str = padded[sec_col:type_col].strip()
    type_str = padded[type_col:ports_col].strip()
    ports_str = padded[ports_col:].strip()

    if not sec_str or not sec_str.isdigit():
        return None

    entry: PrivateVlanEntry = {
        "secondary": int(sec_str),
        "type": type_str,
        "ports": _normalize_ports(ports_str),
    }
    if pri_str and pri_str.lower() != "none":
        entry["primary"] = int(pri_str)

    return entry


def _parse_private_vlans(
    lines: list[str],
) -> list[PrivateVlanEntry]:
    """Parse Private VLAN associations table."""
    entries: list[PrivateVlanEntry] = []

    header_idx = -1
    for i, line in enumerate(lines):
        if _PV_HEADER.match(line.strip()):
            header_idx = i
            break

    if header_idx < 0:
        return entries

    header = lines[header_idx]
    pri_col = header.index("Primary")
    sec_col = header.index("Secondary")
    type_col = header.index("Type")
    ports_col = header.index("Ports")

    for line in lines[header_idx + 1 :]:
        stripped = line.strip()
        if not stripped or _SEPARATOR.match(stripped):
            continue

        entry = _parse_private_vlan_line(line, pri_col, sec_col, type_col, ports_col)
        if entry is not None:
            entries.append(entry)

    return entries


def _match_section(stripped: str) -> str | None:
    """Return the section key if a line matches a section header."""
    for pattern, key in _SECTION_PATTERNS:
        if pattern.match(stripped):
            return key
    return None


def _find_sections(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Identify the line ranges for each section of the output."""
    section_order: list[tuple[str, int]] = []
    seen: set[str] = set()

    for i, line in enumerate(lines):
        key = _match_section(line.strip())
        if key is not None and key not in seen:
            section_order.append((key, i))
            seen.add(key)

    result: dict[str, tuple[int, int]] = {}
    for idx, (name, start) in enumerate(section_order):
        end = section_order[idx + 1][1] if idx + 1 < len(section_order) else len(lines)
        result[name] = (start, end)

    return result


@register(OS.CISCO_IOS, "show vlan")
@register(OS.CISCO_IOSXE, "show vlan")
class ShowVlanParser(BaseParser[ShowVlanResult]):
    """Parser for 'show vlan' on IOS/IOS-XE."""

    @classmethod
    def parse(cls, output: str) -> ShowVlanResult:
        """Parse 'show vlan' output."""
        lines = output.splitlines()
        sections = _find_sections(lines)

        # Parse basic table (always present)
        basic_start, basic_end = sections["basic"]
        vlans = _parse_basic_table(lines[basic_start + 2 : basic_end])

        # Parse extended table (always present)
        if "extended" in sections:
            ext_start, ext_end = sections["extended"]
            _parse_extended_table(lines[ext_start:ext_end], vlans)

        # Parse AREHops (optional)
        if "arehops" in sections:
            are_start, are_end = sections["arehops"]
            _parse_arehops(lines[are_start:are_end], vlans)

        result: ShowVlanResult = {"vlans": vlans}

        # Parse Remote SPAN VLANs (optional)
        if "remote_span" in sections:
            rs_start, rs_end = sections["remote_span"]
            remote_vlans = _parse_remote_span(lines[rs_start + 1 : rs_end])
            if remote_vlans:
                result["remote_span_vlans"] = remote_vlans

        # Parse Private VLANs (optional)
        if "private_vlan" in sections:
            pv_start, pv_end = sections["private_vlan"]
            private_vlans = _parse_private_vlans(lines[pv_start:pv_end])
            if private_vlans:
                result["private_vlans"] = private_vlans

        return result
