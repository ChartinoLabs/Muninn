"""Parser for 'show vlan' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PrivateVlanInfo(TypedDict):
    """Schema for private VLAN association on a VLAN entry."""

    type: str
    primary_vlan: NotRequired[str]
    secondary_vlans: NotRequired[list[str]]


class VlanEntry(TypedDict):
    """Schema for a single VLAN entry."""

    vlan_id: int
    name: str
    status: str
    ports: list[str]
    type: str
    vlan_mode: str
    private_vlan: NotRequired[PrivateVlanInfo]


class ShowVlanResult(TypedDict):
    """Schema for 'show vlan' parsed output."""

    vlans: dict[str, VlanEntry]
    remote_span_vlans: NotRequired[list[int]]


# Section header patterns
_BASIC_HEADER = re.compile(r"^VLAN\s+Name\s+Status\s+Ports\s*$")
_TYPE_HEADER = re.compile(r"^VLAN\s+Type\s+Vlan-mode\s*$")
_REMOTE_SPAN_HEADER = re.compile(r"^Remote SPAN VLANs\s*$")
_PV_HEADER = re.compile(r"^Primary\s+Secondary\s+Type\s+Ports\s*$")
_SEPARATOR = re.compile(r"^[-\s]+$")

# Column positions for the basic VLAN table (consistent across NX-OS samples)
_NAME_COL = 5
_STATUS_COL = 38
_PORTS_COL = 48

_VALID_STATUSES = {
    "active",
    "suspended",
    "sus/lshut",
    "act/lshut",
    "sus/ishut",
    "act/ishut",
    "act/unsup",
}

# Maps section header patterns to their key names
_SECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_BASIC_HEADER, "basic"),
    (_TYPE_HEADER, "type"),
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


def _col_field(line: str, start: int, end: int | None = None) -> str:
    """Extract and strip a column-position field from a line."""
    if end is None:
        return line[start:].strip() if len(line) > start else ""
    return line[start:end].strip() if len(line) > start else ""


def _is_section_end(line: str) -> bool:
    """Check if a line marks the start of a different section."""
    return bool(
        _TYPE_HEADER.match(line)
        or _REMOTE_SPAN_HEADER.match(line)
        or _PV_HEADER.match(line)
    )


def _parse_basic_table(lines: list[str]) -> dict[str, dict]:
    """Parse the basic VLAN table (Name/Status/Ports)."""
    vlans: dict[str, dict] = {}
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
            name = _col_field(line, _NAME_COL, _STATUS_COL)
            status = _col_field(line, _STATUS_COL, _PORTS_COL)
            ports_str = _col_field(line, _PORTS_COL)

            # Handle VLAN names that overflow into the status column
            if name and status not in _VALID_STATUSES:
                combined = _col_field(line, _NAME_COL)
                # Try to find the status by splitting from the right
                for valid_status in _VALID_STATUSES:
                    if combined.endswith(valid_status):
                        name = combined[: -len(valid_status)].strip()
                        status = valid_status
                        break

            vlans[vlan_field] = {
                "vlan_id": int(vlan_field),
                "name": name,
                "status": status,
                "ports": _normalize_ports(ports_str),
            }
            current_vlan_id = vlan_field
        elif current_vlan_id is not None:
            # Continuation line for ports
            ports_str = _col_field(line, _PORTS_COL)
            if ports_str:
                vlans[current_vlan_id]["ports"].extend(_normalize_ports(ports_str))

        i += 1

    return vlans


def _parse_type_table(lines: list[str], vlans: dict[str, dict]) -> None:
    """Parse the VLAN Type/Vlan-mode table and merge into vlans dict."""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _TYPE_HEADER.match(stripped) or _SEPARATOR.match(stripped):
            continue

        parts = stripped.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue

        vlan_id = parts[0]
        entry = vlans.get(vlan_id)
        if entry is not None:
            entry["type"] = parts[1]
            entry["vlan_mode"] = parts[2]


def _parse_remote_span(lines: list[str]) -> list[int]:
    """Parse Remote SPAN VLANs section."""
    result: list[int] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or _SEPARATOR.match(stripped):
            continue
        result.extend(_expand_vlan_ranges(stripped))
    return sorted(result)


def _find_pv_header(lines: list[str]) -> int:
    """Find the index of the Private VLAN header line."""
    for i, line in enumerate(lines):
        if _PV_HEADER.match(line.strip()):
            return i
    return -1


def _apply_secondary_pv(
    vlans: dict[str, dict],
    sec_str: str,
    pri_str: str,
    type_str: str,
    ports_str: str,
) -> None:
    """Apply private VLAN info to a secondary VLAN entry."""
    sec_entry = vlans.get(sec_str)
    if sec_entry is None:
        return
    pv_info: PrivateVlanInfo = {"type": type_str}
    if pri_str and pri_str.isdigit():
        pv_info["primary_vlan"] = pri_str
    sec_entry["private_vlan"] = pv_info
    if ports_str:
        sec_entry["ports"] = _normalize_ports(ports_str)


def _apply_primary_pv(vlans: dict[str, dict], pri_str: str, sec_str: str) -> None:
    """Add secondary VLAN reference to a primary VLAN entry."""
    if not pri_str or not pri_str.isdigit():
        return
    pri_entry = vlans.get(pri_str)
    if pri_entry is None:
        return
    if "private_vlan" not in pri_entry:
        pri_entry["private_vlan"] = {"type": "primary", "secondary_vlans": []}
    pri_pv = pri_entry["private_vlan"]
    if "secondary_vlans" not in pri_pv:
        pri_pv["secondary_vlans"] = []
    pri_pv["secondary_vlans"].append(sec_str)


def _parse_private_vlans(lines: list[str], vlans: dict[str, dict]) -> None:
    """Parse Private VLAN associations and merge into vlans dict."""
    header_idx = _find_pv_header(lines)
    if header_idx < 0:
        return

    header = lines[header_idx]
    pri_col = header.index("Primary")
    sec_col = header.index("Secondary")
    type_col = header.index("Type")
    ports_col = header.index("Ports")

    for line in lines[header_idx + 1 :]:
        stripped = line.strip()
        if not stripped or _SEPARATOR.match(stripped):
            continue

        padded = line.ljust(ports_col + 80)
        pri_str = padded[pri_col:sec_col].strip()
        sec_str = padded[sec_col:type_col].strip()
        type_str = padded[type_col:ports_col].strip()
        ports_str = padded[ports_col:].strip()

        if not sec_str or not sec_str.isdigit():
            continue

        _apply_secondary_pv(vlans, sec_str, pri_str, type_str, ports_str)
        _apply_primary_pv(vlans, pri_str, sec_str)


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


@register(OS.CISCO_NXOS, "show vlan")
class ShowVlanParser(BaseParser[ShowVlanResult]):
    """Parser for 'show vlan' on NX-OS."""

    @classmethod
    def parse(cls, output: str) -> ShowVlanResult:
        """Parse 'show vlan' output on NX-OS."""
        lines = output.splitlines()
        sections = _find_sections(lines)

        # Parse basic table (always present)
        basic_start, basic_end = sections["basic"]
        vlans = _parse_basic_table(lines[basic_start + 2 : basic_end])

        # Parse type/vlan-mode table
        if "type" in sections:
            type_start, type_end = sections["type"]
            _parse_type_table(lines[type_start:type_end], vlans)

        # Parse private VLANs (merge into vlans dict)
        if "private_vlan" in sections:
            pv_start, pv_end = sections["private_vlan"]
            _parse_private_vlans(lines[pv_start:pv_end], vlans)

        result: ShowVlanResult = {"vlans": vlans}

        # Parse Remote SPAN VLANs (optional)
        if "remote_span" in sections:
            rs_start, rs_end = sections["remote_span"]
            remote_vlans = _parse_remote_span(lines[rs_start + 1 : rs_end])
            if remote_vlans:
                result["remote_span_vlans"] = remote_vlans

        return result
