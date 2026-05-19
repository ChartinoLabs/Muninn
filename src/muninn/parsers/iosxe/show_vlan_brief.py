"""Parser for 'show vlan brief' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class VlanBriefEntry(TypedDict):
    """Schema for a single VLAN entry in 'show vlan brief' output."""

    vlan_id: int
    name: str
    status: str
    ports: list[str]


class ShowVlanBriefResult(TypedDict):
    """Schema for 'show vlan brief' parsed output."""

    vlans: dict[str, VlanBriefEntry]


_HEADER_RE = re.compile(r"^VLAN\s+Name\s+Status\s+Ports\s*$")
_SEPARATOR_RE = SEPARATOR_DASH_SPACE_RE

# Column positions inferred from the fixed-width header layout:
#   "VLAN Name                             Status    Ports"
#   "---- -------------------------------- --------- ---..."
_NAME_COL = 5
_STATUS_COL = 38
_PORTS_COL = 48

_VALID_STATUSES = frozenset(
    {"active", "suspended", "act/unsup", "act/lshut", "sus/lshut", "sus/unsup"}
)


def _col_field(line: str, start: int, end: int | None = None) -> str:
    """Extract and strip a column-position field from a line."""
    if len(line) <= start:
        return ""
    if end is None:
        return line[start:].strip()
    return line[start:end].strip()


def _normalize_ports(port_str: str) -> list[str]:
    """Split comma-separated ports and normalize to canonical names."""
    port_str = port_str.strip()
    if not port_str:
        return []
    return [
        canonical_interface_name(p.strip(), os=OS.CISCO_IOSXE)
        for p in port_str.split(",")
        if p.strip()
    ]


def _handle_wrapped_name(
    line: str, lines: list[str], i: int
) -> tuple[str, str, str, int]:
    """Handle VLAN name that overflows into the status column.

    Returns ``(name, status, ports_field, new_index)``.
    """
    next_line = lines[i + 1] if i + 1 < len(lines) else ""
    next_status = _col_field(next_line, _STATUS_COL, _PORTS_COL)
    if next_status:
        name = _col_field(line, _NAME_COL)
        ports = _col_field(next_line, _PORTS_COL)
        return name, next_status, ports, i + 1
    # Fallback: treat what we have as the name with no status/ports.
    return _col_field(line, _NAME_COL), "", "", i


def _parse_vlan_line(
    line: str, lines: list[str], i: int
) -> tuple[str, VlanBriefEntry, int]:
    """Parse a new VLAN row, returning ``(vlan_id, entry, new_index)``."""
    vlan_field = line[:4].strip()
    name = _col_field(line, _NAME_COL, _STATUS_COL)
    status = _col_field(line, _STATUS_COL, _PORTS_COL)
    ports_str = _col_field(line, _PORTS_COL)

    if name and status not in _VALID_STATUSES:
        name, status, ports_str, i = _handle_wrapped_name(line, lines, i)

    entry: VlanBriefEntry = {
        "vlan_id": int(vlan_field),
        "name": name,
        "status": status,
        "ports": _normalize_ports(ports_str),
    }
    return vlan_field, entry, i


def _append_continuation_ports(
    vlans: dict[str, VlanBriefEntry], vlan_id: str, stripped: str
) -> None:
    """Append wrapped port-list continuation tokens to an existing VLAN."""
    extra = _normalize_ports(stripped)
    if extra:
        vlans[vlan_id]["ports"].extend(extra)


def _parse_table(lines: list[str]) -> dict[str, VlanBriefEntry]:
    """Walk the output lines and build the ``vlans`` dict."""
    vlans: dict[str, VlanBriefEntry] = {}
    current_vlan_id: str | None = None
    in_table = False

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not in_table:
            if _HEADER_RE.match(stripped):
                in_table = True
            i += 1
            continue

        if _SEPARATOR_RE.match(stripped) or not stripped:
            i += 1
            continue

        vlan_field = line[:4].strip()
        if vlan_field and vlan_field.isdigit():
            vlan_field, entry, i = _parse_vlan_line(line, lines, i)
            vlans[vlan_field] = entry
            current_vlan_id = vlan_field
        elif current_vlan_id is not None:
            # Continuation line: either indented to the ports column with
            # more ports, or an unindented wrap from terminal-width
            # truncation. In both cases all remaining content is ports.
            _append_continuation_ports(vlans, current_vlan_id, stripped)

        i += 1

    return vlans


@register(OS.CISCO_IOSXE, "show vlan brief")
class ShowVlanBriefParser(BaseParser[ShowVlanBriefResult]):
    """Parser for 'show vlan brief' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SWITCHING,
            ParserTag.VLAN,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowVlanBriefResult:
        """Parse 'show vlan brief' output."""
        lines = output.splitlines()
        vlans = _parse_table(lines)
        if not vlans:
            msg = "No VLAN entries found in 'show vlan brief' output"
            raise ValueError(msg)
        return {"vlans": vlans}
