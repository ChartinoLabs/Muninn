"""Parser for 'show vlan' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class VlanEntry(TypedDict):
    """Schema for a single VLAN entry."""

    vlan_id: int
    name: str
    status: str
    ports: list[str]


class ShowVlanResult(TypedDict):
    """Schema for 'show vlan' parsed output."""

    vlans: dict[str, VlanEntry]


_BASIC_HEADER = re.compile(r"^VLAN\s+Name\s+Status\s+Ports\s*$")

# Column positions for the basic VLAN table.  Boundaries are taken from the
# header line: ``VLAN  Name                             Status    Ports``.
_VLAN_END = 5
_NAME_COL = 6
_STATUS_COL = 39
_PORTS_COL = 49


def _normalize_ports(port_str: str) -> list[str]:
    """Split comma-separated ports and normalize to canonical names."""
    port_str = port_str.strip()
    if not port_str:
        return []
    return [
        canonical_interface_name(p.strip(), os=OS.ARISTA_EOS)
        for p in port_str.split(",")
        if p.strip()
    ]


def _col_field(line: str, start: int, end: int | None = None) -> str:
    """Extract and strip a column-position field from a line."""
    if len(line) <= start:
        return ""
    if end is None:
        return line[start:].strip()
    return line[start:end].strip()


def _parse_basic_line(line: str) -> tuple[str, VlanEntry] | None:
    """Parse a single VLAN row from the basic table."""
    vlan_field = line[:_VLAN_END].strip()
    if not vlan_field or not vlan_field.isdigit():
        return None
    name = _col_field(line, _NAME_COL, _STATUS_COL)
    status = _col_field(line, _STATUS_COL, _PORTS_COL)
    ports_str = _col_field(line, _PORTS_COL)
    entry: VlanEntry = {
        "vlan_id": int(vlan_field),
        "name": name,
        "status": status,
        "ports": _normalize_ports(ports_str),
    }
    return vlan_field, entry


def _parse_basic_table(lines: list[str]) -> dict[str, VlanEntry]:
    """Parse the basic VLAN table, including wrapped port-list continuations."""
    vlans: dict[str, VlanEntry] = {}
    current_vlan_id: str | None = None

    for line in lines:
        if SEPARATOR_DASH_SPACE_RE.match(line) or not line.strip():
            continue
        if _BASIC_HEADER.match(line.strip()):
            continue

        parsed = _parse_basic_line(line)
        if parsed is not None:
            vlan_id, entry = parsed
            vlans[vlan_id] = entry
            current_vlan_id = vlan_id
        elif current_vlan_id is not None:
            ports_str = _col_field(line, _PORTS_COL)
            if ports_str:
                vlans[current_vlan_id]["ports"].extend(_normalize_ports(ports_str))

    return vlans


@register(OS.ARISTA_EOS, "show vlan")
class ShowVlanParser(BaseParser[ShowVlanResult]):
    """Parser for 'show vlan' command on Arista EOS.

    Parses the VLAN table into a wrapper dict containing ``vlans`` keyed by
    VLAN ID string, with each entry carrying the VLAN id, name, status, and
    canonical port list.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SWITCHING,
            ParserTag.VLAN,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowVlanResult:
        """Parse 'show vlan' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            ShowVlanResult with a ``vlans`` dict keyed by VLAN ID string.

        Raises:
            ValueError: If no VLAN entries are found.
        """
        vlans = _parse_basic_table(output.splitlines())
        if not vlans:
            msg = "No VLAN entries found in output"
            raise ValueError(msg)
        return {"vlans": vlans}
