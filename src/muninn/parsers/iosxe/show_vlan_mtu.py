"""Parser for 'show vlan mtu' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag

_HEADER_RE = re.compile(
    r"^VLAN\s+SVI_MTU\s+MinMTU\(port\)\s+MaxMTU\(port\)\s+MTU_Mismatch\s*$"
)
_DATA_RE = re.compile(
    r"^(?P<vlan_id>\d+)\s+"
    r"(?P<svi_mtu>\S+)\s+"
    r"(?P<min_mtu>\d+)\s+"
    r"(?P<max_mtu>\d+)\s+"
    r"(?P<mtu_mismatch>\S+)\s*$"
)


class VlanMtuEntry(TypedDict):
    """Schema for a single VLAN MTU entry."""

    vlan_id: int
    svi_mtu: NotRequired[int]
    min_mtu: int
    max_mtu: int
    mtu_mismatch: bool


class ShowVlanMtuResult(TypedDict):
    """Schema for 'show vlan mtu' parsed output."""

    vlans: dict[str, VlanMtuEntry]


def _build_entry(match: re.Match[str]) -> tuple[str, VlanMtuEntry]:
    """Build a VlanMtuEntry from a regex match."""
    vlan_id_str = match.group("vlan_id")
    svi_mtu_raw = match.group("svi_mtu")

    entry: dict[str, int | bool] = {
        "vlan_id": int(vlan_id_str),
        "min_mtu": int(match.group("min_mtu")),
        "max_mtu": int(match.group("max_mtu")),
        "mtu_mismatch": match.group("mtu_mismatch").lower() == "yes",
    }

    if svi_mtu_raw.isdigit():
        entry["svi_mtu"] = int(svi_mtu_raw)

    return vlan_id_str, cast(VlanMtuEntry, entry)


def _parse_table(output: str) -> dict[str, VlanMtuEntry]:
    """Parse the VLAN MTU table from raw output."""
    vlans: dict[str, VlanMtuEntry] = {}
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()

        if not in_table:
            if _HEADER_RE.match(stripped):
                in_table = True
            continue

        if SEPARATOR_DASH_SPACE_RE.match(stripped) or not stripped:
            continue

        match = _DATA_RE.match(stripped)
        if match:
            vlan_id_str, entry = _build_entry(match)
            vlans[vlan_id_str] = entry

    return vlans


@register(OS.CISCO_IOSXE, "show vlan mtu")
class ShowVlanMtuParser(BaseParser[ShowVlanMtuResult]):
    """Parser for 'show vlan mtu' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SWITCHING,
            ParserTag.VLAN,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowVlanMtuResult:
        """Parse 'show vlan mtu' output into structured data."""
        vlans = _parse_table(output)

        if not vlans:
            msg = "No VLAN MTU entries found in 'show vlan mtu' output"
            raise ValueError(msg)

        return {"vlans": vlans}
