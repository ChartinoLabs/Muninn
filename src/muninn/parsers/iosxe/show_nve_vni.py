"""Parser for 'show nve vni' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class NveVniEntry(TypedDict):
    """Schema for a single NVE VNI entry."""

    interface: str
    vni: int
    vni_state: str
    mode: str
    cfg: str
    multicast_group: NotRequired[str]
    vlan: NotRequired[int]
    vrf: NotRequired[str]


class ShowNveVniResult(TypedDict):
    """Schema for 'show nve vni' parsed output."""

    vnis: dict[str, NveVniEntry]


def _normalize(value: str | None) -> str | None:
    """Normalize sentinel values to None."""
    if value is None:
        return None
    value = value.strip()
    if not value or value in ("--", "N/A"):
        return None
    return value


@register(OS.CISCO_IOSXE, "show nve vni")
class ShowNveVniParser(BaseParser[ShowNveVniResult]):
    """Parser for 'show nve vni' command.

    Example output:
        Interface  VNI        Multicast-group VNI state  Mode  VLAN  cfg vrf
        nve1       30000      N/A             BD Down/Re L3CP  N/A   CLI red
        nve1       20011      N/A             Up         L2CP  11    CLI N/A
    """

    tags: ClassVar[frozenset[str]] = frozenset({"vxlan"})

    # Match data rows: interface, VNI, multicast-group, VNI state, mode,
    # VLAN/BD, cfg, vrf.
    # VNI state can be multi-word (e.g. "BD Down/Re") so we capture up to the
    # mode token (L2CP/L3CP/L2DP/L3DP etc).
    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<vni>\d+)\s+"
        r"(?P<mcast>\S+)\s+"
        r"(?P<vni_state>.+?)\s+"
        r"(?P<mode>L[23][CD]P)\s+"
        r"(?P<vlan>\S+)\s+"
        r"(?P<cfg>\S+)\s+"
        r"(?P<vrf>\S+)\s*$"
    )

    @classmethod
    def _is_header_line(cls, line: str) -> bool:
        """Check if a line is a table header."""
        return "VNI" in line and "Multicast" in line

    @classmethod
    def _build_entry(cls, match: re.Match[str]) -> NveVniEntry:
        """Build an NveVniEntry from a regex match."""
        vlan_raw = _normalize(match.group("vlan"))
        mcast_raw = _normalize(match.group("mcast"))
        vrf_raw = _normalize(match.group("vrf"))

        entry: NveVniEntry = {
            "interface": match.group("interface"),
            "vni": int(match.group("vni")),
            "vni_state": match.group("vni_state").strip(),
            "mode": match.group("mode"),
            "cfg": match.group("cfg"),
        }

        if mcast_raw:
            entry["multicast_group"] = mcast_raw
        if vlan_raw:
            entry["vlan"] = int(vlan_raw)
        if vrf_raw:
            entry["vrf"] = vrf_raw

        return entry

    @classmethod
    def parse(cls, output: str) -> ShowNveVniResult:
        """Parse 'show nve vni' output.

        Args:
            output: Raw CLI output from 'show nve vni' command.

        Returns:
            Parsed NVE VNI data keyed by VNI number.

        Raises:
            ValueError: If no VNI entries found in output.
        """
        vnis: dict[str, NveVniEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line or cls._is_header_line(line):
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                vni_id = match.group("vni")
                vnis[vni_id] = cls._build_entry(match)

        if not vnis:
            msg = "No NVE VNI entries found in output"
            raise ValueError(msg)

        return ShowNveVniResult(vnis=vnis)
