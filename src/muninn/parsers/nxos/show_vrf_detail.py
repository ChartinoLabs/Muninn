"""Parser for 'show vrf detail' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class AddressFamilyEntry(TypedDict):
    """Schema for an address family table entry."""

    table_id: str
    fwd_id: str
    state: str


class VrfDetailEntry(TypedDict):
    """Schema for a single VRF detail entry."""

    vrf_id: int
    state: str
    vpn_id: NotRequired[str]
    rd: NotRequired[str]
    max_routes: int
    mid_threshold: int
    address_families: NotRequired[dict[str, AddressFamilyEntry]]


class ShowVrfDetailResult(TypedDict):
    """Schema for 'show vrf detail' parsed output."""

    vrfs: dict[str, VrfDetailEntry]


@register(OS.CISCO_NXOS, "show vrf detail")
class ShowVrfDetailParser(BaseParser[ShowVrfDetailResult]):
    """Parser for 'show vrf detail' command.

    Example output:
        VRF-Name: HUB, VRF-ID: 9, State: Up
            VPNID: 123:456
            RD: 172.21.111.112:197
            Max Routes: 0  Mid-Threshold: 0
            Table-ID: 0x00000009, AF: IPv4, Fwd-ID: 0x00000009, State: Up
    """

    _VRF_HEADER = re.compile(
        r"^VRF-Name:\s+(?P<name>\S+),\s+"
        r"VRF-ID:\s+(?P<vrf_id>\d+),\s+"
        r"State:\s+(?P<state>\S+)"
    )
    _VPNID = re.compile(r"^\s*VPNID:\s+(?P<vpn_id>\S+)")
    _RD = re.compile(r"^\s*RD:\s+(?P<rd>\S+)")
    _MAX_ROUTES = re.compile(
        r"^\s*Max Routes:\s+(?P<max_routes>\d+)\s+"
        r"Mid-Threshold:\s+(?P<mid_threshold>\d+)"
    )
    _TABLE_ID = re.compile(
        r"^\s*Table-ID:\s+(?P<table_id>\S+),\s+"
        r"AF:\s+(?P<af>\S+),\s+"
        r"Fwd-ID:\s+(?P<fwd_id>\S+),\s+"
        r"State:\s+(?P<state>\S+)"
    )

    @classmethod
    def parse(cls, output: str) -> ShowVrfDetailResult:
        """Parse 'show vrf detail' output.

        Args:
            output: Raw CLI output from 'show vrf detail' command.

        Returns:
            Parsed VRF detail data keyed by VRF name.

        Raises:
            ValueError: If no VRFs found in output.
        """
        vrfs: dict[str, VrfDetailEntry] = {}
        current_entry: VrfDetailEntry | None = None
        current_name: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = cls._VRF_HEADER.match(stripped)
            if match:
                current_name = match.group("name")
                current_entry = VrfDetailEntry(
                    vrf_id=int(match.group("vrf_id")),
                    state=match.group("state"),
                    max_routes=0,
                    mid_threshold=0,
                )
                vrfs[current_name] = current_entry
                continue

            if current_entry is None:
                continue

            _parse_detail_line(cls, stripped, current_entry)

        if not vrfs:
            msg = "No VRFs found in output"
            raise ValueError(msg)

        return ShowVrfDetailResult(vrfs=vrfs)


def _parse_detail_line(
    cls: type[ShowVrfDetailParser],
    line: str,
    entry: VrfDetailEntry,
) -> None:
    """Parse a single detail line within a VRF block."""
    if match := cls._VPNID.match(line):
        entry["vpn_id"] = match.group("vpn_id")
        return

    if match := cls._RD.match(line):
        rd_value = match.group("rd")
        if rd_value not in ("--", "N/A"):
            entry["rd"] = rd_value
        return

    if match := cls._MAX_ROUTES.match(line):
        entry["max_routes"] = int(match.group("max_routes"))
        entry["mid_threshold"] = int(match.group("mid_threshold"))
        return

    if match := cls._TABLE_ID.match(line):
        af_name = match.group("af")
        af_entry = AddressFamilyEntry(
            table_id=match.group("table_id"),
            fwd_id=match.group("fwd_id"),
            state=match.group("state"),
        )
        if "address_families" not in entry:
            entry["address_families"] = {}
        entry["address_families"][af_name] = af_entry
