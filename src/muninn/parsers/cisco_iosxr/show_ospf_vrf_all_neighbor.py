"""Parser for 'show ospf vrf all neighbor' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class OspfVrfNeighborEntry(TypedDict):
    """Schema for a single OSPF neighbor entry within a VRF."""

    priority: int
    state: str
    dead_time: str
    address: str
    role: NotRequired[str]
    up_time: NotRequired[str]


class OspfVrfProcessEntry(TypedDict):
    """Schema for neighbors within an OSPF process and VRF."""

    neighbors: dict[str, dict[str, OspfVrfNeighborEntry]]


class OspfVrfEntry(TypedDict):
    """Schema for a single VRF containing OSPF processes."""

    processes: dict[str, OspfVrfProcessEntry]


class ShowOspfVrfAllNeighborResult(TypedDict):
    """Schema for 'show ospf vrf all neighbor' parsed output.

    Top-level keys are VRF names, each containing processes with neighbors
    keyed by interface then neighbor ID.
    """

    vrfs: dict[str, OspfVrfEntry]


# Section header: "Neighbors for OSPF <process_id>, VRF <vrf_name>"
_SECTION_PATTERN = re.compile(
    r"^Neighbors for OSPF\s+(?P<process_id>\S+),\s+VRF\s+(?P<vrf>\S+)\s*$"
)

# Neighbor table row:
# 192.0.2.1       0     FULL/  -        00:00:39    192.0.2.2       Bundle-Ether10.10
_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<neighbor_id>{IPV4_ADDRESS})\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<state>\w+)/\s*(?P<role>\S+)\s+"
    r"(?P<dead_time>\d{1,2}:\d{2}:\d{2})\s+"
    rf"(?P<address>{IPV4_ADDRESS})\s+"
    r"(?P<interface>\S+(?:\s+\d\S*)?)$"
)

# "Neighbor is up for <duration>" line following a neighbor row.
_UPTIME_PATTERN = re.compile(r"^\s+Neighbor is up for (?P<up_time>\S+)\s*$")


@register(OS.CISCO_IOSXR, "show ospf vrf all neighbor")
class ShowOspfVrfAllNeighborParser(BaseParser["ShowOspfVrfAllNeighborResult"]):
    """Parser for 'show ospf vrf all neighbor' on IOS-XR.

    Parses OSPF neighbor adjacency information across all VRFs.
    Output is nested by VRF name, then OSPF process, then canonical
    interface name, then neighbor router ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
            ParserTag.VRF,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowOspfVrfAllNeighborResult":
        """Parse 'show ospf vrf all neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data grouped by VRF, OSPF process,
            interface, and neighbor ID.

        Raises:
            ValueError: If no neighbors found in output.
        """
        vrfs: dict[str, OspfVrfEntry] = {}
        current_vrf: str | None = None
        current_process: str | None = None
        last_interface: str | None = None
        last_neighbor_id: str | None = None

        for line in output.splitlines():
            result = cls._process_line(
                line,
                vrfs,
                current_vrf,
                current_process,
                last_interface,
                last_neighbor_id,
            )
            current_vrf, current_process, last_interface, last_neighbor_id = result

        if not vrfs:
            msg = "No OSPF VRF neighbors found in output"
            raise ValueError(msg)

        return cast("ShowOspfVrfAllNeighborResult", {"vrfs": vrfs})

    @classmethod
    def _process_line(
        cls,
        line: str,
        vrfs: dict[str, OspfVrfEntry],
        current_vrf: str | None,
        current_process: str | None,
        last_interface: str | None,
        last_neighbor_id: str | None,
    ) -> tuple[str | None, str | None, str | None, str | None]:
        """Process a single line of output.

        Returns:
            Updated (vrf, process_id, last_interface, last_neighbor_id).
        """
        section_result = cls._try_section(line.strip(), vrfs)
        if section_result is not None:
            vrf, process_id = section_result
            return vrf, process_id, None, None

        uptime_match = _UPTIME_PATTERN.match(line)
        if uptime_match is not None:
            cls._apply_uptime(
                vrfs,
                current_vrf,
                current_process,
                last_interface,
                last_neighbor_id,
                uptime_match.group("up_time"),
            )
            return current_vrf, current_process, last_interface, last_neighbor_id

        neighbor_result = cls._try_neighbor(
            line.strip(),
            vrfs,
            current_vrf,
            current_process,
        )
        if neighbor_result is not None:
            intf, nid = neighbor_result
            return current_vrf, current_process, intf, nid

        return current_vrf, current_process, last_interface, last_neighbor_id

    @staticmethod
    def _try_section(
        stripped: str,
        vrfs: dict[str, OspfVrfEntry],
    ) -> tuple[str, str] | None:
        """Try to parse a section header line.

        Returns:
            (vrf_name, process_id) if matched, None otherwise.
        """
        match = _SECTION_PATTERN.match(stripped)
        if match is None:
            return None

        vrf = match.group("vrf")
        process_id = match.group("process_id")

        if vrf not in vrfs:
            vrfs[vrf] = {"processes": {}}
        if process_id not in vrfs[vrf]["processes"]:
            vrfs[vrf]["processes"][process_id] = {"neighbors": {}}

        return vrf, process_id

    @classmethod
    def _try_neighbor(
        cls,
        stripped: str,
        vrfs: dict[str, OspfVrfEntry],
        current_vrf: str | None,
        current_process: str | None,
    ) -> tuple[str, str] | None:
        """Try to parse a neighbor row.

        Returns:
            (interface, neighbor_id) if matched, None otherwise.
        """
        if not stripped or current_vrf is None or current_process is None:
            return None

        match = _NEIGHBOR_PATTERN.match(stripped)
        if match is None:
            return None

        interface_raw = match.group("interface").strip()
        interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)
        neighbor_id = match.group("neighbor_id")

        neighbors = vrfs[current_vrf]["processes"][current_process]["neighbors"]
        if interface not in neighbors:
            neighbors[interface] = {}

        neighbors[interface][neighbor_id] = cls._build_entry(match)
        return interface, neighbor_id

    @staticmethod
    def _build_entry(match: re.Match[str]) -> OspfVrfNeighborEntry:
        """Build a neighbor entry from a regex match."""
        role = match.group("role").strip()
        entry: OspfVrfNeighborEntry = {
            "priority": int(match.group("priority")),
            "state": match.group("state").upper(),
            "dead_time": match.group("dead_time"),
            "address": match.group("address"),
        }

        if role and role != "-":
            entry["role"] = role

        return entry

    @staticmethod
    def _apply_uptime(
        vrfs: dict[str, OspfVrfEntry],
        vrf: str | None,
        process_id: str | None,
        interface: str | None,
        neighbor_id: str | None,
        up_time: str,
    ) -> None:
        """Apply an uptime value to the most recently parsed neighbor."""
        if vrf is None or process_id is None:
            return
        if interface is None or neighbor_id is None:
            return

        entry = vrfs[vrf]["processes"][process_id]["neighbors"][interface][neighbor_id]
        entry["up_time"] = up_time
