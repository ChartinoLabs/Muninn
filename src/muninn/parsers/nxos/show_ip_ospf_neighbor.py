"""Parser for 'show ip ospf neighbor' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class OspfNeighborEntry(TypedDict):
    """Schema for a single NX-OS OSPF neighbor entry."""

    priority: int
    state: str
    up_time: str
    address: str
    role: NotRequired[str]


class OspfProcessEntry(TypedDict):
    """Schema for an OSPF process within a VRF."""

    neighbors: dict[str, dict[str, OspfNeighborEntry]]


class OspfVrfEntry(TypedDict):
    """Schema for a VRF containing one or more OSPF processes."""

    processes: dict[str, OspfProcessEntry]


class ShowIpOspfNeighborResult(TypedDict):
    """Schema for 'show ip ospf neighbor' parsed output."""

    vrfs: dict[str, OspfVrfEntry]


# Pattern for neighbor table rows on NX-OS:
# Neighbor ID     Pri State            Up Time  Address         Interface
# 192.168.1.8       1 FULL/ -          2y0w     192.168.2.2     Vlan2
# 10.0.0.6          1 INIT/DROTHER     -        77.77.77.77     Po4
# 10.0.0.7          1 FULL/            4d19h    88.88.88.88     Eth1/3
_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<neighbor_id>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<state_role>.+?)\s{2,}"
    r"(?P<up_time>\S+)\s+"
    r"(?P<address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"(?P<interface>\S+)\s*$"
)

_SECTION_PATTERN = re.compile(
    r"^OSPF Process ID (?P<process_id>\S+) VRF (?P<vrf>\S+)\s*$"
)


@register(OS.CISCO_NXOS, "show ip ospf neighbor")
class ShowIpOspfNeighborParser(BaseParser[ShowIpOspfNeighborResult]):
    """Parser for 'show ip ospf neighbor' command on NX-OS.

    Parses OSPF neighbor adjacency information from the neighbor table.
    Neighbors are keyed by canonical interface name, then by neighbor router ID.
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfNeighborResult:
        """Parse 'show ip ospf neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data keyed by interface then neighbor ID.

        Raises:
            ValueError: If no neighbors found in output.
        """
        vrfs: dict[str, OspfVrfEntry] = {}
        current_vrf: str | None = None
        current_process_id: str | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            section = cls._parse_section(line, vrfs)
            if section is not None:
                current_vrf, current_process_id = section
                continue

            match = _NEIGHBOR_PATTERN.match(line)
            if not match:
                continue

            if current_vrf is None or current_process_id is None:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_NXOS
            )
            neighbor_id = match.group("neighbor_id")
            state, role = cls._parse_state_role(match.group("state_role"))
            neighbors = vrfs[current_vrf]["processes"][current_process_id]["neighbors"]

            if interface not in neighbors:
                neighbors[interface] = {}

            entry: OspfNeighborEntry = {
                "priority": int(match.group("priority")),
                "state": state,
                "up_time": match.group("up_time"),
                "address": match.group("address"),
            }

            if role and role != "-":
                entry["role"] = role

            neighbors[interface][neighbor_id] = entry

        if not vrfs:
            msg = "No OSPF neighbors found in output"
            raise ValueError(msg)

        return ShowIpOspfNeighborResult(vrfs=vrfs)

    @staticmethod
    def _parse_section(
        line: str, vrfs: dict[str, OspfVrfEntry]
    ) -> tuple[str, str] | None:
        section_match = _SECTION_PATTERN.match(line)
        if section_match is None:
            return None

        vrf = section_match.group("vrf")
        process_id = section_match.group("process_id")

        if vrf not in vrfs:
            vrfs[vrf] = {"processes": {}}

        processes = vrfs[vrf]["processes"]
        if process_id not in processes:
            processes[process_id] = {"neighbors": {}}

        return vrf, process_id

    @staticmethod
    def _parse_state_role(state_role: str) -> tuple[str, str]:
        state, _, role = state_role.partition("/")
        return state.strip().upper(), role.strip()
