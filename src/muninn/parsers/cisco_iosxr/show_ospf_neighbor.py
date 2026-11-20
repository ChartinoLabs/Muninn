"""Parser for 'show ospf neighbor' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class OspfNeighborEntry(TypedDict):
    """Schema for a single IOS-XR OSPF neighbor entry."""

    priority: int
    state: str
    dead_time: str
    address: str
    role: NotRequired[str]
    up_time: NotRequired[str]


class OspfProcessEntry(TypedDict):
    """Schema for neighbors within an OSPF process."""

    neighbors: dict[str, dict[str, OspfNeighborEntry]]


class ShowOspfNeighborResult(TypedDict):
    """Schema for 'show ospf neighbor' parsed output."""

    processes: dict[str, OspfProcessEntry]


# Section header pattern: "Neighbors for OSPF <process_id>"
# Process ID may be absent (just "Neighbors for OSPF").
_SECTION_PATTERN = re.compile(r"^Neighbors for OSPF\s*(?P<process_id>\S+)?\s*$")

# Neighbor table row pattern for IOS-XR:
# Neighbor ID  Pri  State         Dead Time  Address       Interface
# 1.1.1.1      128  FULL/DR       00:00:39   10.1.2.1      Gi0/0/0/1
# 192.168.48.1   1  FULL/DROTHER  0:00:33    192.168.48.1  Gi 0/3/0/3
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

# Default process ID when the section header has no explicit ID.
_DEFAULT_PROCESS_ID = "default"


@register(OS.CISCO_IOSXR, "show ospf neighbor")
class ShowOspfNeighborParser(BaseParser["ShowOspfNeighborResult"]):
    """Parser for 'show ospf neighbor' command on IOS-XR.

    Parses OSPF neighbor adjacency information from the neighbor table.
    Neighbors are grouped by OSPF process, then keyed by canonical
    interface name and neighbor router ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowOspfNeighborResult":
        """Parse 'show ospf neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data grouped by OSPF process, then keyed
            by interface and neighbor ID.

        Raises:
            ValueError: If no neighbors found in output.
        """
        processes: dict[str, OspfProcessEntry] = {}
        current_process_id: str | None = None
        last_interface: str | None = None
        last_neighbor_id: str | None = None

        for line in output.splitlines():
            result = cls._process_line(
                line,
                processes,
                current_process_id,
                last_interface,
                last_neighbor_id,
            )
            current_process_id, last_interface, last_neighbor_id = result

        if not processes:
            msg = "No OSPF neighbors found in output"
            raise ValueError(msg)

        return cast("ShowOspfNeighborResult", {"processes": processes})

    @classmethod
    def _process_line(
        cls,
        line: str,
        processes: dict[str, OspfProcessEntry],
        current_process_id: str | None,
        last_interface: str | None,
        last_neighbor_id: str | None,
    ) -> tuple[str | None, str | None, str | None]:
        """Process a single line of output.

        Returns:
            Updated (process_id, last_interface, last_neighbor_id).
        """
        section_result = cls._try_section(line.strip(), processes)
        if section_result is not None:
            return section_result, None, None

        uptime_match = _UPTIME_PATTERN.match(line)
        if uptime_match is not None:
            cls._apply_uptime(
                processes,
                current_process_id,
                last_interface,
                last_neighbor_id,
                uptime_match.group("up_time"),
            )
            return current_process_id, last_interface, last_neighbor_id

        neighbor_result = cls._try_neighbor(
            line.strip(),
            processes,
            current_process_id,
        )
        if neighbor_result is not None:
            intf, nid = neighbor_result
            return current_process_id, intf, nid

        return current_process_id, last_interface, last_neighbor_id

    @staticmethod
    def _try_section(
        stripped: str,
        processes: dict[str, OspfProcessEntry],
    ) -> str | None:
        """Try to parse a section header line.

        Returns:
            The process ID if matched, None otherwise.
        """
        match = _SECTION_PATTERN.match(stripped)
        if match is None:
            return None

        process_id = match.group("process_id") or _DEFAULT_PROCESS_ID
        if process_id not in processes:
            processes[process_id] = {"neighbors": {}}
        return process_id

    @classmethod
    def _try_neighbor(
        cls,
        stripped: str,
        processes: dict[str, OspfProcessEntry],
        current_process_id: str | None,
    ) -> tuple[str, str] | None:
        """Try to parse a neighbor row.

        Returns:
            (interface, neighbor_id) if matched, None otherwise.
        """
        if not stripped or current_process_id is None:
            return None

        match = _NEIGHBOR_PATTERN.match(stripped)
        if match is None:
            return None

        interface_raw = match.group("interface").strip()
        interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)
        neighbor_id = match.group("neighbor_id")

        neighbors = processes[current_process_id]["neighbors"]
        if interface not in neighbors:
            neighbors[interface] = {}

        neighbors[interface][neighbor_id] = cls._build_entry(match)
        return interface, neighbor_id

    @staticmethod
    def _build_entry(match: re.Match[str]) -> OspfNeighborEntry:
        """Build a neighbor entry from a regex match."""
        role = match.group("role").strip()
        entry: OspfNeighborEntry = {
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
        processes: dict[str, OspfProcessEntry],
        process_id: str | None,
        interface: str | None,
        neighbor_id: str | None,
        up_time: str,
    ) -> None:
        """Apply an uptime value to the most recently parsed neighbor."""
        if process_id is None or interface is None or neighbor_id is None:
            return

        entry = processes[process_id]["neighbors"][interface][neighbor_id]
        entry["up_time"] = up_time
