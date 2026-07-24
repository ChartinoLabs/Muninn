"""Parser for 'show isis neighbors detail' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisNeighborDetailEntry(TypedDict):
    """Schema for a single IS-IS neighbor detail entry."""

    snpa: str
    state: str
    holdtime: int
    neighbor_type: str
    ietf_nsf: NotRequired[str]
    area_addresses: list[str]
    ipv4_addresses: NotRequired[list[str]]
    ipv6_addresses: NotRequired[list[str]]
    topologies: list[str]
    uptime: str


class ShowIsisNeighborsDetailResult(TypedDict):
    """Schema for 'show isis neighbors detail' parsed output.

    Top-level keys are IS-IS instance IDs. Each instance maps system IDs
    to a dict of interfaces, each containing the detailed neighbor entry.
    """

    instances: dict[str, dict[str, dict[str, IsisNeighborDetailEntry]]]
    total_neighbor_count: NotRequired[int]


# Instance header: "IS-IS <tag> neighbors:"
_INSTANCE_PATTERN = re.compile(r"^IS-IS\s+(?P<instance>\S+)\s+neighbors:\s*$")

# Summary footer: "Total neighbor count: N"
_TOTAL_PATTERN = re.compile(r"^Total\s+neighbor\s+count:\s+(?P<count>\d+)\s*$")

# Neighbor table row:
# System Id      Interface        SNPA           State Holdtime Type IETF-NSF
# RTR1           Hu0/0/0/1.10    *PtoP*         Up    26       L2   Capable
_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<system_id>\S+)\s+"
    r"(?P<interface>\S+(?:\s+\d\S*)?)\s+"
    r"(?P<snpa>\S+)\s+"
    r"(?P<state>\w+)\s+"
    r"(?P<holdtime>\d+)\s+"
    r"(?P<type>L1L2|L1|L2)\s*"
    r"(?P<ietf_nsf>\S+)?\s*$"
)

# Detail lines following a neighbor row
_AREA_ADDR_PATTERN = re.compile(r"^\s+Area Address\(es\):\s+(?P<addresses>.+)$")
_IPV4_ADDR_PATTERN = re.compile(r"^\s+IPv4 Address\(es\):\s+(?P<addresses>.+)$")
_IPV6_ADDR_PATTERN = re.compile(r"^\s+IPv6 Address\(es\):\s+(?P<addresses>.+)$")
_TOPOLOGIES_PATTERN = re.compile(r"^\s+Topologies:\s+(?P<topologies>.+)$")
_UPTIME_PATTERN = re.compile(r"^\s+Uptime:\s+(?P<uptime>\S+)\s*$")

# Default instance ID when no header is found (single-instance output).
_DEFAULT_INSTANCE = "default"


def _parse_address_list(raw: str) -> list[str]:
    """Parse space-separated addresses, stripping trailing asterisks."""
    return [addr.rstrip("*") for addr in raw.split()]


def _parse_topology_list(raw: str) -> list[str]:
    """Parse quoted topology names from the Topologies line.

    Example: "'IPv4 Unicast' 'IPv6 Unicast'" -> ["IPv4 Unicast", "IPv6 Unicast"]
    """
    return re.findall(r"'([^']+)'", raw)


@register(OS.CISCO_IOSXR, "show isis neighbors detail")
class ShowIsisNeighborsDetailParser(BaseParser["ShowIsisNeighborsDetailResult"]):
    """Parser for 'show isis neighbors detail' command on IOS-XR.

    Parses detailed IS-IS neighbor adjacency information including area
    addresses, IPv4/IPv6 addresses, topologies, and uptime. Neighbors are
    grouped by IS-IS instance, then keyed by system ID and canonical
    interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisNeighborsDetailResult":
        """Parse 'show isis neighbors detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor detail data grouped by IS-IS instance, then keyed
            by system ID and interface.

        Raises:
            ValueError: If no neighbors found in output.
        """
        instances: dict[str, dict[str, dict[str, IsisNeighborDetailEntry]]] = {}
        current_instance: str | None = None
        current_entry: IsisNeighborDetailEntry | None = None
        total_neighbor_count: int | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            current_instance, current_entry, total_neighbor_count = cls._process_line(
                line,
                stripped,
                instances,
                current_instance,
                current_entry,
                total_neighbor_count,
            )

        if not instances:
            msg = "No IS-IS neighbors found in output"
            raise ValueError(msg)

        result: ShowIsisNeighborsDetailResult = {"instances": instances}
        if total_neighbor_count is not None:
            result["total_neighbor_count"] = total_neighbor_count
        return result

    @classmethod
    def _process_line(
        cls,
        line: str,
        stripped: str,
        instances: dict[str, dict[str, dict[str, IsisNeighborDetailEntry]]],
        current_instance: str | None,
        current_entry: IsisNeighborDetailEntry | None,
        total_neighbor_count: int | None,
    ) -> tuple[str | None, IsisNeighborDetailEntry | None, int | None]:
        """Process a single line and return updated state."""
        # Check for instance header
        instance_match = _INSTANCE_PATTERN.match(stripped)
        if instance_match:
            current_instance = instance_match.group("instance")
            if current_instance not in instances:
                instances[current_instance] = {}
            return current_instance, None, total_neighbor_count

        # Check for total neighbor count footer
        total_match = _TOTAL_PATTERN.match(stripped)
        if total_match:
            return current_instance, current_entry, int(total_match.group("count"))

        # Check for a new neighbor row
        neighbor_match = _NEIGHBOR_PATTERN.match(stripped)
        if neighbor_match:
            if current_instance is None:
                current_instance = _DEFAULT_INSTANCE
                instances[current_instance] = {}
            entry = cls._create_neighbor_entry(
                instances, current_instance, neighbor_match
            )
            return current_instance, entry, total_neighbor_count

        # Parse detail lines that follow a neighbor row
        if current_entry is not None:
            cls._parse_detail_line(line, current_entry)

        return current_instance, current_entry, total_neighbor_count

    @classmethod
    def _create_neighbor_entry(
        cls,
        instances: dict[str, dict[str, dict[str, IsisNeighborDetailEntry]]],
        instance_id: str,
        match: re.Match[str],
    ) -> IsisNeighborDetailEntry:
        """Create and insert a neighbor entry from the matched table row."""
        system_id = match.group("system_id")
        interface_raw = match.group("interface").strip()
        interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)

        neighbors = instances[instance_id]
        if system_id not in neighbors:
            neighbors[system_id] = {}

        entry: IsisNeighborDetailEntry = {
            "snpa": match.group("snpa"),
            "state": match.group("state"),
            "holdtime": int(match.group("holdtime")),
            "neighbor_type": match.group("type"),
            "area_addresses": [],
            "topologies": [],
            "uptime": "",
        }

        ietf_nsf = match.group("ietf_nsf")
        if ietf_nsf:
            entry["ietf_nsf"] = ietf_nsf

        neighbors[system_id][interface] = entry
        return entry

    @staticmethod
    def _parse_detail_line(
        line: str,
        entry: IsisNeighborDetailEntry,
    ) -> None:
        """Parse a single detail line and update the entry."""
        area_match = _AREA_ADDR_PATTERN.match(line)
        if area_match:
            entry["area_addresses"] = _parse_address_list(area_match.group("addresses"))
            return

        ipv4_match = _IPV4_ADDR_PATTERN.match(line)
        if ipv4_match:
            entry["ipv4_addresses"] = _parse_address_list(ipv4_match.group("addresses"))
            return

        ipv6_match = _IPV6_ADDR_PATTERN.match(line)
        if ipv6_match:
            entry["ipv6_addresses"] = _parse_address_list(ipv6_match.group("addresses"))
            return

        topo_match = _TOPOLOGIES_PATTERN.match(line)
        if topo_match:
            entry["topologies"] = _parse_topology_list(topo_match.group("topologies"))
            return

        uptime_match = _UPTIME_PATTERN.match(line)
        if uptime_match:
            entry["uptime"] = uptime_match.group("uptime")
