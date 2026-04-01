"""Parser for 'show isis neighbors' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisNeighborEntry(TypedDict):
    """Schema for a single IS-IS neighbor entry."""

    snpa: str
    state: str
    holdtime: int
    neighbor_type: str
    ietf_nsf: NotRequired[str]


class ShowIsisNeighborsResult(TypedDict):
    """Schema for 'show isis neighbors' parsed output.

    Top-level keys are IS-IS instance IDs. Each instance maps system IDs
    to a dict of interfaces, each containing the neighbor entry.
    """

    instances: dict[str, dict[str, dict[str, IsisNeighborEntry]]]


# Instance header: "IS-IS <tag> neighbors:"
_INSTANCE_PATTERN = re.compile(r"^IS-IS\s+(?P<instance>\S+)\s+neighbors:\s*$")

# Neighbor table row:
# System Id      Interface        SNPA           State Holdtime Type IETF-NSF
# CSR2           Gi0/0/0/1        5000.0002.0001 Up    23       L1L2 Capable
_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<system_id>\S+)\s+"
    r"(?P<interface>\S+(?:\s+\d\S*)?)\s+"
    r"(?P<snpa>\S+)\s+"
    r"(?P<state>\w+)\s+"
    r"(?P<holdtime>\d+)\s+"
    r"(?P<type>L1L2|L1|L2)\s*"
    r"(?P<ietf_nsf>\S+)?\s*$"
)

# Default instance ID when no header is found (single-instance output).
_DEFAULT_INSTANCE = "default"


@register(OS.CISCO_IOSXR, "show isis neighbors")
class ShowIsisNeighborsParser(BaseParser["ShowIsisNeighborsResult"]):
    """Parser for 'show isis neighbors' command on IOS-XR.

    Parses IS-IS neighbor adjacency information. Neighbors are grouped
    by IS-IS instance, then keyed by system ID and canonical interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisNeighborsResult":
        """Parse 'show isis neighbors' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data grouped by IS-IS instance, then keyed
            by system ID and interface.

        Raises:
            ValueError: If no neighbors found in output.
        """
        instances: dict[str, dict[str, dict[str, IsisNeighborEntry]]] = {}
        current_instance: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            instance_match = _INSTANCE_PATTERN.match(stripped)
            if instance_match:
                current_instance = instance_match.group("instance")
                if current_instance not in instances:
                    instances[current_instance] = {}
                continue

            neighbor_match = _NEIGHBOR_PATTERN.match(stripped)
            if neighbor_match:
                if current_instance is None:
                    current_instance = _DEFAULT_INSTANCE
                    instances[current_instance] = {}

                cls._add_neighbor(instances, current_instance, neighbor_match)

        if not instances:
            msg = "No IS-IS neighbors found in output"
            raise ValueError(msg)

        return {"instances": instances}

    @staticmethod
    def _add_neighbor(
        instances: dict[str, dict[str, dict[str, IsisNeighborEntry]]],
        instance_id: str,
        match: re.Match[str],
    ) -> None:
        """Add a parsed neighbor entry to the instances dict."""
        system_id = match.group("system_id")
        interface_raw = match.group("interface").strip()
        interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)

        neighbors = instances[instance_id]
        if system_id not in neighbors:
            neighbors[system_id] = {}

        entry: IsisNeighborEntry = {
            "snpa": match.group("snpa"),
            "state": match.group("state"),
            "holdtime": int(match.group("holdtime")),
            "neighbor_type": match.group("type"),
        }

        ietf_nsf = match.group("ietf_nsf")
        if ietf_nsf:
            entry["ietf_nsf"] = ietf_nsf

        neighbors[system_id][interface] = entry
