"""Parser for 'show lldp neighbors' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LldpNeighborEntry(TypedDict):
    """Schema for a single LLDP neighbor entry."""

    parent_interface: NotRequired[str]
    chassis_id: str
    port_info: str
    system_name: str


class ShowLldpNeighborsResult(TypedDict):
    """Schema for 'show lldp neighbors' parsed output on Juniper Junos.

    Neighbors are keyed by local interface name (e.g. ``ge-0/0/1``).
    """

    neighbors: dict[str, LldpNeighborEntry]


# Juniper Junos LLDP neighbor table format:
#
# Local Interface  Parent Interface  Chassis Id          Port info  System Name
# ge-0/0/1         -                 2c:6b:f5:a1:c2:c0  ge-0/0/1   vmx2
# ge-0/0/0         -                 2c:6b:f5:a2:08:c0  ge-0/0/0   vmx3

_SKIP_PATTERNS = re.compile(
    r"^\s*$"
    r"|^Local\s+Interface\s+"
    r"|^-{3,}",
    re.IGNORECASE,
)

# Hyphen-only values that represent "no parent interface".
_NO_VALUE_PLACEHOLDER = re.compile(r"^-{1,3}$")

_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<local_intf>\S+)\s+"
    r"(?P<parent_intf>\S+)\s+"
    r"(?P<chassis_id>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+"
    r"(?P<port_info>\S+)\s+"
    r"(?P<system_name>\S+)\s*$"
)


@register(OS.JUNIPER_JUNOS, "show lldp neighbors")
class ShowLldpNeighborsParser(BaseParser[ShowLldpNeighborsResult]):
    """Parser for 'show lldp neighbors' command on Juniper Junos."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    @classmethod
    def parse(cls, output: str) -> ShowLldpNeighborsResult:
        """Parse 'show lldp neighbors' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LLDP neighbors keyed by local interface.

        Raises:
            ValueError: If no LLDP neighbors are found in the output.
        """
        neighbors: dict[str, LldpNeighborEntry] = {}

        for line in output.splitlines():
            if _SKIP_PATTERNS.match(line):
                continue

            match = _NEIGHBOR_PATTERN.match(line)
            if not match:
                continue

            local_intf = match.group("local_intf")
            parent_intf = match.group("parent_intf")
            chassis_id = match.group("chassis_id")
            port_info = match.group("port_info")
            system_name = match.group("system_name")

            entry: LldpNeighborEntry = {
                "chassis_id": chassis_id,
                "port_info": port_info,
                "system_name": system_name,
            }

            # Only include parent_interface when it contains a real value.
            if not _NO_VALUE_PLACEHOLDER.match(parent_intf):
                entry["parent_interface"] = parent_intf

            neighbors[local_intf] = entry

        if not neighbors:
            msg = "No LLDP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowLldpNeighborsResult, {"neighbors": neighbors})
