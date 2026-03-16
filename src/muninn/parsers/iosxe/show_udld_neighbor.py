"""Parser for 'show udld neighbor' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class UdldNeighborEntry(TypedDict):
    """Schema for a single UDLD neighbor entry."""

    device_name: str
    device_id: int
    port_id: str
    neighbor_state: str


class ShowUdldNeighborResult(TypedDict):
    """Schema for 'show udld neighbor' parsed output."""

    neighbors: dict[str, UdldNeighborEntry]
    total_bidirectional_entries: int


@register(OS.CISCO_IOSXE, "show udld neighbor")
class ShowUdldNeighborParser(BaseParser[ShowUdldNeighborResult]):
    """Parser for 'show udld neighbor' command on IOS-XE.

    Parses UDLD neighbor information showing connected devices and their
    bidirectional state.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"interfaces"})

    # Port           Device Name     Device ID    Port ID         Neighbor State
    # Gi1/0/7        A4B43937780     1            Gi1/0/6         Bidirectional
    _NEIGHBOR_PATTERN = re.compile(
        r"^(?P<port>\S+)\s+"
        r"(?P<device_name>\S+)\s+"
        r"(?P<device_id>\d+)\s+"
        r"(?P<port_id>\S+)\s+"
        r"(?P<neighbor_state>\S+)$"
    )

    _TOTAL_PATTERN = re.compile(
        r"^Total number of bidirectional entries displayed:\s*(?P<total>\d+)",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowUdldNeighborResult:
        """Parse 'show udld neighbor' output on IOS-XE.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed UDLD neighbors keyed by local interface name.

        Raises:
            ValueError: If no UDLD neighbors found in output.
        """
        neighbors: dict[str, UdldNeighborEntry] = {}
        total_bidirectional: int | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Skip header lines
            if line.startswith(("Port", "----")):
                continue

            # Check for total line
            total_match = cls._TOTAL_PATTERN.match(line)
            if total_match:
                total_bidirectional = int(total_match.group("total"))
                continue

            # Try neighbor entry
            match = cls._NEIGHBOR_PATTERN.match(line)
            if match:
                interface = canonical_interface_name(
                    match.group("port"), os=OS.CISCO_IOSXE
                )
                port_id = canonical_interface_name(
                    match.group("port_id"), os=OS.CISCO_IOSXE
                )

                neighbors[interface] = {
                    "device_name": match.group("device_name"),
                    "device_id": int(match.group("device_id")),
                    "port_id": port_id,
                    "neighbor_state": match.group("neighbor_state"),
                }

        if not neighbors:
            msg = "No UDLD neighbors found in output"
            raise ValueError(msg)

        if total_bidirectional is None:
            msg = "No total bidirectional entries line found in output"
            raise ValueError(msg)

        return ShowUdldNeighborResult(
            neighbors=neighbors,
            total_bidirectional_entries=total_bidirectional,
        )
