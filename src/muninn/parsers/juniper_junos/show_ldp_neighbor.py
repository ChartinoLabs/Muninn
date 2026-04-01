"""Parser for 'show ldp neighbor' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class LdpNeighborEntry(TypedDict):
    """Schema for a single Junos LDP neighbor entry.

    Attributes:
        address: Neighbor transport address.
        interface: Local interface name (e.g., ``ge-0/0/0.0``).
        label_space_id: Label space identifier (e.g., ``10.34.2.250:0``).
        hold_time: Hold time remaining in seconds.
    """

    address: str
    interface: str
    label_space_id: str
    hold_time: int


class ShowLdpNeighborResult(TypedDict):
    """Schema for 'show ldp neighbor' parsed output.

    Top-level dict-of-dicts keyed by neighbor address.
    """

    neighbors: dict[str, LdpNeighborEntry]


# Junos 'show ldp neighbor' output format:
# Address                             Interface       Label space ID     Hold time
# 10.169.14.158                      ge-0/0/0.0      10.34.2.250:0       14
_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<address>{IPV4_ADDRESS})\s+"
    r"(?P<interface>\S+)\s+"
    rf"(?P<label_space_id>{IPV4_ADDRESS}:\d+)\s+"
    r"(?P<hold_time>\d+)\s*$"
)

# Junos prompt lines like "{master:0}" or "{primary:node0}"
_PROMPT_PATTERN = re.compile(r"^\{.+\}\s*$")


@register(OS.JUNIPER_JUNOS, "show ldp neighbor")
class ShowLdpNeighborParser(BaseParser[ShowLdpNeighborResult]):
    """Parser for 'show ldp neighbor' command on Juniper Junos.

    Parses LDP neighbor information from the neighbor table.
    Neighbors are keyed by their transport address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MPLS,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowLdpNeighborResult:
        """Parse 'show ldp neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data keyed by neighbor address.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors: dict[str, LdpNeighborEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Skip header lines, command echo, and prompt lines
            if _PROMPT_PATTERN.match(stripped):
                continue

            match = _NEIGHBOR_PATTERN.match(stripped)
            if match is None:
                continue

            address = match.group("address")
            neighbors[address] = LdpNeighborEntry(
                address=address,
                interface=match.group("interface"),
                label_space_id=match.group("label_space_id"),
                hold_time=int(match.group("hold_time")),
            )

        if not neighbors:
            msg = "No LDP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowLdpNeighborResult, {"neighbors": neighbors})
