"""Parser for 'show ipv6 neighbors' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS_COLON
from muninn.registry import register
from muninn.tags import ParserTag


class Ipv6NeighborEntry(TypedDict):
    """Schema for a single IPv6 neighbor entry."""

    mac_address: str
    state: str
    expire_seconds: int
    is_router: bool
    is_secure: bool
    interface: str


class ShowIpv6NeighborsResult(TypedDict):
    """Schema for 'show ipv6 neighbors' parsed output.

    Neighbor entries are keyed by IPv6 address.
    """

    ipv6_neighbors: dict[str, Ipv6NeighborEntry]
    total_entries: NotRequired[int]


@register(OS.JUNIPER_JUNOS, "show ipv6 neighbors")
class ShowIpv6NeighborsParser(BaseParser[ShowIpv6NeighborsResult]):
    """Parser for 'show ipv6 neighbors' command on Juniper Junos.

    Parses IPv6 neighbor discovery table entries containing IPv6 address,
    MAC address, state, expiry, router flag, secure flag, and interface.

    Example output::

        IPv6 Address         Linklayer Address  State
        2001:db8::1          00:50:56:ff:00:4b  reachable
        fe80::250:56ff:fe04  00:50:56:ff:e0:4e  delay
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    _NEIGHBOR_ENTRY = re.compile(
        r"^\s*(?P<ipv6>\S+)\s+"
        rf"(?P<mac>{MAC_ADDRESS_COLON})\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<expire>\d+)\s+"
        r"(?P<router>yes|no)\s+"
        r"(?P<secure>yes|no)\s+"
        r"(?P<interface>\S+)\s*$",
    )
    _TOTAL_ENTRIES = re.compile(r"^\s*Total entries:\s*(?P<count>\d+)\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowIpv6NeighborsResult:
        """Parse 'show ipv6 neighbors' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed IPv6 neighbor entries keyed by IPv6 address.

        Raises:
            ValueError: If no neighbor entries are found in the output.
        """
        neighbors: dict[str, Ipv6NeighborEntry] = {}
        total_entries: int | None = None

        for line in output.splitlines():
            match = cls._NEIGHBOR_ENTRY.match(line)
            if match:
                ipv6_address = match.group("ipv6")
                entry = Ipv6NeighborEntry(
                    mac_address=match.group("mac").lower(),
                    state=match.group("state"),
                    expire_seconds=int(match.group("expire")),
                    is_router=match.group("router") == "yes",
                    is_secure=match.group("secure") == "yes",
                    interface=match.group("interface"),
                )
                neighbors[ipv6_address] = entry
                continue

            total_match = cls._TOTAL_ENTRIES.match(line)
            if total_match:
                total_entries = int(total_match.group("count"))

        if not neighbors:
            msg = "No IPv6 neighbor entries found in output"
            raise ValueError(msg)

        result: ShowIpv6NeighborsResult = cast(
            ShowIpv6NeighborsResult, {"ipv6_neighbors": neighbors}
        )
        if total_entries is not None:
            result["total_entries"] = total_entries
        return result
