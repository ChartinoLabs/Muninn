"""Parser for 'show ipv6 neighbors' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class Ipv6NeighborEntry(TypedDict):
    """Schema for a single IPv6 neighbor entry on a specific interface."""

    age: NotRequired[int]
    link_layer_address: NotRequired[str]
    state: str


class ShowIpv6NeighborsResult(TypedDict):
    """Schema for 'show ipv6 neighbors' parsed output.

    Keyed by IPv6 address, then by canonical interface name.
    """

    neighbors: dict[str, dict[str, Ipv6NeighborEntry]]


_MISSING_VALUE = "-"


@register(OS.CISCO_IOS, "show ipv6 neighbors")
class ShowIpv6NeighborsParser(BaseParser[ShowIpv6NeighborsResult]):
    """Parser for 'show ipv6 neighbors' command on IOS.

    Parses IPv6 neighbor discovery cache entries.
    """

    _HEADER_PATTERN = re.compile(r"^IPv6\s+Address\s+Age\s+Link-layer\s+Addr", re.I)

    # Each entry line:
    # 2402:1234:106:100:793A:F08D:5B3A:EF89      33 54e1.addb.200f  STALE Vl6
    # FE80::9277:EEFF:FE9B:4E00                   - -               REACH Di0
    _ENTRY_PATTERN = re.compile(
        r"^(?P<ipv6_address>\S+)\s+"
        r"(?P<age>\d+|-)\s+"
        r"(?P<link_layer>\S+)\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<interface>\S+)$"
    )

    @classmethod
    def _is_skippable_line(cls, line: str) -> bool:
        """Return True if the line is blank or a header."""
        return not line or cls._HEADER_PATTERN.match(line) is not None

    @classmethod
    def _build_entry(cls, match: re.Match[str]) -> Ipv6NeighborEntry:
        """Build a neighbor entry from a regex match."""
        entry: Ipv6NeighborEntry = {"state": match.group("state")}

        age_raw = match.group("age")
        if age_raw != _MISSING_VALUE:
            entry["age"] = int(age_raw)

        link_layer = match.group("link_layer")
        if link_layer != _MISSING_VALUE:
            entry["link_layer_address"] = link_layer

        return entry

    @classmethod
    def parse(cls, output: str) -> ShowIpv6NeighborsResult:
        """Parse 'show ipv6 neighbors' output on IOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IPv6 neighbors keyed by IPv6 address, then interface.

        Raises:
            ValueError: If no neighbor entries found in output.
        """
        neighbors: dict[str, dict[str, Ipv6NeighborEntry]] = {}

        for line in output.splitlines():
            stripped = line.strip()

            if cls._is_skippable_line(stripped):
                continue

            match = cls._ENTRY_PATTERN.match(stripped)
            if not match:
                continue

            ipv6_address = match.group("ipv6_address")
            interface = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_IOS
            )
            entry = cls._build_entry(match)

            if ipv6_address not in neighbors:
                neighbors[ipv6_address] = {}
            neighbors[ipv6_address][interface] = entry

        if not neighbors:
            msg = "No IPv6 neighbor entries found in output"
            raise ValueError(msg)

        return {"neighbors": neighbors}
