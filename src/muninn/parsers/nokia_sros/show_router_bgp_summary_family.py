"""Parser for 'show router bgp summary family' command on Nokia SR OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class BgpNeighborEntry(TypedDict):
    """Schema for a single BGP neighbor summary entry."""

    autonomous_system: str
    packets_received: int
    packets_sent: int
    in_queue: int
    out_queue: int
    up_down: str
    state: NotRequired[str]
    routes_received: NotRequired[int]
    routes_active: NotRequired[int]
    routes_sent: NotRequired[int]


# Top-level result is a dict keyed by neighbor address
ShowRouterBgpSummaryFamilyResult = dict[str, BgpNeighborEntry]


@register(OS.NOKIA_SROS, "show router bgp summary family")
class ShowRouterBgpSummaryFamilyParser(
    BaseParser[ShowRouterBgpSummaryFamilyResult],
):
    """Parser for 'show router bgp summary family' on Nokia SR OS.

    Parses the BGP neighbor summary table from the family-specific output,
    returning a dict keyed by peer IP address. Each value contains the
    neighbor's AS, packet counters, queue depths, uptime, and either
    a session state string or received/active/sent route counts.

    The output format places the neighbor address on one line and the
    remaining columns on the following line, indented.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.BGP,
            ParserTag.ROUTING,
        }
    )

    # Matches a neighbor IP address on its own line
    _NEIGHBOR_LINE = re.compile(r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s*$")

    # Matches the detail line beneath a neighbor address.
    # The last field is either a state string (e.g. "Connect", "Active")
    # or a routes triplet like "2/2/1" or "862440/627895/373".
    # Fields may have a trailing asterisk indicating truncation.
    _DETAIL_LINE = re.compile(
        r"^\s+"
        r"(?P<as>\d+\*?)\s+"
        r"(?P<pkt_rcvd>\d+\*?)\s+"
        r"(?P<pkt_sent>\d+\*?)\s+"
        r"(?P<in_q>\d+)\s+"
        r"(?P<out_q>\d+)\s+"
        r"(?P<up_down>\S+)\s+"
        r"(?P<state_or_routes>\S+)$"
    )

    # Matches a routes triplet like "2/2/1"
    _ROUTES_TRIPLET = re.compile(r"^(\d+)/(\d+)/(\d+)$")

    @classmethod
    def _strip_truncation_marker(cls, value: str) -> str:
        """Remove trailing asterisk used by SR OS to indicate truncation."""
        if value.endswith("*"):
            return value[:-1]
        return value

    @classmethod
    def parse(cls, output: str) -> ShowRouterBgpSummaryFamilyResult:
        """Parse 'show router bgp summary family' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by neighbor IP address, each value a BgpNeighborEntry.

        Raises:
            ValueError: If no BGP neighbor entries can be parsed.
        """
        result: dict[str, BgpNeighborEntry] = {}
        lines = output.splitlines()
        current_neighbor: str | None = None

        for line in lines:
            # Check for a neighbor address line
            neighbor_match = cls._NEIGHBOR_LINE.match(line)
            if neighbor_match:
                current_neighbor = neighbor_match.group("neighbor")
                continue

            # Check for a detail line following a neighbor
            if current_neighbor is not None:
                detail_match = cls._DETAIL_LINE.match(line)
                if detail_match:
                    as_raw = detail_match.group("as")
                    pkt_rcvd_raw = detail_match.group("pkt_rcvd")
                    pkt_sent_raw = detail_match.group("pkt_sent")
                    state_or_routes = detail_match.group("state_or_routes")

                    entry: BgpNeighborEntry = {
                        "autonomous_system": cls._strip_truncation_marker(as_raw),
                        "packets_received": int(
                            cls._strip_truncation_marker(pkt_rcvd_raw)
                        ),
                        "packets_sent": int(cls._strip_truncation_marker(pkt_sent_raw)),
                        "in_queue": int(detail_match.group("in_q")),
                        "out_queue": int(detail_match.group("out_q")),
                        "up_down": detail_match.group("up_down"),
                    }

                    # Determine if the last field is a routes triplet or a
                    # session state string
                    routes_match = cls._ROUTES_TRIPLET.match(state_or_routes)
                    if routes_match:
                        entry["routes_received"] = int(routes_match.group(1))
                        entry["routes_active"] = int(routes_match.group(2))
                        entry["routes_sent"] = int(routes_match.group(3))
                    else:
                        entry["state"] = state_or_routes

                    result[current_neighbor] = entry

                current_neighbor = None

        if not result:
            msg = "No BGP neighbor entries found in output"
            raise ValueError(msg)

        return cast(ShowRouterBgpSummaryFamilyResult, result)
