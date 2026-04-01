"""Parser for 'show ipv6 bgp summary' command on Arista EOS.

Arista EOS ``show ipv6 bgp summary`` displays the BGP router identifier,
local AS number, VRF name, and a neighbor table with per-peer statistics
including AS number, message counters, uptime, and state or prefix count.
"""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the summary table."""

    address_family_version: int
    remote_as: int
    msg_rcvd: int
    msg_sent: int
    in_queue: int
    out_queue: int
    up_down: str
    state_pfxrcd: str


class ShowIpv6BgpSummaryResult(TypedDict):
    """Schema for 'show ipv6 bgp summary' parsed output on Arista EOS."""

    router_id: str
    local_as: int
    vrf: str
    neighbors: dict[str, NeighborEntry]


_ROUTER_ID_RE = re.compile(
    r"^BGP router identifier\s+(?P<router_id>\S+),\s*"
    r"local AS number\s+(?P<local_as>\d+)"
)

_VRF_RE = re.compile(r"^VRF name:\s*(?P<vrf>\S+)")

_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+V\s+AS\s+MsgRcvd")

# Neighbor data line: IPv6 address followed by numeric fields and state.
_NEIGHBOR_RE = re.compile(
    r"^(?P<neighbor>\S+)\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<remote_as>\d+)\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<in_queue>\d+)\s+"
    r"(?P<out_queue>\d+)\s+"
    r"(?P<up_down>\S+)\s+"
    r"(?P<state_pfxrcd>\S+.*?)\s*$"
)


def _build_neighbor_entry(match: re.Match[str]) -> NeighborEntry:
    """Build a NeighborEntry from a regex match on a neighbor line."""
    return NeighborEntry(
        address_family_version=int(match.group("version")),
        remote_as=int(match.group("remote_as")),
        msg_rcvd=int(match.group("msg_rcvd")),
        msg_sent=int(match.group("msg_sent")),
        in_queue=int(match.group("in_queue")),
        out_queue=int(match.group("out_queue")),
        up_down=match.group("up_down"),
        state_pfxrcd=match.group("state_pfxrcd").strip(),
    )


def _parse_neighbors(lines: list[str]) -> dict[str, NeighborEntry]:
    """Parse neighbor entries from lines following the neighbor header."""
    neighbors: dict[str, NeighborEntry] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if match := _NEIGHBOR_RE.match(stripped):
            neighbors[match.group("neighbor")] = _build_neighbor_entry(match)
    return neighbors


@register(OS.ARISTA_EOS, "show ipv6 bgp summary")
class ShowIpv6BgpSummaryParser(BaseParser[ShowIpv6BgpSummaryResult]):
    """Parser for 'show ipv6 bgp summary' command on Arista EOS.

    Parses the BGP router identifier, local AS, VRF, and neighbor table
    from the command output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpv6BgpSummaryResult:
        """Parse 'show ipv6 bgp summary' output on Arista EOS.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP IPv6 summary information.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        router_id: str | None = None
        local_as: int | None = None
        vrf = "default"
        neighbor_lines: list[str] = []
        in_neighbor_table = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if in_neighbor_table:
                neighbor_lines.append(stripped)
                continue

            if match := _ROUTER_ID_RE.match(stripped):
                router_id = match.group("router_id")
                local_as = int(match.group("local_as"))
            elif match := _VRF_RE.match(stripped):
                vrf = match.group("vrf")
            elif _NEIGHBOR_HEADER_RE.match(stripped):
                in_neighbor_table = True

        if router_id is None or local_as is None:
            msg = "Missing BGP router identifier or local AS number"
            raise ValueError(msg)

        return cast(
            ShowIpv6BgpSummaryResult,
            {
                "router_id": router_id,
                "local_as": local_as,
                "vrf": vrf,
                "neighbors": _parse_neighbors(neighbor_lines),
            },
        )
