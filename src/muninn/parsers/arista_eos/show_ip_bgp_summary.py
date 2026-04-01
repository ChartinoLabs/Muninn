"""Parser for 'show ip bgp summary' command on Arista EOS.

Arista EOS ``show ip bgp summary`` displays the BGP router identifier,
local AS number, VRF name, and a neighbor table with per-peer statistics
including messages received/sent, state or prefix count, and uptime.
"""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the summary table."""

    bgp_version: int
    remote_as: int
    msg_rcvd: int
    msg_sent: int
    in_queue: int
    out_queue: int
    up_down: str
    state_pfxrcd: str


class ShowIpBgpSummaryResult(TypedDict):
    """Schema for 'show ip bgp summary' parsed output on Arista EOS."""

    router_id: str
    local_as: int
    vrf: NotRequired[str]
    neighbors: dict[str, NeighborEntry]


_ROUTER_ID_RE = re.compile(
    r"^BGP router identifier (?P<router_id>\S+),\s*"
    r"local AS number (?P<local_as>\d+)"
)

_VRF_RE = re.compile(r"^VRF name:\s*(?P<vrf>\S+)", re.I)

_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+V\s+AS\s+MsgRcvd")

_NEIGHBOR_LINE_RE = re.compile(
    r"^(?P<neighbor>\S+)\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<remote_as>\d+)\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<in_q>\d+)\s+"
    r"(?P<out_q>\d+)\s+"
    r"(?P<up_down>\S+)\s+"
    r"(?P<state_pfxrcd>\S+.*?)\s*$"
)


def _parse_neighbor_line(m: re.Match[str]) -> NeighborEntry:
    """Build a NeighborEntry from a regex match on a neighbor table line."""
    return NeighborEntry(
        bgp_version=int(m.group("version")),
        remote_as=int(m.group("remote_as")),
        msg_rcvd=int(m.group("msg_rcvd")),
        msg_sent=int(m.group("msg_sent")),
        in_queue=int(m.group("in_q")),
        out_queue=int(m.group("out_q")),
        up_down=m.group("up_down"),
        state_pfxrcd=m.group("state_pfxrcd").strip(),
    )


def _parse_neighbors(lines: list[str]) -> dict[str, NeighborEntry]:
    """Parse neighbor entries from lines following the neighbor table header."""
    neighbors: dict[str, NeighborEntry] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if m := _NEIGHBOR_LINE_RE.match(stripped):
            neighbors[m.group("neighbor")] = _parse_neighbor_line(m)
    return neighbors


class _HeaderFields:
    """Container for fields extracted from the BGP summary header."""

    __slots__ = ("local_as", "neighbor_start", "router_id", "vrf")

    def __init__(self) -> None:
        self.router_id: str | None = None
        self.local_as: int | None = None
        self.vrf: str | None = None
        self.neighbor_start: int | None = None


def _extract_header(lines: list[str]) -> _HeaderFields:
    """Scan output lines for router-id, local-AS, VRF, and neighbor offset."""
    fields = _HeaderFields()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if m := _ROUTER_ID_RE.match(stripped):
            fields.router_id = m.group("router_id")
            fields.local_as = int(m.group("local_as"))
        elif m := _VRF_RE.match(stripped):
            fields.vrf = m.group("vrf")
        elif _NEIGHBOR_HEADER_RE.match(stripped):
            fields.neighbor_start = idx + 1
    return fields


@register(OS.ARISTA_EOS, "show ip bgp summary")
class ShowIpBgpSummaryParser(BaseParser["ShowIpBgpSummaryResult"]):
    """Parser for 'show ip bgp summary' on Arista EOS.

    Parses BGP process header information and the neighbor summary table.
    Output is keyed by neighbor IP address in a dict-of-dicts structure.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpSummaryResult:
        """Parse 'show ip bgp summary' output on Arista EOS.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP summary information.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        all_lines = output.splitlines()
        hdr = _extract_header(all_lines)

        if hdr.router_id is None or hdr.local_as is None:
            msg = "Missing BGP router identifier or local AS number"
            raise ValueError(msg)

        if hdr.neighbor_start is not None:
            neighbor_lines = all_lines[hdr.neighbor_start :]
        else:
            neighbor_lines = []

        result: dict[str, object] = {
            "router_id": hdr.router_id,
            "local_as": hdr.local_as,
            "neighbors": _parse_neighbors(neighbor_lines),
        }

        if hdr.vrf is not None:
            result["vrf"] = hdr.vrf

        return cast(ShowIpBgpSummaryResult, result)
