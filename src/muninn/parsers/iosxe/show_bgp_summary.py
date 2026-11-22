"""Parser for 'show bgp summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the summary table."""

    version: int
    remote_as: int
    msg_rcvd: int
    msg_sent: int
    table_version: int
    in_queue: int
    out_queue: int
    up_down: str
    state: NotRequired[str]
    prefixes_received: NotRequired[int]


class ShowBgpSummaryResult(TypedDict):
    """Schema for 'show bgp summary' parsed output."""

    router_id: str
    local_as: int
    neighbors: dict[str, NeighborEntry]


def _parse_local_as(raw: str) -> int:
    """Parse local AS number, handling asdot notation (e.g., '304.304')."""
    if "." in raw:
        high, low = raw.split(".", 1)
        return int(high) * 65536 + int(low)
    return int(raw)


def _is_noise_line(line: str) -> bool:
    """Return True if the line is a prompt, load, or time source line."""
    if not line:
        return True
    if line.endswith("#") or "#show " in line.lower():
        return True
    return line.startswith("Load for ") or line.startswith("Time source ")


def _parse_state_pfxrcd(value: str) -> tuple[str | None, int | None]:
    """Parse the State/PfxRcd field into state and prefix count.

    If the value is a plain integer, it represents prefixes received.
    Otherwise, it is a state string (e.g., 'Idle', 'Active', 'Connect').
    """
    try:
        return (None, int(value))
    except ValueError:
        return (value, None)


_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<neighbor>\S+)\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<remote_as>\S+)\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<tbl_ver>\d+)\s+"
    r"(?P<in_q>\d+)\s+"
    r"(?P<out_q>\d+)\s+"
    r"(?P<up_down>\S+)\s+"
    r"(?P<state_pfxrcd>\S+)\s*$"
)


_ROUTER_ID_PATTERN = re.compile(
    r"BGP\s+router\s+identifier\s+(?P<router_id>\S+),\s+"
    r"local\s+AS\s+number\s+(?P<local_as>\S+)"
)

_HEADER_PATTERN = re.compile(r"^\s*Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent")


def _build_neighbor_entry(
    match: re.Match[str],
) -> tuple[str, NeighborEntry]:
    """Build a NeighborEntry from a regex match on a neighbor row."""
    neighbor = match.group("neighbor")
    state, prefixes = _parse_state_pfxrcd(match.group("state_pfxrcd"))

    entry: NeighborEntry = {
        "version": int(match.group("version")),
        "remote_as": _parse_local_as(match.group("remote_as")),
        "msg_rcvd": int(match.group("msg_rcvd")),
        "msg_sent": int(match.group("msg_sent")),
        "table_version": int(match.group("tbl_ver")),
        "in_queue": int(match.group("in_q")),
        "out_queue": int(match.group("out_q")),
        "up_down": match.group("up_down"),
    }

    if state is not None:
        entry["state"] = state
    if prefixes is not None:
        entry["prefixes_received"] = prefixes

    return (neighbor, entry)


def _find_router_id(
    lines: list[str],
) -> tuple[str | None, int | None]:
    """Find the first BGP router identifier line and extract ID and AS."""
    for line in lines:
        stripped = line.strip()
        if _is_noise_line(stripped):
            continue
        id_match = _ROUTER_ID_PATTERN.search(stripped)
        if id_match:
            rid = id_match.group("router_id")
            las = _parse_local_as(id_match.group("local_as"))
            return (rid, las)
    return (None, None)


def _parse_neighbors(
    lines: list[str],
) -> dict[str, NeighborEntry]:
    """Parse neighbor rows from lines following the table header."""
    neighbors: dict[str, NeighborEntry] = {}
    in_table = False

    for line in lines:
        stripped = line.strip()
        if _is_noise_line(stripped):
            continue

        if _HEADER_PATTERN.match(stripped):
            in_table = True
            continue

        if not in_table:
            continue

        match = _NEIGHBOR_PATTERN.match(stripped)
        if match:
            key, entry = _build_neighbor_entry(match)
            neighbors[key] = entry

    return neighbors


@register(OS.CISCO_IOSXE, "show bgp summary")
class ShowBgpSummaryParser(BaseParser["ShowBgpSummaryResult"]):
    """Parser for 'show bgp summary' command.

    Example output::

        BGP router identifier 192.168.111.1, local AS number 100
        Neighbor   V    AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
        192.168.111.1  4  100    0    0     1   0   0 01:07:38 Idle
        10.5.17.1      4  150  220  217    60   0   0 03:08:19   15
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpSummaryResult:
        """Parse 'show bgp summary' output.

        Args:
            output: Raw CLI output from 'show bgp summary' command.

        Returns:
            Parsed data with neighbors keyed by neighbor address.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()

        router_id, local_as = _find_router_id(lines)
        if router_id is None or local_as is None:
            msg = "Could not find BGP router identifier in output"
            raise ValueError(msg)

        neighbors = _parse_neighbors(lines)
        if not neighbors:
            msg = "No BGP neighbors found in output"
            raise ValueError(msg)

        return ShowBgpSummaryResult(
            router_id=router_id,
            local_as=local_as,
            neighbors=neighbors,
        )
