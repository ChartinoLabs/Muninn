"""Parser for 'show bgp neighbors' command on Cisco FTD.

Cisco FTD ``show bgp neighbors`` displays detailed information about each BGP
neighbor including session state, timers, message counters, BFD/fall-over
status, and per-address-family prefix statistics.

The parser produces a result containing a ``bgp_operational`` boolean
indicating whether BGP is functioning (``False`` when the output contains
"% BGP cannot run"), and a ``neighbors`` dict keyed by neighbor IP address
with operational state information for each peer.
"""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

__all__ = ["ShowBgpNeighborsParser"]


class BgpNeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the detailed output."""

    remote_as: int
    vrf: str
    link_type: str
    bgp_version: int
    router_id: str
    bgp_state: str
    hold_time: int
    keepalive_interval: int
    connections_established: int
    connections_dropped: int
    bfd_configured: NotRequired[bool]
    fall_over_configured: NotRequired[bool]
    graceful_restart: NotRequired[str]


class ShowBgpNeighborsResult(TypedDict):
    """Top-level result for 'show bgp neighbors' on Cisco FTD."""

    bgp_operational: bool
    neighbors: dict[str, BgpNeighborEntry]


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_NEIGHBOR_HEADER_RE = re.compile(
    r"^BGP neighbor is (?P<ip>\S+),\s+vrf (?P<vrf>\S+),\s+"
    r"remote AS (?P<asn>\d+),\s+(?P<link_type>.+?)\s*$"
)

_BGP_VERSION_RE = re.compile(r"BGP version (\d+), remote router ID (\S+)")

_BGP_STATE_RE = re.compile(r"BGP state = (\w+)")

_HOLD_TIME_RE = re.compile(r"hold time is (\d+), keepalive interval is (\d+)")

_CONNECTIONS_RE = re.compile(r"Connections established (\d+); dropped (\d+)")

_BFD_CONFIGURED_RE = re.compile(r"BFD is configured", re.IGNORECASE)

_FALL_OVER_RE = re.compile(r"Fall over configured", re.IGNORECASE)

_GRACEFUL_RESTART_RE = re.compile(r"Graceful-Restart is (\S+)")


def _split_neighbor_blocks(output: str) -> list[tuple[str, str, int, str, list[str]]]:
    """Split raw output into neighbor blocks.

    Returns a list of tuples:
        (neighbor_ip, vrf, remote_as, link_type, body_lines)
    """
    blocks: list[tuple[str, str, int, str, list[str]]] = []
    current_ip: str | None = None
    current_vrf: str = ""
    current_as: int = 0
    current_link: str = ""
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _NEIGHBOR_HEADER_RE.match(line)
        if m:
            if current_ip is not None:
                blocks.append(
                    (
                        current_ip,
                        current_vrf,
                        current_as,
                        current_link,
                        current_lines,
                    )
                )
            current_ip = m.group("ip")
            current_vrf = m.group("vrf")
            current_as = int(m.group("asn"))
            current_link = m.group("link_type").strip()
            current_lines = []
        elif current_ip is not None:
            current_lines.append(line)

    if current_ip is not None:
        blocks.append(
            (
                current_ip,
                current_vrf,
                current_as,
                current_link,
                current_lines,
            )
        )

    return blocks


def _extract_version_and_id(stripped: str, fields: dict) -> bool:
    """Extract BGP version and router ID from a line."""
    if m := _BGP_VERSION_RE.search(stripped):
        fields["bgp_version"] = int(m.group(1))
        fields["router_id"] = m.group(2)
        return True
    return False


def _extract_state(stripped: str, fields: dict) -> bool:
    """Extract BGP session state from a line."""
    if m := _BGP_STATE_RE.search(stripped):
        fields["bgp_state"] = m.group(1)
        return True
    return False


def _extract_timers(stripped: str, fields: dict) -> bool:
    """Extract hold time and keepalive interval from a line."""
    if "hold time is" not in stripped or "Configured" in stripped:
        return False
    if m := _HOLD_TIME_RE.search(stripped):
        fields["hold_time"] = int(m.group(1))
        fields["keepalive_interval"] = int(m.group(2))
        return True
    return False


def _extract_connections(stripped: str, fields: dict) -> bool:
    """Extract connection counters from a line."""
    if m := _CONNECTIONS_RE.search(stripped):
        fields["connections_established"] = int(m.group(1))
        fields["connections_dropped"] = int(m.group(2))
        return True
    return False


def _extract_features(stripped: str, fields: dict) -> bool:
    """Extract BFD, fall-over, and graceful-restart status from a line."""
    if _BFD_CONFIGURED_RE.search(stripped):
        fields["bfd_configured"] = True
        return True
    if _FALL_OVER_RE.search(stripped):
        fields["fall_over_configured"] = True
        return True
    if m := _GRACEFUL_RESTART_RE.search(stripped):
        fields["graceful_restart"] = m.group(1)
        return True
    return False


_SESSION_EXTRACTORS = (
    _extract_version_and_id,
    _extract_state,
    _extract_timers,
    _extract_connections,
    _extract_features,
)


def _parse_session_fields(lines: list[str]) -> dict:
    """Extract session-level fields from the body lines of a neighbor block."""
    fields: dict = {}

    for line in lines:
        stripped = line.strip()
        for extractor in _SESSION_EXTRACTORS:
            if extractor(stripped, fields):
                break

    return fields


def _build_neighbor_entry(
    vrf: str,
    remote_as: int,
    link_type: str,
    lines: list[str],
) -> BgpNeighborEntry:
    """Build a BgpNeighborEntry from parsed header and body lines."""
    fields = _parse_session_fields(lines)

    result: BgpNeighborEntry = {
        "remote_as": remote_as,
        "vrf": vrf,
        "link_type": link_type,
        "bgp_version": fields.get("bgp_version", 0),
        "router_id": fields.get("router_id", ""),
        "bgp_state": fields.get("bgp_state", ""),
        "hold_time": fields.get("hold_time", 0),
        "keepalive_interval": fields.get("keepalive_interval", 0),
        "connections_established": fields.get("connections_established", 0),
        "connections_dropped": fields.get("connections_dropped", 0),
    }

    if fields.get("bfd_configured"):
        result["bfd_configured"] = True
    if fields.get("fall_over_configured"):
        result["fall_over_configured"] = True
    if "graceful_restart" in fields:
        result["graceful_restart"] = fields["graceful_restart"]

    return result


@register(OS.CISCO_FTD, "show bgp neighbors")
class ShowBgpNeighborsParser(BaseParser[ShowBgpNeighborsResult]):
    """Parser for 'show bgp neighbors' on Cisco FTD.

    Parses detailed BGP neighbor information including session state,
    timers, BFD/fall-over configuration, and connection statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP})

    @classmethod
    def parse(cls, output: str) -> ShowBgpNeighborsResult:
        """Parse 'show bgp neighbors' output on Cisco FTD.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Result with ``bgp_operational`` flag and ``neighbors`` dict.

        Raises:
            ValueError: If no neighbor blocks are found in the output.
        """
        bgp_operational = "% BGP cannot run" not in output

        blocks = _split_neighbor_blocks(output)
        if not blocks:
            msg = "No BGP neighbor data found in output"
            raise ValueError(msg)

        neighbors: dict[str, BgpNeighborEntry] = {}
        for ip, vrf, remote_as, link_type, lines in blocks:
            neighbors[ip] = _build_neighbor_entry(vrf, remote_as, link_type, lines)

        return ShowBgpNeighborsResult(
            bgp_operational=bgp_operational,
            neighbors=neighbors,
        )
