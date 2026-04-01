"""Parser for 'show bgp vrf all ipv4 unicast summary' on Cisco IOS-XR.

IOS-XR ``show bgp vrf all ipv4 unicast summary`` displays BGP summary
information for every VRF configured on the router.  Each VRF section
includes the router identifier, local AS number, process/speaker table,
and an optional neighbor table.

The parser produces a dict keyed by VRF name, with each entry containing
the router ID, local AS, and a nested dict of neighbors keyed by address.
"""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in a VRF summary table."""

    spk: int
    remote_as: str
    msg_rcvd: int
    msg_sent: int
    tbl_ver: int
    in_queue: int
    out_queue: int
    up_down: str
    state_pfxrcd: str


class VrfEntry(TypedDict):
    """Schema for a single VRF section."""

    router_id: str
    local_as: str
    neighbors: dict[str, NeighborEntry]


ShowBgpVrfAllIpv4UnicastSummaryResult = dict[str, VrfEntry]

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Timestamp line (e.g. "Tue Mar 21 09:08:19.039 EDT")
_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+", re.I
)

# VRF header: "VRF: PROD"
_VRF_HEADER_RE = re.compile(r"^VRF:\s*(\S+)")

# Router identifier and local AS
_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\S+)")

# Neighbor table header line
_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+Spk\s+AS\s+MsgRcvd")


def _is_noise_line(stripped: str) -> bool:
    """Return True if the line is noise (timestamp, separator, prompt)."""
    if not stripped:
        return True
    if _TIMESTAMP_RE.match(stripped):
        return True
    if SEPARATOR_DASH_RE.match(stripped):
        return True
    return stripped.endswith("#") or "#show " in stripped.lower()


def _parse_neighbor_line(
    line: str,
    neighbors: dict[str, NeighborEntry],
) -> None:
    """Parse a single neighbor data line and add to the neighbors dict."""
    tokens = line.split()
    min_tokens = 10
    if len(tokens) < min_tokens:
        return
    address = tokens[0]
    neighbors[address] = {
        "spk": int(tokens[1]),
        "remote_as": tokens[2],
        "msg_rcvd": int(tokens[3]),
        "msg_sent": int(tokens[4]),
        "tbl_ver": int(tokens[5]),
        "in_queue": int(tokens[6]),
        "out_queue": int(tokens[7]),
        "up_down": tokens[8],
        "state_pfxrcd": " ".join(tokens[9:]),
    }


def _parse_vrf_block(lines: list[str]) -> VrfEntry:
    """Parse lines belonging to a single VRF section.

    Raises:
        ValueError: If router identifier or local AS cannot be found.
    """
    router_id: str | None = None
    local_as: str | None = None
    neighbors: dict[str, NeighborEntry] = {}
    in_neighbor_table = False

    for raw_line in lines:
        stripped = raw_line.strip()
        if _is_noise_line(stripped):
            continue

        if _NEIGHBOR_HEADER_RE.match(stripped):
            in_neighbor_table = True
            continue

        if in_neighbor_table:
            _parse_neighbor_line(stripped, neighbors)
            continue

        m = _ROUTER_ID_RE.match(stripped)
        if m:
            router_id = m.group(1)
            local_as = m.group(2)

    if router_id is None or local_as is None:
        msg = "Missing BGP router identifier or local AS number in VRF block"
        raise ValueError(msg)

    return {
        "router_id": router_id,
        "local_as": local_as,
        "neighbors": neighbors,
    }


@register(OS.CISCO_IOSXR, "show bgp vrf all ipv4 unicast summary")
class ShowBgpVrfAllIpv4UnicastSummaryParser(
    BaseParser["ShowBgpVrfAllIpv4UnicastSummaryResult"],
):
    """Parser for 'show bgp vrf all ipv4 unicast summary' on Cisco IOS-XR.

    Parses per-VRF BGP summary information including router ID, local AS,
    and neighbor table entries.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.BGP, ParserTag.ROUTING, ParserTag.VRF}
    )

    @classmethod
    def parse(cls, output: str) -> ShowBgpVrfAllIpv4UnicastSummaryResult:
        """Parse 'show bgp vrf all ipv4 unicast summary' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by VRF name, each containing router_id, local_as,
            and a neighbors dict.

        Raises:
            ValueError: If no VRF sections are found or required fields
                are missing.
        """
        vrf_sections: list[tuple[str, list[str]]] = []
        current_vrf: str | None = None
        current_lines: list[str] = []

        for line in output.splitlines():
            stripped = line.strip()
            m = _VRF_HEADER_RE.match(stripped)
            if m:
                if current_vrf is not None:
                    vrf_sections.append((current_vrf, current_lines))
                current_vrf = m.group(1)
                current_lines = []
            else:
                current_lines.append(line)

        if current_vrf is not None:
            vrf_sections.append((current_vrf, current_lines))

        if not vrf_sections:
            msg = "No VRF sections found in output"
            raise ValueError(msg)

        result: ShowBgpVrfAllIpv4UnicastSummaryResult = {}
        for vrf_name, lines in vrf_sections:
            result[vrf_name] = _parse_vrf_block(lines)

        return result
