"""Parser for 'show ipv6 bgp summary' command on Arista EOS.

Arista EOS ``show ipv6 bgp summary`` displays the BGP router identifier,
local AS number, and a neighbor table with per-peer statistics including
remote AS, message counters, uptime, and either a prefix count (when the
peer is Established) or a session state string.

The output appears in three observed forms:

* a flat form with no VRF banner and a combined ``State/PfxRcd`` column;
* a single-VRF form with a ``BGP summary information for VRF <name>``
  banner and split ``State`` / ``PfxRcd`` / ``PfxAcc`` columns;
* a multi-VRF form repeating the VRF banner and table per VRF.

The parsed result is keyed by VRF name so the schema covers all forms.
"""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the summary table."""

    version: int
    remote_as: str
    msg_rcvd: int
    msg_sent: int
    in_queue: int
    out_queue: int
    up_down: str
    state: NotRequired[str]
    prefix_received: NotRequired[int]
    prefix_accepted: NotRequired[int]


class VrfEntry(TypedDict):
    """Schema for a single VRF section in the BGP summary."""

    router_id: str
    local_as: str
    neighbors: dict[str, NeighborEntry]


class ShowIpv6BgpSummaryResult(TypedDict):
    """Schema for 'show ipv6 bgp summary' parsed output on Arista EOS."""

    vrfs: dict[str, VrfEntry]


_VRF_BANNER_RE = re.compile(r"^BGP summary information for VRF\s+(?P<vrf>\S+)")

# Matches both "BGP router identifier ..." and "Router identifier ..." forms.
_ROUTER_ID_RE = re.compile(
    r"^(?:BGP\s+)?Router identifier\s+(?P<router_id>\S+),\s*"
    r"local AS number\s+(?P<local_as>\S+)",
    re.IGNORECASE,
)

# Combined-trailing-column header: "... Up/Down State/PfxRcd"
_NEIGHBOR_HEADER_COMBINED_RE = re.compile(
    r"^Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent\s+InQ\s+OutQ\s+Up/Down\s+State/PfxRcd\s*$"
)

# Split-trailing-column header: "... Up/Down State  PfxRcd  PfxAcc"
_NEIGHBOR_HEADER_SPLIT_RE = re.compile(
    r"^Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent\s+InQ\s+OutQ\s+Up/Down"
    r"\s+State\s+PfxRcd\s+PfxAcc\s*$"
)

_NEIGHBOR_STATUS_CODES_RE = re.compile(r"^Neighbor Status Codes:")

# Number of leading neighbor-row tokens shared by both header variants:
# address, V, AS, MsgRcvd, MsgSent, InQ, OutQ, Up/Down.
_NEIGHBOR_LEADING_TOKENS = 8


def _populate_combined_trailing(entry: NeighborEntry, trailing: list[str]) -> None:
    """Populate state/prefix fields when the table uses State/PfxRcd."""
    last = " ".join(trailing)
    if last.isdigit():
        entry["prefix_received"] = int(last)
    else:
        entry["state"] = last


def _populate_split_trailing(entry: NeighborEntry, trailing: list[str]) -> None:
    """Populate state/prefix fields when the table uses State PfxRcd PfxAcc."""
    entry["state"] = trailing[0]
    pfxrcd_index = 1
    pfxacc_index = 2
    if len(trailing) > pfxrcd_index and trailing[pfxrcd_index].isdigit():
        entry["prefix_received"] = int(trailing[pfxrcd_index])
    if len(trailing) > pfxacc_index and trailing[pfxacc_index].isdigit():
        entry["prefix_accepted"] = int(trailing[pfxacc_index])


def _parse_neighbor_row(
    line: str, *, split_columns: bool
) -> tuple[str, NeighborEntry] | None:
    """Parse a single neighbor data line into (address, entry) or None."""
    tokens = line.split()
    if len(tokens) <= _NEIGHBOR_LEADING_TOKENS:
        return None
    if not tokens[1].isdigit() or not tokens[3].isdigit():
        return None
    entry: NeighborEntry = {
        "version": int(tokens[1]),
        "remote_as": tokens[2],
        "msg_rcvd": int(tokens[3]),
        "msg_sent": int(tokens[4]),
        "in_queue": int(tokens[5]),
        "out_queue": int(tokens[6]),
        "up_down": tokens[7],
    }
    trailing = tokens[_NEIGHBOR_LEADING_TOKENS:]
    if split_columns:
        _populate_split_trailing(entry, trailing)
    else:
        _populate_combined_trailing(entry, trailing)
    return tokens[0], entry


def _detect_header_form(stripped: str) -> bool | None:
    """Return True for split-column header, False for combined, None otherwise."""
    if _NEIGHBOR_HEADER_SPLIT_RE.match(stripped):
        return True
    if _NEIGHBOR_HEADER_COMBINED_RE.match(stripped):
        return False
    return None


def _parse_vrf_section(lines: list[str]) -> VrfEntry:
    """Parse the lines belonging to a single VRF section."""
    router_id: str | None = None
    local_as: str | None = None
    neighbors: dict[str, NeighborEntry] = {}
    split_columns: bool | None = None

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or _NEIGHBOR_STATUS_CODES_RE.match(stripped):
            continue

        if split_columns is not None:
            parsed = _parse_neighbor_row(stripped, split_columns=split_columns)
            if parsed is not None:
                neighbors[parsed[0]] = parsed[1]
            continue

        if match := _ROUTER_ID_RE.match(stripped):
            router_id = match.group("router_id")
            local_as = match.group("local_as")
            continue

        header_form = _detect_header_form(stripped)
        if header_form is not None:
            split_columns = header_form

    if router_id is None or local_as is None:
        msg = "Missing BGP router identifier or local AS number"
        raise ValueError(msg)

    return {
        "router_id": router_id,
        "local_as": local_as,
        "neighbors": neighbors,
    }


def _split_vrf_sections(output: str) -> dict[str, list[str]]:
    """Split the raw output into a mapping of VRF name to lines.

    If no ``BGP summary information for VRF`` banner is present, the whole
    output is treated as a single ``default`` VRF section.
    """
    sections: dict[str, list[str]] = {}
    current_vrf: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        if match := _VRF_BANNER_RE.match(stripped):
            if current_vrf is not None:
                sections[current_vrf] = current_lines
            current_vrf = match.group("vrf")
            current_lines = []
            continue
        current_lines.append(line)

    if current_vrf is not None:
        sections[current_vrf] = current_lines
    else:
        sections["default"] = current_lines

    return sections


@register(OS.ARISTA_EOS, "show ipv6 bgp summary")
class ShowIpv6BgpSummaryParser(BaseParser[ShowIpv6BgpSummaryResult]):
    """Parser for 'show ipv6 bgp summary' command on Arista EOS.

    Parses the per-VRF BGP router identifier, local AS, and IPv6 neighbor
    table.  Supports the bannerless form, the single-VRF banner form, and
    multi-VRF output, as well as both combined ``State/PfxRcd`` and split
    ``State PfxRcd PfxAcc`` table column variants.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpv6BgpSummaryResult:
        """Parse 'show ipv6 bgp summary' output on Arista EOS.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP IPv6 summary information keyed by VRF name.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        vrf_sections = _split_vrf_sections(output)
        vrfs = {name: _parse_vrf_section(lines) for name, lines in vrf_sections.items()}
        return cast(ShowIpv6BgpSummaryResult, {"vrfs": vrfs})
