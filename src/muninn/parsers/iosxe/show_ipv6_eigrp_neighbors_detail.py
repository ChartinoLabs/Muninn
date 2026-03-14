"""Parser for 'show ipv6 eigrp neighbors detail' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class Ipv6EigrpDetailNeighborEntry(TypedDict):
    """Schema for a single IPv6 EIGRP neighbor detail entry."""

    handle: int
    interface: str
    hold_time: int
    uptime: str
    srtt: int
    rto: int
    queue_count: int
    sequence_number: int
    software_version: str
    retransmit_count: int
    retry_count: int
    prefixes: NotRequired[int]
    topology_ids_from_peer: int
    topology_advert_to_peer: NotRequired[str]


class ShowIpv6EigrpNeighborsDetailResult(TypedDict):
    """Schema for 'show ipv6 eigrp neighbors detail' parsed output.

    Keyed by AS number (str) -> neighbor address -> entry.
    """

    neighbors: dict[str, dict[str, Ipv6EigrpDetailNeighborEntry]]


# --- Compiled regex patterns ---

_AS_HEADER_RE = re.compile(
    r"EIGRP-IPv6\s+(?:VR\(\S+\)\s+Address-Family\s+)?Neighbors\s+for\s+"
    r"(?:AS|process)\s*\(\s*(?P<as_num>\d+)\s*\)"
)

_ROW_RE = re.compile(
    r"^(?P<handle>\d+)\s+"
    r"(?P<address>\S+)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<hold>\d+)\s+"
    r"(?P<uptime>\S+)\s+"
    r"(?P<srtt>\d+)\s+"
    r"(?P<rto>\d+)\s+"
    r"(?P<q_count>\d+)\s+"
    r"(?P<seq_num>\d+)\s*$"
)

_VERSION_RE = re.compile(
    r"Version\s+(?P<version>\d+\.\d+/\d+\.\d+),\s+"
    r"Retrans:\s*(?P<retrans>\d+),\s+"
    r"Retries:\s*(?P<retries>\d+)"
    r"(?:,\s*Prefixes:\s*(?P<prefixes>\d+))?"
)

_TOPOLOGY_IDS_RE = re.compile(r"Topology-ids\s+from\s+peer\s+-\s+(?P<topo_ids>\d+)")

_TOPOLOGY_ADVERT_RE = re.compile(
    r"Topologies\s+advertised\s+to\s+peer:\s*(?P<topo_advert>\S+)"
)


def _is_header_or_noise(line: str) -> bool:
    """Check if a line is a header, separator, or other non-data line."""
    if not line:
        return True
    if line.startswith("H ") or line.startswith("EIGRP-"):
        return True
    if line.startswith("Max Nbrs"):
        return True
    return "(sec)" in line and "Cnt" in line


def _apply_detail_fields(entry: Ipv6EigrpDetailNeighborEntry, line: str) -> None:
    """Try to extract detail fields from a line into the entry."""
    m = _VERSION_RE.search(line)
    if m:
        entry["software_version"] = m.group("version")
        entry["retransmit_count"] = int(m.group("retrans"))
        entry["retry_count"] = int(m.group("retries"))
        if m.group("prefixes") is not None:
            entry["prefixes"] = int(m.group("prefixes"))
        return

    m = _TOPOLOGY_IDS_RE.search(line)
    if m:
        entry["topology_ids_from_peer"] = int(m.group("topo_ids"))
        return

    m = _TOPOLOGY_ADVERT_RE.search(line)
    if m:
        entry["topology_advert_to_peer"] = m.group("topo_advert")


def _build_entry(
    match: re.Match[str],
) -> Ipv6EigrpDetailNeighborEntry:
    """Build an initial entry from a row pattern match."""
    return Ipv6EigrpDetailNeighborEntry(
        handle=int(match.group("handle")),
        interface=canonical_interface_name(match.group("interface"), os=OS.CISCO_IOSXE),
        hold_time=int(match.group("hold")),
        uptime=match.group("uptime"),
        srtt=int(match.group("srtt")),
        rto=int(match.group("rto")),
        queue_count=int(match.group("q_count")),
        sequence_number=int(match.group("seq_num")),
        software_version="0.0/0.0",
        retransmit_count=0,
        retry_count=0,
        topology_ids_from_peer=0,
    )


@register(OS.CISCO_IOSXE, "show ipv6 eigrp neighbors detail")
class ShowIpv6EigrpNeighborsDetailParser(
    BaseParser[ShowIpv6EigrpNeighborsDetailResult],
):
    """Parser for 'show ipv6 eigrp neighbors detail' command.

    Example output::

        EIGRP-IPv6 Neighbors for AS(1)
        H   Address          Interface  Hold Uptime   SRTT  RTO Q Seq
                                        (sec)         (ms)      C Num
        0   FE80::1          Gi0/0        12 00:05:30  20   200 0  5
           Version 12.0/2.0, Retrans: 0, Retries: 0
           Topology-ids from peer - 0
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpv6EigrpNeighborsDetailResult:
        """Parse 'show ipv6 eigrp neighbors detail' output.

        Args:
            output: Raw CLI output from 'show ipv6 eigrp neighbors detail'.

        Returns:
            Parsed neighbor data keyed by AS number then neighbor address.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors = _parse_neighbors(output)

        if not neighbors:
            msg = "No EIGRP neighbors found in output"
            raise ValueError(msg)

        return ShowIpv6EigrpNeighborsDetailResult(neighbors=neighbors)


def _ensure_as_bucket(
    neighbors: dict[str, dict[str, Ipv6EigrpDetailNeighborEntry]],
    as_num: str,
) -> None:
    """Ensure an AS bucket exists in the neighbors dict."""
    if as_num not in neighbors:
        neighbors[as_num] = {}


def _parse_neighbors(
    output: str,
) -> dict[str, dict[str, Ipv6EigrpDetailNeighborEntry]]:
    """Parse all neighbor entries from the output."""
    neighbors: dict[str, dict[str, Ipv6EigrpDetailNeighborEntry]] = {}
    current_as: str | None = None
    current_entry: Ipv6EigrpDetailNeighborEntry | None = None

    for line in output.splitlines():
        stripped = line.strip()

        as_match = _AS_HEADER_RE.search(stripped)
        if as_match:
            current_as = as_match.group("as_num")
            _ensure_as_bucket(neighbors, current_as)
            continue

        if _is_header_or_noise(stripped):
            continue

        match = _ROW_RE.match(stripped)
        if match:
            if current_as is None:
                current_as = "0"
                _ensure_as_bucket(neighbors, current_as)
            current_entry = _build_entry(match)
            neighbors[current_as][match.group("address")] = current_entry
            continue

        if current_entry is not None:
            _apply_detail_fields(current_entry, stripped)

    return neighbors
