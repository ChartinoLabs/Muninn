"""Parser for 'show ip eigrp neighbors detail' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class EigrpDetailNeighborEntry(TypedDict):
    """Schema for a single EIGRP neighbor detail entry."""

    handle: int
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


class ShowIpEigrpNeighborsDetailResult(TypedDict):
    """Schema for 'show ip eigrp neighbors detail' parsed output."""

    neighbors: dict[str, dict[str, EigrpDetailNeighborEntry]]


# --- Compiled regex patterns ---

_AS_HEADER_RE = re.compile(
    r"EIGRP-IPv4\s+(?:VR\(\S+\)\s+Address-Family\s+)?Neighbors\s+for\s+"
    r"(?:AS|process)\s*\(\s*(?P<as_num>\d+)\s*\)"
)

_ROW_RE = re.compile(
    r"^(?P<handle>\d+)\s+"
    r"(?P<address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
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
    return "(sec)" in line and "Cnt" in line


def _apply_detail_fields(entry: EigrpDetailNeighborEntry, line: str) -> None:
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


@register(OS.CISCO_IOSXE, "show ip eigrp neighbors detail")
class ShowIpEigrpNeighborsDetailParser(
    BaseParser[ShowIpEigrpNeighborsDetailResult],
):
    """Parser for 'show ip eigrp neighbors detail' command.

    Example output:
        EIGRP-IPv4 Neighbors for AS(215)
        H   Address         Interface      Hold Uptime   SRTT   RTO  Q  Seq
        1   81.211.127.255  Tu5              13 18:52:46   55   330  0  1042408760
           Version 25.0/2.0, Retrans: 1, Retries: 0, Prefixes: 952
           Topology-ids from peer - 0
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpEigrpNeighborsDetailResult:
        """Parse 'show ip eigrp neighbors detail' output.

        Args:
            output: Raw CLI output from 'show ip eigrp neighbors detail'.

        Returns:
            Parsed neighbor data keyed by interface then neighbor address.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors: dict[str, dict[str, EigrpDetailNeighborEntry]] = {}
        current_entry: EigrpDetailNeighborEntry | None = None

        for line in output.splitlines():
            stripped = line.strip()

            if _is_header_or_noise(stripped):
                continue

            match = _ROW_RE.match(stripped)
            if match:
                current_entry = _build_entry(match)
                interface = canonical_interface_name(
                    match.group("interface"), os=OS.CISCO_IOSXE
                )
                address = match.group("address")
                if interface not in neighbors:
                    neighbors[interface] = {}
                neighbors[interface][address] = current_entry
                continue

            if current_entry is not None:
                _apply_detail_fields(current_entry, stripped)

        if not neighbors:
            msg = "No EIGRP neighbors found in output"
            raise ValueError(msg)

        return ShowIpEigrpNeighborsDetailResult(neighbors=neighbors)


def _build_entry(match: re.Match[str]) -> EigrpDetailNeighborEntry:
    """Build an initial entry from a row pattern match."""
    return EigrpDetailNeighborEntry(
        handle=int(match.group("handle")),
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
