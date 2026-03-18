"""Parser for 'show ip eigrp neighbors' command on NX-OS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class EigrpNeighborEntry(TypedDict):
    """Schema for a single EIGRP neighbor entry."""

    peer_handle: int
    interface: str
    hold_time: int
    uptime: str
    srtt: int
    rto: int
    queue_count: int
    sequence_number: int


class EigrpProcessEntry(TypedDict):
    """Schema for a single EIGRP process with its neighbors."""

    neighbors: dict[str, EigrpNeighborEntry]


class ShowIpEigrpNeighborsResult(TypedDict):
    """Schema for 'show ip eigrp neighbors' parsed output on NX-OS."""

    processes: dict[str, EigrpProcessEntry]


# --- Compiled regex patterns ---

_PROCESS_HEADER_RE = re.compile(
    r"^IP-EIGRP\s+neighbors\s+for\s+process\s+(?P<as_num>\d+)"
    r"\s+VRF\s+(?P<vrf>\S+)$"
)

_NEIGHBOR_RE = re.compile(
    r"^(?P<peer_handle>\d+)\s+"
    r"(?P<address>\S+)\s+"
    r"(?P<interface>[A-Za-z]+[\d/\.]+)\s+"
    r"(?P<hold>\d+)\s+"
    r"(?P<uptime>\S+)\s+"
    r"(?P<srtt>\d+)\s+"
    r"(?P<rto>\d+)\s+"
    r"(?P<q_cnt>\d+)\s+"
    r"(?P<seq_num>\d+)$"
)


@register(OS.CISCO_NXOS, "show ip eigrp neighbors")
class ShowIpEigrpNeighborsParser(BaseParser["ShowIpEigrpNeighborsResult"]):
    """Parser for 'show ip eigrp neighbors' on NX-OS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.EIGRP,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpEigrpNeighborsResult:
        """Parse 'show ip eigrp neighbors' output."""
        processes: dict[str, EigrpProcessEntry] = {}
        current_as: str | None = None

        for line in output.splitlines():
            line = line.strip()

            m = _PROCESS_HEADER_RE.match(line)
            if m:
                current_as = m.group("as_num")
                if current_as not in processes:
                    processes[current_as] = {"neighbors": {}}
                continue

            m = _NEIGHBOR_RE.match(line)
            if m:
                if current_as is None:
                    msg = "Neighbor line found before process header"
                    raise ValueError(msg)

                address = m.group("address")
                entry: EigrpNeighborEntry = {
                    "peer_handle": int(m.group("peer_handle")),
                    "interface": canonical_interface_name(
                        m.group("interface"),
                        os=OS.CISCO_NXOS,
                    ),
                    "hold_time": int(m.group("hold")),
                    "uptime": m.group("uptime"),
                    "srtt": int(m.group("srtt")),
                    "rto": int(m.group("rto")),
                    "queue_count": int(m.group("q_cnt")),
                    "sequence_number": int(m.group("seq_num")),
                }
                processes[current_as]["neighbors"][address] = entry
                continue

        return {"processes": processes}
