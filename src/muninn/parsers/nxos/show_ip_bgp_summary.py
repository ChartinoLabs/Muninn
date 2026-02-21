"""Parser for 'show ip bgp summary' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor entry."""

    bgp_version: int
    remote_as: int
    msg_rcvd: int
    msg_sent: int
    table_version: int
    in_queue: int
    out_queue: int
    up_down: str
    state_pfx_received: str


class ShowIpBgpSummaryResult(TypedDict):
    """Schema for 'show ip bgp summary' parsed output on NX-OS."""

    router_id: str
    local_as: int
    vrf: str
    address_family: NotRequired[str]
    neighbors: dict[str, NeighborEntry]


# --- Regex patterns ---

_VRF_AF_RE = re.compile(
    r"^BGP summary information for VRF (\S+),\s*address family (.+?)\s*$"
)

_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\d+)\s*$")

# Neighbor data line with all fields on one line.
# State/PfxRcd can be a number or a string like "Idle" or
# "Idle (Admin)".
_NEIGHBOR_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<remote_as>\d+)\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<tbl_ver>\d+)\s+"
    r"(?P<inq>\d+)\s+"
    r"(?P<outq>\d+)\s+"
    r"(?P<up_down>\S+)\s+"
    r"(?P<state_pfx>.+?)\s*$"
)

# Partial neighbor line: IP, version, AS only (wraps to next line)
_NEIGHBOR_PARTIAL_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<remote_as>\d+)\s*$"
)

# Continuation line for a wrapped neighbor entry
_CONTINUATION_RE = re.compile(
    r"^\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<tbl_ver>\d+)\s+"
    r"(?P<inq>\d+)\s+"
    r"(?P<outq>\d+)\s+"
    r"(?P<up_down>\S+)\s+"
    r"(?P<state_pfx>.+?)\s*$"
)


def _build_neighbor_entry(
    version: str,
    remote_as: str,
    msg_rcvd: str,
    msg_sent: str,
    tbl_ver: str,
    inq: str,
    outq: str,
    up_down: str,
    state_pfx: str,
) -> NeighborEntry:
    """Build a NeighborEntry from raw string fields."""
    return {
        "bgp_version": int(version),
        "remote_as": int(remote_as),
        "msg_rcvd": int(msg_rcvd),
        "msg_sent": int(msg_sent),
        "table_version": int(tbl_ver),
        "in_queue": int(inq),
        "out_queue": int(outq),
        "up_down": up_down,
        "state_pfx_received": state_pfx,
    }


@register(OS.CISCO_NXOS, "show ip bgp summary")
class ShowIpBgpSummaryParser(BaseParser["ShowIpBgpSummaryResult"]):
    """Parser for 'show ip bgp summary' on NX-OS."""

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpSummaryResult:
        """Parse 'show ip bgp summary' output."""
        vrf = "default"
        address_family: str | None = None
        router_id = ""
        local_as = 0
        neighbors: dict[str, NeighborEntry] = {}

        # State for handling wrapped neighbor lines
        pending_neighbor: str | None = None
        pending_version: str = ""
        pending_remote_as: str = ""

        for line in output.splitlines():
            # VRF and address family header
            m = _VRF_AF_RE.match(line)
            if m:
                vrf = m.group(1)
                address_family = m.group(2)
                continue

            # Router ID and local AS
            m = _ROUTER_ID_RE.match(line)
            if m:
                router_id = m.group(1)
                local_as = int(m.group(2))
                continue

            # Handle continuation of a wrapped neighbor line
            if pending_neighbor is not None:
                m = _CONTINUATION_RE.match(line)
                if m:
                    entry = _build_neighbor_entry(
                        pending_version,
                        pending_remote_as,
                        m.group("msg_rcvd"),
                        m.group("msg_sent"),
                        m.group("tbl_ver"),
                        m.group("inq"),
                        m.group("outq"),
                        m.group("up_down"),
                        m.group("state_pfx"),
                    )
                    neighbors[pending_neighbor] = entry
                    pending_neighbor = None
                    continue
                # If continuation didn't match, clear pending state
                pending_neighbor = None

            # Full neighbor line
            m = _NEIGHBOR_RE.match(line)
            if m:
                entry = _build_neighbor_entry(
                    m.group("version"),
                    m.group("remote_as"),
                    m.group("msg_rcvd"),
                    m.group("msg_sent"),
                    m.group("tbl_ver"),
                    m.group("inq"),
                    m.group("outq"),
                    m.group("up_down"),
                    m.group("state_pfx"),
                )
                neighbors[m.group("neighbor")] = entry
                continue

            # Partial neighbor line (wraps to next line)
            m = _NEIGHBOR_PARTIAL_RE.match(line)
            if m:
                pending_neighbor = m.group("neighbor")
                pending_version = m.group("version")
                pending_remote_as = m.group("remote_as")
                continue

        result: ShowIpBgpSummaryResult = {
            "router_id": router_id,
            "local_as": local_as,
            "vrf": vrf,
            "neighbors": neighbors,
        }

        if address_family is not None:
            result["address_family"] = address_family

        return result
