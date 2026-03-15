"""Parser for 'show bgp sessions' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# --- State abbreviation mapping ---

_STATE_MAP: dict[str, str] = {
    "I": "idle",
    "A": "active",
    "O": "open",
    "E": "established",
    "C": "closing",
    "S": "shutdown",
}


class NeighborEntry(TypedDict):
    """Schema for a single BGP session neighbor entry."""

    remote_as: int
    flaps: int
    last_flap: str
    last_read: str
    last_write: str
    state: str
    local_port: int
    remote_port: int
    notifications_sent: int
    notifications_received: int


class VrfEntry(TypedDict):
    """Schema for a single VRF in BGP sessions."""

    local_as: int
    peers: int
    established_peers: int
    router_id: str
    neighbors: NotRequired[dict[str, NeighborEntry]]


class ShowBgpSessionsResult(TypedDict):
    """Schema for 'show bgp sessions' parsed output on NX-OS."""

    total_peers: int
    total_established_peers: int
    local_as: int
    vrfs: dict[str, VrfEntry]


# --- Compiled regex patterns ---

_TOTAL_PEERS_RE = re.compile(
    r"^Total peers\s+(?P<total>\d+),\s*established peers\s+(?P<established>\d+)$"
)

_LOCAL_ASN_RE = re.compile(r"^ASN\s+(?P<asn>\d+)$")

_VRF_HEADER_RE = re.compile(r"^VRF\s+(?P<vrf>\S+),\s*local ASN\s+(?P<asn>\d+)$")

_VRF_PEERS_RE = re.compile(
    r"^peers\s+(?P<peers>\d+),\s*established peers\s+(?P<established>\d+),"
    r"\s*local router-id\s+(?P<rid>\S+)$"
)

_NEIGHBOR_HEADER_RE = re.compile(r"^\s*Neighbor\s+ASN\s+Flaps")

# Single-line neighbor: neighbor IP/IPv6, ASN, flaps, times, state, ports, notifs
_NEIGHBOR_SINGLE_RE = re.compile(
    r"^(?P<neighbor>\S+)\s+"
    r"(?P<asn>\d+)\s+"
    r"(?P<flaps>\d+)\s+"
    r"(?P<last_flap>\S+)\s*"
    r"\|\s*(?P<last_read>\S+)\s*"
    r"\|\s*(?P<last_write>\S+)\s+"
    r"(?P<state>[IAOECSDR])\s+"
    r"(?P<lport>\d+)/(?P<rport>\d+)\s+"
    r"(?P<nsent>\d+)/(?P<nrecv>\d+)\s*$"
)

# Wrapped first line: long neighbor address only (IPv6 link-local with interface)
_WRAP_FIRST_NEIGHBOR_RE = re.compile(r"^(?P<neighbor>\S+)\s*$")

# Wrapped continuation: indented, starts with ASN
_WRAP_CONT_RE = re.compile(
    r"^\s+(?P<asn>\d+)\s+"
    r"(?P<flaps>\d+)\s+"
    r"(?P<last_flap>\S+)\s*"
    r"\|\s*(?P<last_read>\S+)\s*"
    r"\|\s*(?P<last_write>\S+)\s+"
    r"(?P<state>[IAOECSDR])\s+"
    r"(?P<lport>\d+)/(?P<rport>\d+)\s+"
    r"(?P<nsent>\d+)/(?P<nrecv>\d+)\s*$"
)

# Wrapped first line: neighbor + ASN only (large ASN wraps)
_WRAP_FIRST_WITH_ASN_RE = re.compile(r"^(?P<neighbor>\S+)\s+(?P<asn>\d+)\s*$")

# Wrapped continuation for large ASN: indented, starts with flaps
_WRAP_CONT_ASN_RE = re.compile(
    r"^\s+(?P<flaps>\d+)\s+"
    r"(?P<last_flap>\S+)\s*"
    r"\|\s*(?P<last_read>\S+)\s*"
    r"\|\s*(?P<last_write>\S+)\s+"
    r"(?P<state>[IAOECSDR])\s+"
    r"(?P<lport>\d+)/(?P<rport>\d+)\s+"
    r"(?P<nsent>\d+)/(?P<nrecv>\d+)\s*$"
)


def _build_neighbor_entry(
    asn: str,
    flaps: str,
    last_flap: str,
    last_read: str,
    last_write: str,
    state: str,
    lport: str,
    rport: str,
    nsent: str,
    nrecv: str,
) -> NeighborEntry:
    """Build a NeighborEntry from parsed string fields."""
    return {
        "remote_as": int(asn),
        "flaps": int(flaps),
        "last_flap": last_flap,
        "last_read": last_read,
        "last_write": last_write,
        "state": _STATE_MAP.get(state, state.lower()),
        "local_port": int(lport),
        "remote_port": int(rport),
        "notifications_sent": int(nsent),
        "notifications_received": int(nrecv),
    }


def _parse_global_header(
    stripped: str,
    result: dict[str, int],
) -> bool:
    """Parse global header lines (total peers, ASN).

    Returns True if the line was consumed.
    """
    m = _TOTAL_PEERS_RE.match(stripped)
    if m:
        result["total_peers"] = int(m.group("total"))
        result["total_established_peers"] = int(m.group("established"))
        return True

    m = _LOCAL_ASN_RE.match(stripped)
    if m:
        result["local_as"] = int(m.group("asn"))
        return True

    return False


def _try_parse_single_neighbor(
    stripped: str,
    neighbors: dict[str, NeighborEntry],
) -> bool:
    """Try to parse a single-line neighbor entry.

    Returns True if the line was consumed.
    """
    m = _NEIGHBOR_SINGLE_RE.match(stripped)
    if m:
        neighbors[m.group("neighbor")] = _build_neighbor_entry(
            asn=m.group("asn"),
            flaps=m.group("flaps"),
            last_flap=m.group("last_flap"),
            last_read=m.group("last_read"),
            last_write=m.group("last_write"),
            state=m.group("state"),
            lport=m.group("lport"),
            rport=m.group("rport"),
            nsent=m.group("nsent"),
            nrecv=m.group("nrecv"),
        )
        return True
    return False


@register(OS.CISCO_NXOS, "show bgp sessions")
class ShowBgpSessionsParser(BaseParser["ShowBgpSessionsResult"]):
    """Parser for 'show bgp sessions' command on NX-OS.

    Example output:
        Total peers 3, established peers 2
        ASN 333
        VRF default, local ASN 333
        peers 3, established peers 2, local router-id 10.106.0.6
    """

    @classmethod
    def parse(cls, output: str) -> ShowBgpSessionsResult:
        """Parse 'show bgp sessions' output.

        Args:
            output: Raw CLI output from 'show bgp sessions' command.

        Returns:
            Parsed data with VRF and neighbor session information.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        global_info: dict[str, int] = {}
        vrfs: dict[str, VrfEntry] = {}
        current_vrf: str | None = None
        current_vrf_entry: VrfEntry | None = None
        in_neighbor_table = False
        pending_wrap: dict[str, str] | None = None

        for line in lines:
            stripped = line.strip()

            if _parse_global_header(stripped, global_info):
                continue

            result = _parse_vrf_line(
                stripped,
                line,
                vrfs,
                current_vrf,
                current_vrf_entry,
                in_neighbor_table,
                pending_wrap,
            )
            current_vrf, current_vrf_entry, in_neighbor_table, pending_wrap = result

        _save_vrf_entry(vrfs, current_vrf, current_vrf_entry)

        missing = [
            f
            for f in ("total_peers", "total_established_peers", "local_as")
            if f not in global_info
        ]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        return {
            "total_peers": global_info["total_peers"],
            "total_established_peers": global_info["total_established_peers"],
            "local_as": global_info["local_as"],
            "vrfs": vrfs,
        }


def _save_vrf_entry(
    vrfs: dict[str, VrfEntry],
    vrf_name: str | None,
    vrf_entry: VrfEntry | None,
) -> None:
    """Save a VRF entry into the result."""
    if vrf_name is not None and vrf_entry is not None:
        vrfs[vrf_name] = vrf_entry


def _parse_vrf_line(
    stripped: str,
    line: str,
    vrfs: dict[str, VrfEntry],
    current_vrf: str | None,
    current_vrf_entry: VrfEntry | None,
    in_neighbor_table: bool,
    pending_wrap: dict[str, str] | None,
) -> tuple[str | None, VrfEntry | None, bool, dict[str, str] | None]:
    """Parse a single line within VRF context.

    Returns updated (current_vrf, current_vrf_entry, in_neighbor_table,
    pending_wrap).
    """
    # New VRF section
    m = _VRF_HEADER_RE.match(stripped)
    if m:
        _save_vrf_entry(vrfs, current_vrf, current_vrf_entry)
        vrf_name = m.group("vrf")
        vrf_entry: VrfEntry = {
            "local_as": int(m.group("asn")),
            "peers": 0,
            "established_peers": 0,
            "router_id": "",
        }
        return vrf_name, vrf_entry, False, None

    if current_vrf_entry is None:
        return current_vrf, current_vrf_entry, in_neighbor_table, pending_wrap

    # VRF peers line
    m = _VRF_PEERS_RE.match(stripped)
    if m:
        current_vrf_entry["peers"] = int(m.group("peers"))
        current_vrf_entry["established_peers"] = int(m.group("established"))
        current_vrf_entry["router_id"] = m.group("rid")
        return current_vrf, current_vrf_entry, in_neighbor_table, pending_wrap

    # Neighbor header
    if _NEIGHBOR_HEADER_RE.match(stripped):
        return current_vrf, current_vrf_entry, True, None

    # State legend line — skip
    if stripped.startswith("State:"):
        return current_vrf, current_vrf_entry, in_neighbor_table, pending_wrap

    if not in_neighbor_table:
        return current_vrf, current_vrf_entry, in_neighbor_table, pending_wrap

    neighbors = current_vrf_entry.get("neighbors", {})
    new_pending = _parse_neighbor(stripped, line, neighbors, pending_wrap)
    if neighbors:
        current_vrf_entry["neighbors"] = neighbors

    return current_vrf, current_vrf_entry, in_neighbor_table, new_pending


def _parse_neighbor(
    stripped: str,
    line: str,
    neighbors: dict[str, NeighborEntry],
    pending_wrap: dict[str, str] | None,
) -> dict[str, str] | None:
    """Parse a neighbor line, handling wrapping.

    Returns updated pending_wrap state.
    """
    # Handle continuation of a wrapped line
    if pending_wrap is not None:
        return _handle_wrap_continuation(line, neighbors, pending_wrap)

    if not stripped:
        return None

    # Try single-line neighbor
    if _try_parse_single_neighbor(stripped, neighbors):
        return None

    # Try wrapped first line with neighbor + ASN
    m = _WRAP_FIRST_WITH_ASN_RE.match(stripped)
    if m:
        return {"neighbor": m.group("neighbor"), "asn": m.group("asn")}

    # Try wrapped first line with only neighbor address
    m = _WRAP_FIRST_NEIGHBOR_RE.match(stripped)
    if m:
        return {"neighbor": m.group("neighbor")}

    return None


def _handle_wrap_continuation(
    line: str,
    neighbors: dict[str, NeighborEntry],
    pending_wrap: dict[str, str],
) -> None:
    """Handle a continuation line for a wrapped neighbor entry."""
    if "asn" in pending_wrap:
        # Large ASN case: continuation has flaps onward
        m = _WRAP_CONT_ASN_RE.match(line)
        if m:
            neighbors[pending_wrap["neighbor"]] = _build_neighbor_entry(
                asn=pending_wrap["asn"],
                flaps=m.group("flaps"),
                last_flap=m.group("last_flap"),
                last_read=m.group("last_read"),
                last_write=m.group("last_write"),
                state=m.group("state"),
                lport=m.group("lport"),
                rport=m.group("rport"),
                nsent=m.group("nsent"),
                nrecv=m.group("nrecv"),
            )
    else:
        # Long neighbor case: continuation has ASN onward
        m = _WRAP_CONT_RE.match(line)
        if m:
            neighbors[pending_wrap["neighbor"]] = _build_neighbor_entry(
                asn=m.group("asn"),
                flaps=m.group("flaps"),
                last_flap=m.group("last_flap"),
                last_read=m.group("last_read"),
                last_write=m.group("last_write"),
                state=m.group("state"),
                lport=m.group("lport"),
                rport=m.group("rport"),
                nsent=m.group("nsent"),
                nrecv=m.group("nrecv"),
            )
    return None
