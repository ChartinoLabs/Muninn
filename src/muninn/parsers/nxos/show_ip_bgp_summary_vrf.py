"""Parser for 'show ip bgp summary vrf' command on NX-OS."""

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
    state_pfx_rcd: str


class AddressFamilyEntry(TypedDict):
    """Schema for a single address family within a VRF."""

    router_id: NotRequired[str]
    local_as: NotRequired[int]
    table_version: NotRequired[int]
    config_peers: NotRequired[int]
    capable_peers: NotRequired[int]
    neighbors: dict[str, NeighborEntry]


class VrfEntry(TypedDict):
    """Schema for a single VRF."""

    address_families: dict[str, AddressFamilyEntry]


class ShowIpBgpSummaryVrfResult(TypedDict):
    """Schema for 'show ip bgp summary vrf' parsed output on NX-OS."""

    vrfs: dict[str, VrfEntry]


# --- Compiled regex patterns ---

_VRF_AF_RE = re.compile(
    r"^BGP summary information for VRF (\S+),\s*address family (.+?)\s*$"
)

_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\d+)\s*$")

_TABLE_VERSION_RE = re.compile(
    r"^BGP table version is (\d+),\s*.+?\s+config peers (\d+),"
    r"\s*capable peers (\d+)\s*$"
)

# Standard neighbor header line
_NEIGHBOR_HEADER_RE = re.compile(
    r"^\s*Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent\s+"
    r"TblVer\s+InQ\s+OutQ\s+Up/Down\s+State/PfxRcd"
)

# Type breakdown header (L2VPN EVPN) - we skip these lines
_TYPE_HEADER_RE = re.compile(r"^\s*Neighbor\s+T\s+AS\s+PfxRcd")

# Single-line neighbor entry: all fields on one line
_NEIGHBOR_SINGLE_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<as>\d+)\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<tbl_ver>\d+)\s+"
    r"(?P<inq>\d+)\s+"
    r"(?P<outq>\d+)\s+"
    r"(?P<up_down>\S+)\s+"
    r"(?P<state_pfx>\S+)\s*$"
)

# Wrapped neighbor: first line has neighbor, version, AS only
_NEIGHBOR_WRAP_FIRST_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<as>\d+)\s*$"
)

# Wrapped neighbor continuation (indented, remaining fields)
_NEIGHBOR_WRAP_CONT_RE = re.compile(
    r"^\s+(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<tbl_ver>\d+)\s+"
    r"(?P<inq>\d+)\s+"
    r"(?P<outq>\d+)\s+"
    r"(?P<up_down>\S+)\s+"
    r"(?P<state_pfx>\S+)\s*$"
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
    """Build a NeighborEntry from parsed string fields."""
    return {
        "bgp_version": int(version),
        "remote_as": int(remote_as),
        "msg_rcvd": int(msg_rcvd),
        "msg_sent": int(msg_sent),
        "table_version": int(tbl_ver),
        "in_queue": int(inq),
        "out_queue": int(outq),
        "up_down": up_down,
        "state_pfx_rcd": state_pfx,
    }


def _entry_from_single(m: re.Match[str]) -> tuple[str, NeighborEntry]:
    """Build neighbor IP and entry from a single-line match."""
    return m.group("neighbor"), _build_neighbor_entry(
        version=m.group("version"),
        remote_as=m.group("as"),
        msg_rcvd=m.group("msg_rcvd"),
        msg_sent=m.group("msg_sent"),
        tbl_ver=m.group("tbl_ver"),
        inq=m.group("inq"),
        outq=m.group("outq"),
        up_down=m.group("up_down"),
        state_pfx=m.group("state_pfx"),
    )


def _entry_from_wrap(
    wrap: dict[str, str], m_cont: re.Match[str]
) -> tuple[str, NeighborEntry]:
    """Build neighbor IP and entry from a wrapped two-line match."""
    return wrap["neighbor"], _build_neighbor_entry(
        version=wrap["version"],
        remote_as=wrap["as"],
        msg_rcvd=m_cont.group("msg_rcvd"),
        msg_sent=m_cont.group("msg_sent"),
        tbl_ver=m_cont.group("tbl_ver"),
        inq=m_cont.group("inq"),
        outq=m_cont.group("outq"),
        up_down=m_cont.group("up_down"),
        state_pfx=m_cont.group("state_pfx"),
    )


def _parse_header_fields(
    stripped: str,
    af_entry: AddressFamilyEntry,
) -> bool:
    """Try to parse router-id or table-version from a line.

    Returns True if the line was consumed as a header field.
    """
    m_rid = _ROUTER_ID_RE.match(stripped)
    if m_rid:
        af_entry["router_id"] = m_rid.group(1)
        af_entry["local_as"] = int(m_rid.group(2))
        return True

    m_tv = _TABLE_VERSION_RE.match(stripped)
    if m_tv:
        af_entry["table_version"] = int(m_tv.group(1))
        af_entry["config_peers"] = int(m_tv.group(2))
        af_entry["capable_peers"] = int(m_tv.group(3))
        return True

    return False


def _save_af_entry(
    vrfs: dict[str, VrfEntry],
    vrf_name: str | None,
    af_name: str | None,
    af_entry: AddressFamilyEntry | None,
) -> None:
    """Save an address family entry into the VRF structure."""
    if vrf_name is None or af_name is None or af_entry is None:
        return

    if vrf_name not in vrfs:
        vrfs[vrf_name] = {"address_families": {}}
    vrfs[vrf_name]["address_families"][af_name] = af_entry


def _parse_neighbor_line(
    line: str,
    stripped: str,
    neighbors: dict[str, NeighborEntry],
    pending_wrap: dict[str, str] | None,
) -> dict[str, str] | None:
    """Parse a single neighbor line, returning updated pending_wrap.

    Handles single-line entries, wrapped first lines, and
    wrapped continuation lines.
    """
    # Handle wrapped continuation
    if pending_wrap is not None:
        m_cont = _NEIGHBOR_WRAP_CONT_RE.match(line)
        if m_cont:
            ip, entry = _entry_from_wrap(pending_wrap, m_cont)
            neighbors[ip] = entry
        return None

    if not stripped:
        return None

    # Single-line neighbor
    m_single = _NEIGHBOR_SINGLE_RE.match(stripped)
    if m_single:
        ip, entry = _entry_from_single(m_single)
        neighbors[ip] = entry
        return None

    # Wrapped first line (long AS number)
    m_wrap = _NEIGHBOR_WRAP_FIRST_RE.match(stripped)
    if m_wrap:
        return {
            "neighbor": m_wrap.group("neighbor"),
            "version": m_wrap.group("version"),
            "as": m_wrap.group("as"),
        }

    return None


@register(OS.CISCO_NXOS, "show ip bgp summary vrf")
class ShowIpBgpSummaryVrfParser(BaseParser["ShowIpBgpSummaryVrfResult"]):
    """Parser for 'show ip bgp summary vrf' on NX-OS.

    Parses VRF-scoped BGP summary information showing neighbor state
    and prefix counts across multiple VRFs and address families.
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpSummaryVrfResult:
        """Parse 'show ip bgp summary vrf' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BGP summary keyed by VRF, address family,
            then neighbor IP.
        """
        vrfs: dict[str, VrfEntry] = {}
        lines = output.splitlines()

        current_vrf: str | None = None
        current_af: str | None = None
        af_entry: AddressFamilyEntry | None = None
        in_neighbor_table = False
        in_type_table = False
        pending_wrap: dict[str, str] | None = None

        for line in lines:
            stripped = line.strip()

            # Detect VRF/AF section header
            m_vrf = _VRF_AF_RE.match(stripped)
            if m_vrf:
                _save_af_entry(vrfs, current_vrf, current_af, af_entry)
                current_vrf = m_vrf.group(1)
                current_af = m_vrf.group(2)
                af_entry = {"neighbors": {}}
                in_neighbor_table = False
                in_type_table = False
                pending_wrap = None
                continue

            if af_entry is None:
                continue

            if _parse_header_fields(stripped, af_entry):
                continue

            # Table headers toggle parsing mode
            if _TYPE_HEADER_RE.match(stripped):
                in_type_table = True
                in_neighbor_table = False
                pending_wrap = None
                continue
            if _NEIGHBOR_HEADER_RE.match(stripped):
                in_neighbor_table = True
                in_type_table = False
                pending_wrap = None
                continue

            if in_type_table or not in_neighbor_table:
                continue

            pending_wrap = _parse_neighbor_line(
                line, stripped, af_entry["neighbors"], pending_wrap
            )

        _save_af_entry(vrfs, current_vrf, current_af, af_entry)
        return {"vrfs": vrfs}
