"""Parser for 'show dmvpn' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register


class DmvpnPeerEntry(TypedDict):
    """Schema for a single DMVPN NHRP peer entry."""

    peer_nbma_address: str
    peer_tunnel_address: str
    state: str
    uptime: str
    attribute: str
    entry_count: int


class DmvpnInterfaceEntry(TypedDict):
    """Schema for a DMVPN tunnel interface."""

    type: str
    nhrp_peer_count: int
    peers: dict[str, DmvpnPeerEntry]
    address_family: NotRequired[str]


class ShowDmvpnResult(TypedDict):
    """Schema for 'show dmvpn' parsed output."""

    interfaces: dict[str, DmvpnInterfaceEntry]


# Interface section header: "Interface: Tunnel100, IPv4 NHRP Details"
_INTERFACE_PATTERN = re.compile(
    r"^Interface:\s*(?P<interface>\S+),\s*(?P<af>\S+)\s+NHRP\s+Details"
)

# Type line: "Type:Spoke, NHRP Peers:2,"
_TYPE_PATTERN = re.compile(
    r"^Type:\s*(?P<type>\S+),\s*NHRP\s+Peers:\s*(?P<peer_count>\d+)"
)

# Full peer row with entry count, NBMA, tunnel addr, state, uptime, attrb
_PEER_ROW_PATTERN = re.compile(
    r"^\s*(?P<ent>\d+)\s+"
    r"(?P<nbma>\S+)\s+"
    rf"(?P<tunnel>{IPV4_ADDRESS})\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<uptime>\S+)\s+"
    r"(?P<attrb>\S+)\s*$"
)

# Continuation row (no entry count, starts with tunnel IP after stripping)
_CONTINUATION_PATTERN = re.compile(
    rf"^(?P<tunnel>{IPV4_ADDRESS})\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<uptime>\S+)\s+"
    r"(?P<attrb>\S+)\s*$"
)

# NBMA-only line (long address like IPv6 that wraps to next line)
_NBMA_ONLY_PATTERN = re.compile(r"^\s*(?P<ent>\d+)\s+(?P<nbma>\S+)\s*$")

# Separator and header lines to skip
_SKIP_PATTERN = re.compile(r"^[-=]+$|^#\s*Ent|^Ent\s+Peer|^Legend:|^\s+[A-Z#]")


def _is_skip_line(line: str) -> bool:
    """Return True for legend, header, separator, and decoration lines."""
    if not line:
        return True
    if line.startswith(("Legend:", "=", "-")):
        return True
    if _SKIP_PATTERN.match(line):
        return True
    return False


def _build_peer_key(entry_number: int) -> str:
    """Build a stable key for a peer entry."""
    return str(entry_number)


@register(OS.CISCO_IOSXE, "show dmvpn")
class ShowDmvpnParser(BaseParser[ShowDmvpnResult]):
    """Parser for 'show dmvpn' command.

    Example output:
        Interface: Tunnel100, IPv4 NHRP Details
        Type:Spoke, NHRP Peers:2,

         # Ent  Peer NBMA Addr Peer Tunnel Add State  UpDn Tm Attrb
         ----- --------------- --------------- ----- -------- -----
             1 10.200.0.3           10.253.0.1    UP 03:19:46     S
    """

    tags: ClassVar[frozenset[str]] = frozenset({"vpn"})

    @classmethod
    def parse(cls, output: str) -> ShowDmvpnResult:
        """Parse 'show dmvpn' output.

        Args:
            output: Raw CLI output from 'show dmvpn' command.

        Returns:
            Parsed DMVPN data keyed by tunnel interface.

        Raises:
            ValueError: If no DMVPN interfaces found in output.
        """
        interfaces: dict[str, DmvpnInterfaceEntry] = {}
        lines = output.splitlines()
        idx = 0
        while idx < len(lines):
            line = lines[idx].strip()
            intf_match = _INTERFACE_PATTERN.match(line)
            if intf_match:
                idx = _parse_interface_section(lines, idx, intf_match, interfaces)
            else:
                idx += 1

        if not interfaces:
            msg = "No DMVPN interfaces found in output"
            raise ValueError(msg)

        return ShowDmvpnResult(interfaces=interfaces)


def _parse_interface_section(
    lines: list[str],
    idx: int,
    intf_match: re.Match[str],
    interfaces: dict[str, DmvpnInterfaceEntry],
) -> int:
    """Parse a single interface section. Returns the next line index."""
    interface_name = intf_match.group("interface")
    af = intf_match.group("af")
    idx += 1

    # Look for the Type line
    intf_type = "Unknown"
    peer_count = 0
    while idx < len(lines):
        stripped = lines[idx].strip()
        type_match = _TYPE_PATTERN.match(stripped)
        if type_match:
            intf_type = type_match.group("type")
            peer_count = int(type_match.group("peer_count"))
            idx += 1
            break
        if _INTERFACE_PATTERN.match(stripped):
            break
        idx += 1

    peers: dict[str, DmvpnPeerEntry] = {}
    pending_nbma: str | None = None
    pending_ent: int = 0
    peer_index = 1

    while idx < len(lines):
        stripped = lines[idx].strip()

        if _INTERFACE_PATTERN.match(stripped):
            break

        if _is_skip_line(stripped):
            idx += 1
            continue

        idx, pending_nbma, pending_ent, peer_index = _parse_peer_line(
            stripped,
            peers,
            pending_nbma,
            pending_ent,
            idx,
            peer_index,
        )

    entry = DmvpnInterfaceEntry(
        type=intf_type,
        nhrp_peer_count=peer_count,
        peers=peers,
    )
    if af != "IPv4":
        entry["address_family"] = af

    interfaces[interface_name] = entry
    return idx


def _parse_peer_line(
    line: str,
    peers: dict[str, DmvpnPeerEntry],
    pending_nbma: str | None,
    pending_ent: int,
    idx: int,
    peer_index: int,
) -> tuple[int, str | None, int, int]:
    """Parse a single peer data line.

    Returns (next_idx, pending_nbma, pending_ent, next_peer_index).
    """
    # Full peer row
    peer_match = _PEER_ROW_PATTERN.match(line)
    if peer_match:
        _add_peer(peers, peer_match, peer_index)
        nbma = peer_match.group("nbma")
        ent = int(peer_match.group("ent"))
        return idx + 1, nbma, ent, peer_index + 1

    # Continuation row (additional tunnel for same NBMA, or tunnel after wrapped NBMA)
    cont_match = _CONTINUATION_PATTERN.match(line)
    if cont_match:
        nbma = pending_nbma or "UNKNOWN"
        ent = pending_ent or 1
        _add_continuation_peer(peers, cont_match, nbma, ent, peer_index)
        return idx + 1, pending_nbma, pending_ent, peer_index + 1

    # NBMA-only line (long address wraps)
    nbma_match = _NBMA_ONLY_PATTERN.match(line)
    if nbma_match:
        return (
            idx + 1,
            nbma_match.group("nbma"),
            int(nbma_match.group("ent")),
            peer_index,
        )

    return idx + 1, None, 0, peer_index


def _add_peer(
    peers: dict[str, DmvpnPeerEntry],
    match: re.Match[str],
    peer_index: int,
) -> None:
    """Add a peer entry from a full row match."""
    nbma = match.group("nbma")
    key = _build_peer_key(peer_index)
    peers[key] = DmvpnPeerEntry(
        peer_nbma_address=nbma,
        peer_tunnel_address=match.group("tunnel"),
        state=match.group("state"),
        uptime=match.group("uptime"),
        attribute=match.group("attrb"),
        entry_count=int(match.group("ent")),
    )


def _add_continuation_peer(
    peers: dict[str, DmvpnPeerEntry],
    match: re.Match[str],
    nbma: str,
    ent: int,
    peer_index: int,
) -> None:
    """Add a peer entry from a continuation line."""
    key = _build_peer_key(peer_index)
    peers[key] = DmvpnPeerEntry(
        peer_nbma_address=nbma,
        peer_tunnel_address=match.group("tunnel"),
        state=match.group("state"),
        uptime=match.group("uptime"),
        attribute=match.group("attrb"),
        entry_count=ent,
    )
