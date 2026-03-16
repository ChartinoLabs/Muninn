"""Parser for 'show ip mroute' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Multicast route entry header:
# (*, 239.0.0.1), 00:00:58/00:02:02, RP 172.16.2.1, flags: SJC
# (192.168.2.44, 239.0.0.5), 00:00:07/00:02:58, flags: FT
_ROUTE_HEADER_RE = re.compile(
    r"^\((?P<source>\*|[\d.]+),\s+(?P<group>[\d.]+)\),\s+"
    r"(?P<uptime>\S+)/(?P<expires>\S+)"
    r"(?:,\s+RP\s+(?P<rp>[\d.]+))?"
    r",\s+flags:\s+(?P<flags>\S+)\s*$"
)

# Incoming interface line:
# Incoming interface: FastEthernet0/1, RPF nbr 172.16.2.1
# Incoming interface: Vlan1, RPF nbr 0.0.0.0, Registering
# Incoming interface: Null, RPF nbr 0.0.0.0
_INCOMING_RE = re.compile(
    r"^\s+Incoming interface:\s+(?P<interface>\S+)"
    r",\s+RPF nbr\s+(?P<rpf_neighbor>[\d.]+)"
    r"(?:,\s+(?P<rpf_info>.+?))?\s*$"
)

# Outgoing interface entry:
# Vlan1, Forward/Sparse, 00:00:58/00:02:02
# FastEthernet0/1, Forward/Dense, 00:00:07/00:00:00
# ATM0/0, VCD 14, Forward/Sparse, 00:03:57/00:02:53
_OIF_RE = re.compile(
    r"^\s+(?P<interface>\S+)"
    r"(?:,\s+VCD\s+(?P<vcd>\d+))?"
    r",\s+(?P<state_mode>\S+/\S+)"
    r",\s+(?P<uptime>\S+)/(?P<expires>\S+)\s*$"
)

# Outgoing interface list: Null
_OIF_NULL_RE = re.compile(r"^\s+Outgoing interface list:\s*Null\s*$")

# Outgoing interface list:
_OIF_HEADER_RE = re.compile(r"^\s+Outgoing interface list:\s*$")


class OutgoingInterfaceEntry(TypedDict):
    """Schema for a single outgoing interface."""

    state_mode: str
    uptime: str
    expires: str
    vcd: NotRequired[int]


class SourceEntry(TypedDict):
    """Schema for a source entry within a multicast group."""

    uptime: str
    expires: str
    flags: str
    rpf_neighbor: str
    incoming_interface: NotRequired[str]
    rpf_info: NotRequired[str]
    rp: NotRequired[str]
    outgoing_interfaces: NotRequired[dict[str, OutgoingInterfaceEntry]]


class GroupEntry(TypedDict):
    """Schema for a multicast group."""

    sources: dict[str, SourceEntry]


class ShowIpMrouteResult(TypedDict):
    """Schema for 'show ip mroute' parsed output."""

    groups: dict[str, GroupEntry]


def _parse_route_blocks(output: str) -> list[tuple[re.Match[str], list[str]]]:
    """Split output into per-route blocks, each starting with a route header."""
    blocks: list[tuple[re.Match[str], list[str]]] = []
    current_match: re.Match[str] | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _ROUTE_HEADER_RE.match(line)
        if m:
            if current_match is not None:
                blocks.append((current_match, current_lines))
            current_match = m
            current_lines = []
        elif current_match is not None:
            current_lines.append(line)

    if current_match is not None:
        blocks.append((current_match, current_lines))

    return blocks


def _parse_incoming(body_lines: list[str], entry: dict[str, object]) -> None:
    """Parse the incoming interface line from body lines."""
    for line in body_lines:
        m = _INCOMING_RE.match(line)
        if m:
            iface = m.group("interface")
            if iface != "Null":
                entry["incoming_interface"] = canonical_interface_name(
                    iface, os=OS.CISCO_IOS
                )
            entry["rpf_neighbor"] = m.group("rpf_neighbor")
            rpf_info = m.group("rpf_info")
            if rpf_info:
                entry["rpf_info"] = rpf_info
            return


def _parse_oif_entry(m: re.Match[str]) -> tuple[str, OutgoingInterfaceEntry]:
    """Build a single outgoing interface entry from a regex match."""
    iface_name = canonical_interface_name(m.group("interface"), os=OS.CISCO_IOS)
    oif_entry: OutgoingInterfaceEntry = {
        "state_mode": m.group("state_mode"),
        "uptime": m.group("uptime"),
        "expires": m.group("expires"),
    }
    vcd = m.group("vcd")
    if vcd:
        oif_entry["vcd"] = int(vcd)
    return iface_name, oif_entry


def _parse_outgoing(body_lines: list[str], entry: dict[str, object]) -> None:
    """Parse outgoing interface list from body lines."""
    oif: dict[str, OutgoingInterfaceEntry] = {}
    in_oif_list = False

    for line in body_lines:
        if _OIF_NULL_RE.match(line):
            return
        if _OIF_HEADER_RE.match(line):
            in_oif_list = True
            continue
        if in_oif_list:
            m = _OIF_RE.match(line)
            if m:
                name, oif_entry = _parse_oif_entry(m)
                oif[name] = oif_entry
            else:
                break

    if oif:
        entry["outgoing_interfaces"] = oif


def _parse_source_entry(
    header: re.Match[str],
    body_lines: list[str],
) -> SourceEntry:
    """Parse a single route block into a SourceEntry."""
    entry: dict[str, object] = {
        "uptime": header.group("uptime"),
        "expires": header.group("expires"),
        "flags": header.group("flags"),
    }

    rp = header.group("rp")
    if rp:
        entry["rp"] = rp

    _parse_incoming(body_lines, entry)
    _parse_outgoing(body_lines, entry)

    return entry  # type: ignore[return-value]


@register(OS.CISCO_IOS, "show ip mroute")
class ShowIpMrouteParser(BaseParser[ShowIpMrouteResult]):
    """Parser for 'show ip mroute' on IOS.

    Parses IP multicast routing table entries with group/source
    hierarchy, incoming/outgoing interfaces, flags, and timers.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"multicast", "routing"})

    @classmethod
    def parse(cls, output: str) -> ShowIpMrouteResult:
        """Parse 'show ip mroute' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed multicast route entries keyed by group then source.

        Raises:
            ValueError: If no multicast route entries found.
        """
        blocks = _parse_route_blocks(output)

        if not blocks:
            msg = "No multicast route entries found in output"
            raise ValueError(msg)

        groups: dict[str, GroupEntry] = {}

        for header, body_lines in blocks:
            group = header.group("group")
            source = header.group("source")
            source_entry = _parse_source_entry(header, body_lines)

            if group not in groups:
                groups[group] = {"sources": {}}

            groups[group]["sources"][source] = source_entry

        return {"groups": groups}
