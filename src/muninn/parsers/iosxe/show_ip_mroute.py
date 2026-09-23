"""Parser for 'show ip mroute' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# (*, 239.1.1.1), 00:05:14/stopped, RP 192.168.19.1, flags: SPF
# (50.50.50.2, 239.0.0.13), 00:00:39/00:02:20, flags:
_ROUTE_HEADER_RE = re.compile(
    r"^\((?P<source>\*|[\d.]+),\s+(?P<group>[\d.]+)\),\s+"
    r"(?P<uptime>[^/\s]+)/(?P<expires>[^,\s]+)"
    r"(?:,\s+RP\s+(?P<rp>[\d.]+))?"
    r",\s+flags:(?:\s+(?P<flags>\S+))?\s*$"
)

# Incoming interface: Vlan1022, RPF nbr 0.0.0.0, Registering
# Incoming interface: Vlan500, RPF nbr 8888::8
# Incoming interface: Tunnel0, RPF nbr 2.2.2.2, MDT:239.192.20.41/00:02:02
_INCOMING_RE = re.compile(
    r"^\s+Incoming interface:\s+(?P<interface>[^\s,]+)"
    r",\s+RPF nbr\s+(?P<rpf_neighbor>[^\s,]+)"
    r"(?:,\s+(?P<rpf_info>.+?))?\s*$"
)


# Vlan100, Forward/Sparse, 1d05h/00:02:42, flags:
# Vlan500, VXLAN v4 Encap: (50000, 239.1.1.0), Forward/Sparse, 1d05h/stopped
# LISP0.4100, (172.24.0.3, 232.0.0.199), Forward/Sparse, 00:00:52/stopped
# LISP0.1, 100.99.99.99, Forward/Sparse, 02:00:04/00:02:43, Pkts:2, flags: p
_OIF_RE = re.compile(
    r"^\s+(?P<interface>[^\s,]+),"
    r"(?:\s+VXLAN\s+(?P<vxlan_version>v\d)\s+Encap:\s+"
    r"\((?P<vxlan_vni>\d+),\s+(?P<vxlan_group>[^)\s]+)\),)?"
    r"(?:\s+\((?P<lisp_source>[\d.]+),\s+(?P<lisp_group>[\d.]+)\),)?"
    r"(?:\s+(?P<next_hop>[\d.]+),)?"
    r"\s+(?P<state_mode>\w+/[\w-]+),"
    r"\s+(?P<uptime>[^/\s]+)/(?P<expires>[^,\s]+)"
    r"(?:,\s+Pkts:(?P<pkts>\d+))?"
    r"(?:,\s+flags:(?:\s+(?P<flags>\S+))?)?\s*$"
)

# Extranet receivers in vrf VRF1:
_EXTRANET_HEADER_RE = re.compile(r"^\s+Extranet receivers in vrf (?P<vrf>\S+):\s*$")

# (193.168.1.2, 239.2.1.100), 00:02:11/00:00:48, OIF count: 0, flags: PFT
# (*, 239.7.1.100), 00:58:24/stopped, RP 153.1.1.1, OIF count: 0, flags: SP
_EXTRANET_ENTRY_RE = re.compile(
    r"^\s+\((?P<source>\*|[\d.]+),\s+(?P<group>[\d.]+)\),\s+"
    r"(?P<uptime>[^/\s]+)/(?P<expires>[^,\s]+)"
    r"(?:,\s+RP\s+(?P<rp>[\d.]+))?"
    r",\s+OIF count:\s+(?P<oif_count>\d+)"
    r",\s+flags:(?:\s+(?P<flags>\S+))?\s*$"
)


class VxlanEncap(TypedDict):
    """VXLAN encapsulation of an outgoing interface."""

    version: str
    vni: int
    group: str


class LispUnderlay(TypedDict):
    """LISP underlay (source, group) of an outgoing interface."""

    source: str
    group: str


class NextHopEntry(TypedDict):
    """Per-next-hop state of an outgoing interface (e.g. LISP RLOCs)."""

    state_mode: str
    uptime: str
    expires: str
    pkts: NotRequired[int]
    flags: NotRequired[str]


class OutgoingInterfaceEntry(TypedDict):
    """Schema for a single outgoing interface.

    When the interface lists next hops, per-hop state lives under
    ``next_hops`` and the interface-level state fields are absent.
    """

    state_mode: NotRequired[str]
    uptime: NotRequired[str]
    expires: NotRequired[str]
    pkts: NotRequired[int]
    flags: NotRequired[str]
    vxlan_encap: NotRequired[VxlanEncap]
    lisp_underlay: NotRequired[LispUnderlay]
    next_hops: NotRequired[dict[str, NextHopEntry]]


class ExtranetReceiverEntry(TypedDict):
    """Schema for an extranet receiver entry in another VRF."""

    source: str
    group: str
    uptime: str
    expires: str
    oif_count: int
    rp: NotRequired[str]
    flags: NotRequired[str]


class SourceEntry(TypedDict):
    """Schema for a source entry within a multicast group."""

    uptime: str
    expires: str
    rpf_neighbor: str
    flags: NotRequired[str]
    incoming_interface: NotRequired[str]
    rpf_info: NotRequired[str]
    rp: NotRequired[str]
    outgoing_interfaces: NotRequired[dict[str, OutgoingInterfaceEntry]]
    extranet_receivers: NotRequired[dict[str, ExtranetReceiverEntry]]


class GroupEntry(TypedDict):
    """Schema for a multicast group."""

    sources: dict[str, SourceEntry]


class ShowIpMrouteResult(TypedDict):
    """Schema for 'show ip mroute' parsed output."""

    groups: dict[str, GroupEntry]


def _state(m: re.Match[str]) -> dict[str, object]:
    """Build the state/timer/pkts/flags fields shared by OIF and next hop."""
    entry: dict[str, object] = {
        "state_mode": m.group("state_mode"),
        "uptime": m.group("uptime"),
        "expires": m.group("expires"),
    }
    if m.group("pkts"):
        entry["pkts"] = int(m.group("pkts"))
    if m.group("flags"):
        entry["flags"] = m.group("flags")
    return entry


def _add_oif(m: re.Match[str], oifs: dict[str, dict[str, object]]) -> None:
    """Add an outgoing interface line to the OIF dict."""
    name = canonical_interface_name(m.group("interface"), os=OS.CISCO_IOSXE)
    oif = oifs.setdefault(name, {})
    if m.group("next_hop"):
        hops = cast(dict[str, object], oif.setdefault("next_hops", {}))
        hops[m.group("next_hop")] = _state(m)
    else:
        oif.update(_state(m))
    if m.group("vxlan_version"):
        oif["vxlan_encap"] = {
            "version": m.group("vxlan_version"),
            "vni": int(m.group("vxlan_vni")),
            "group": m.group("vxlan_group"),
        }
    if m.group("lisp_source"):
        oif["lisp_underlay"] = {
            "source": m.group("lisp_source"),
            "group": m.group("lisp_group"),
        }


def _extranet_entry(m: re.Match[str]) -> dict[str, object]:
    """Build an extranet receiver entry from a regex match."""
    entry: dict[str, object] = {
        "source": m.group("source"),
        "group": m.group("group"),
        "uptime": m.group("uptime"),
        "expires": m.group("expires"),
        "oif_count": int(m.group("oif_count")),
    }
    if m.group("rp"):
        entry["rp"] = m.group("rp")
    if m.group("flags"):
        entry["flags"] = m.group("flags")
    return entry


def _new_source(m: re.Match[str]) -> dict[str, object]:
    """Build a source entry from a route header match."""
    entry: dict[str, object] = {
        "uptime": m.group("uptime"),
        "expires": m.group("expires"),
    }
    for key in ("rp", "flags"):
        if m.group(key):
            entry[key] = m.group(key)
    return entry


def _apply_incoming(m: re.Match[str], entry: dict[str, object]) -> None:
    """Apply an incoming interface match to a source entry."""
    iface = m.group("interface")
    if iface != "Null":
        entry["incoming_interface"] = canonical_interface_name(iface, os=OS.CISCO_IOSXE)
    entry["rpf_neighbor"] = m.group("rpf_neighbor")
    if m.group("rpf_info"):
        entry["rpf_info"] = m.group("rpf_info")


def _parse_body_line(line: str, entry: dict[str, object], state: dict) -> None:
    """Parse one line inside a route block, tracking the extranet VRF."""
    if m := _INCOMING_RE.match(line):
        _apply_incoming(m, entry)
    elif m := _OIF_RE.match(line):
        _add_oif(m, cast(dict, entry.setdefault("outgoing_interfaces", {})))
    elif m := _EXTRANET_HEADER_RE.match(line):
        state["vrf"] = m.group("vrf")
    elif (m := _EXTRANET_ENTRY_RE.match(line)) and state.get("vrf"):
        receivers = cast(dict, entry.setdefault("extranet_receivers", {}))
        receivers[state["vrf"]] = _extranet_entry(m)


@register(OS.CISCO_IOSXE, "show ip mroute")
@register(OS.CISCO_IOSXE, r"show ip mroute vrf (?P<vrf>\S+)")
@register(
    OS.CISCO_IOSXE,
    r"show ip mroute vrf (?P<vrf>\S+) (?P<group>\d+\.\d+\.\d+\.\d+)",
)
class ShowIpMrouteParser(BaseParser[ShowIpMrouteResult]):
    """Parser for 'show ip mroute' on IOS-XE.

    Parses IP multicast routing table entries with group/source
    hierarchy, incoming/outgoing interfaces, flags, timers, VXLAN/LISP
    outgoing interface details, and extranet receivers.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MULTICAST,
            ParserTag.ROUTING,
        }
    )

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
        groups: dict[str, dict[str, dict[str, dict[str, object]]]] = {}
        entry: dict[str, object] | None = None
        state: dict[str, str] = {}

        for line in output.splitlines():
            if m := _ROUTE_HEADER_RE.match(line):
                entry = _new_source(m)
                state = {}
                group = groups.setdefault(m.group("group"), {"sources": {}})
                group["sources"][m.group("source")] = entry
            elif entry is not None:
                _parse_body_line(line, entry, state)

        if not groups:
            msg = "No multicast route entries found in output"
            raise ValueError(msg)
        for group in groups.values():
            if any("rpf_neighbor" not in s for s in group["sources"].values()):
                msg = "Missing required field: rpf_neighbor"
                raise ValueError(msg)

        return cast(ShowIpMrouteResult, {"groups": groups})
