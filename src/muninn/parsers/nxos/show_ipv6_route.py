"""Parser for 'show ipv6 route' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class NextHop(TypedDict):
    """Schema for a single next-hop entry."""

    next_hop: str
    interface: NotRequired[str]
    preference: int
    metric: int
    uptime: str
    protocol: str
    best: NotRequired[bool]
    tag: NotRequired[int]
    route_type: NotRequired[str]
    segid: NotRequired[int]
    tunnelid: NotRequired[str]
    encap: NotRequired[str]


class RouteEntry(TypedDict):
    """Schema for a single route entry."""

    ubest: int
    mbest: int
    attached: NotRequired[bool]
    next_hops: list[NextHop]


class VrfRoutes(TypedDict):
    """Schema for routes within a VRF."""

    routes: dict[str, RouteEntry]


class ShowIpv6RouteResult(TypedDict):
    """Schema for 'show ipv6 route' parsed output."""

    vrfs: dict[str, VrfRoutes]


# Regex for VRF header line
_VRF_PATTERN = re.compile(r'IPv6 Routing Table for VRF "(?P<vrf>[^"]+)"')

# Regex for route prefix line
# Examples:
#   2001:1:1:1::1/128, ubest/mbest: 2/0
#   2001:3:3:3::3/128, ubest/mbest: 2/0, attached
_ROUTE_PATTERN = re.compile(
    r"^(?P<prefix>[0-9a-fA-F:]+/\d+),\s+"
    r"ubest/mbest:\s+(?P<ubest>\d+)/(?P<mbest>\d+)"
    r"(?:,\s+attached)?"
)

# Regex for next-hop line (captures core fields; tail parsed separately)
# Examples:
#   *via 2001:10:1:3::1, Eth1/2, [1/0], 01:02:00, static
#   *via fe80::5054:ff:fe64:bd2e, Eth1/3, [110/41], 01:01:10, ospfv3-1, intra
#   *via ::ffff:10.229.11.11%default:IPv4, [200/0], 01:01:43, bgp-100, internal,
#   *via 2001:100:20:b::1, Vlan111, [0/0], 3d21h, direct, tag 12345
#   *via ::ffff:40.17.113.3%default:IPv4, [200/0], 0.000000, bgp-65103, , tag 6555
_NEXTHOP_PATTERN = re.compile(
    r"^\s*(?P<best>\*?)via\s+(?P<next_hop>\S+?),"
    r"\s+(?:(?P<interface>[A-Za-z][A-Za-z0-9/.\-]+),\s+)?"
    r"\[(?P<preference>\d+)/(?P<metric>\d+)\],\s+"
    r"(?P<uptime>\S+),\s+"
    r"(?P<protocol>\S+?)"
    r"(?P<tail>,.*)?$"
)

# Regex for continuation line with tag (possibly with VXLAN attributes)
# Examples:
#   tag 100
#   , segid 50003 tunnelid: 0x28117103 encap: VXLAN
_TAG_PATTERN = re.compile(r"^(?:,\s*)?tag\s+(?P<tag>\d+)")

# Regex for VXLAN continuation line
# Example: , segid 50003 tunnelid: 0x28117103 encap: VXLAN
_VXLAN_PATTERN = re.compile(
    r"segid\s+(?P<segid>\d+)\s+"
    r"tunnelid:\s+(?P<tunnelid>\S+)\s+"
    r"encap:\s+(?P<encap>\S+)"
)


def _has_attached(line: str) -> bool:
    """Check if a route line includes the 'attached' flag."""
    return ", attached" in line


@register(OS.CISCO_NXOS, "show ipv6 route")
class ShowIpv6RouteParser(BaseParser[ShowIpv6RouteResult]):
    """Parser for 'show ipv6 route' command on NX-OS.

    Parses IPv6 routing table entries grouped by VRF with next-hop details.
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpv6RouteResult:
        """Parse 'show ipv6 route' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IPv6 routing table keyed by VRF and prefix.

        Raises:
            ValueError: If no VRF routing tables found.
        """
        vrfs: dict[str, VrfRoutes] = {}
        current_vrf: str | None = None
        current_prefix: str | None = None
        current_next_hops: list[NextHop] = []
        current_route: RouteEntry | None = None

        lines = output.splitlines()
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            # Check for VRF header
            vrf_match = _VRF_PATTERN.search(stripped)
            if vrf_match:
                current_vrf = vrf_match.group("vrf")
                vrfs[current_vrf] = {"routes": {}}
                current_prefix = None
                current_route = None
                continue

            if current_vrf is None:
                continue

            # Check for route prefix line
            route_match = _ROUTE_PATTERN.match(stripped)
            if route_match:
                current_prefix = route_match.group("prefix")
                current_next_hops = []
                current_route = {
                    "ubest": int(route_match.group("ubest")),
                    "mbest": int(route_match.group("mbest")),
                    "next_hops": current_next_hops,
                }
                if _has_attached(stripped):
                    current_route["attached"] = True
                vrfs[current_vrf]["routes"][current_prefix] = current_route
                continue

            if current_prefix is None or current_route is None:
                continue

            # Check for next-hop line
            nh_match = _NEXTHOP_PATTERN.match(stripped)
            if nh_match:
                hop = _build_next_hop(nh_match)
                current_next_hops.append(hop)
                continue

            # Check for continuation lines (tag, VXLAN attributes)
            _parse_continuation(stripped, current_next_hops)

        if not vrfs:
            msg = "No IPv6 routing tables found in output"
            raise ValueError(msg)

        return ShowIpv6RouteResult(vrfs=vrfs)


# Pattern to extract route_type from the tail (first alphabetic word after comma,
# excluding "tag" which is a separate field)
_ROUTE_TYPE_PATTERN = re.compile(r",\s*(?P<route_type>(?!tag\b)[a-zA-Z][a-zA-Z_]+)")

# Pattern to extract inline tag from the tail
_INLINE_TAG_PATTERN = re.compile(r"tag\s+(?P<tag>\d+)")


def _build_next_hop(match: re.Match[str]) -> NextHop:
    """Build a NextHop dict from a regex match.

    Args:
        match: Regex match object from _NEXTHOP_PATTERN.

    Returns:
        Populated NextHop dictionary.
    """
    hop: NextHop = {
        "next_hop": match.group("next_hop"),
        "preference": int(match.group("preference")),
        "metric": int(match.group("metric")),
        "uptime": match.group("uptime"),
        "protocol": match.group("protocol"),
    }

    if match.group("best"):
        hop["best"] = True

    interface = match.group("interface")
    if interface:
        hop["interface"] = canonical_interface_name(interface)

    # Parse the trailing portion after protocol for route_type and tag
    tail = match.group("tail") or ""
    _parse_nexthop_tail(tail, hop)

    return hop


def _parse_nexthop_tail(tail: str, hop: NextHop) -> None:
    """Parse the trailing portion of a next-hop line for route_type and tag.

    Args:
        tail: The comma-separated tail after the protocol field.
        hop: NextHop dict to update in place.
    """
    if not tail:
        return

    route_type_match = _ROUTE_TYPE_PATTERN.search(tail)
    if route_type_match:
        hop["route_type"] = route_type_match.group("route_type")

    tag_match = _INLINE_TAG_PATTERN.search(tail)
    if tag_match:
        hop["tag"] = int(tag_match.group("tag"))


def _parse_continuation(line: str, next_hops: list[NextHop]) -> None:
    """Parse a continuation line and update the last next-hop entry.

    Handles tag values and VXLAN attributes (segid, tunnelid, encap)
    that appear on continuation lines.

    Args:
        line: Stripped continuation line text.
        next_hops: List of next-hops to update (modifies last entry).
    """
    if not next_hops:
        return

    last_hop = next_hops[-1]

    tag_match = _TAG_PATTERN.search(line)
    if tag_match:
        last_hop["tag"] = int(tag_match.group("tag"))

    vxlan_match = _VXLAN_PATTERN.search(line)
    if vxlan_match:
        last_hop["segid"] = int(vxlan_match.group("segid"))
        last_hop["tunnelid"] = vxlan_match.group("tunnelid")
        last_hop["encap"] = vxlan_match.group("encap")
