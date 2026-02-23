"""Parser for 'show ip route' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class NextHop(TypedDict):
    """Schema for a single next-hop entry."""

    best: bool
    best_ucast: bool
    best_mcast: bool
    next_hop: str
    preference: int
    metric: int
    uptime: str
    protocol: str
    next_hop_vrf: NotRequired[str]
    interface: NotRequired[str]
    process: NotRequired[str]
    route_type: NotRequired[str]
    tag: NotRequired[int]
    segid: NotRequired[int]
    tunnelid: NotRequired[str]
    encap: NotRequired[str]


class Route(TypedDict):
    """Schema for a single route entry."""

    prefix: str
    mask: int
    ubest: int
    mbest: int
    attached: bool
    direct: bool
    pervasive: bool
    pending: bool
    next_hops: list[NextHop]


class VrfRoutes(TypedDict):
    """Schema for routes within a VRF."""

    routes: dict[str, Route]


class ShowIpRouteResult(TypedDict):
    """Schema for 'show ip route' parsed output."""

    vrfs: dict[str, VrfRoutes]


# VRF header line: IP Route Table for VRF "name"
_VRF_HEADER_PATTERN = re.compile(r'^IP Route Table for VRF "(?P<vrf>.+)"')

# Route prefix line: 10.10.0.21/32, ubest/mbest: 1/0[, flags...]
_ROUTE_PREFIX_PATTERN = re.compile(
    r"^(?P<prefix>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"/(?P<mask>\d{1,2}),\s+"
    r"ubest/mbest:\s+(?P<ubest>\d+)/(?P<mbest>\d+)"
    r"(?P<flags>(?:,\s*\S+)*)"
)

# Next-hop line with optional best marker, VRF, and interface
_NEXTHOP_PATTERN = re.compile(
    r"^\s+(?P<best_marker>\*{0,2})"
    r"via\s+(?P<next_hop>[^,\s%]+)"
    r"(?:%(?P<next_hop_vrf>[^,\s]+))?"
    r"(?:,\s*(?P<interface>[A-Za-z][A-Za-z0-9/.-]+))?"
    r",\s*\[(?P<preference>\d+)/(?P<metric>\d+)\]"
    r",\s*(?P<uptime>[^,]+)"
    r",\s*(?P<protocol_info>.+)$"
)


def _parse_flags(flags_str: str) -> dict[str, bool]:
    """Extract boolean flags from the route prefix line."""
    flags = flags_str.lower()
    return {
        "attached": "attached" in flags,
        "direct": "direct" in flags,
        "pervasive": "pervasive" in flags,
        "pending": "pending" in flags,
    }


def _extract_field(proto_info: str, pattern: str) -> tuple[str, str | None]:
    """Extract a named field from protocol info and return cleaned string + value."""
    match = re.search(pattern, proto_info)
    if not match:
        return proto_info, None
    value = match.group(1)
    proto_info = proto_info[: match.start()] + proto_info[match.end() :]
    return proto_info, value


def _parse_protocol_tokens(
    proto_info: str, result: dict[str, str | int | None]
) -> None:
    """Parse remaining protocol tokens into protocol, process, and route_type."""
    tokens = [t.strip() for t in proto_info.split(",") if t.strip()]

    if tokens:
        proto_parts = tokens[0].split("-", 1)
        result["protocol"] = proto_parts[0]
        if len(proto_parts) > 1:
            result["process"] = proto_parts[1]

    if len(tokens) > 1:
        route_type = tokens[1].strip()
        if route_type:
            result["route_type"] = route_type


def _parse_protocol_info(
    proto_info: str,
) -> dict[str, str | int | None]:
    """Parse protocol, process, route_type, tag, and VXLAN fields."""
    result: dict[str, str | int | None] = {"protocol": ""}

    # Remove eLB marker and parenthetical modifiers like (evpn), (hidden)
    proto_info = re.sub(r",?\s*eLB\b", "", proto_info)
    proto_info = re.sub(r"\s*\([^)]+\)", "", proto_info)

    # Extract key:value fields
    proto_info, encap = _extract_field(proto_info, r"encap:\s*(\S+)")
    if encap:
        result["encap"] = encap

    proto_info, tunnelid = _extract_field(proto_info, r"tunnelid:\s*(\S+)")
    if tunnelid:
        result["tunnelid"] = tunnelid

    proto_info, segid = _extract_field(proto_info, r"segid:\s*(\d+)")
    if segid:
        result["segid"] = int(segid)

    proto_info, tag = _extract_field(proto_info, r"tag\s+(\d+)")
    if tag:
        result["tag"] = int(tag)

    _parse_protocol_tokens(proto_info, result)
    return result


def _build_nexthop(
    nh_match: re.Match[str],
    proto_fields: dict[str, str | int | None],
) -> NextHop:
    """Build a NextHop dict, omitting fields with None values."""
    best_marker = nh_match.group("best_marker")
    is_best = len(best_marker) >= 1

    nexthop: NextHop = {
        "best": is_best,
        "best_ucast": "*" in best_marker,
        "best_mcast": best_marker == "**",
        "next_hop": nh_match.group("next_hop"),
        "preference": int(nh_match.group("preference")),
        "metric": int(nh_match.group("metric")),
        "uptime": nh_match.group("uptime").strip(),
        "protocol": str(proto_fields["protocol"]),
    }

    # Add optional fields only when present
    next_hop_vrf = nh_match.group("next_hop_vrf")
    if next_hop_vrf:
        nexthop["next_hop_vrf"] = next_hop_vrf

    interface = nh_match.group("interface")
    if interface:
        nexthop["interface"] = canonical_interface_name(interface, os=OS.CISCO_NXOS)

    for key in ("process", "route_type", "tunnelid", "encap"):
        val = proto_fields.get(key)
        if val is not None:
            nexthop[key] = val  # type: ignore[literal-required]

    for key in ("tag", "segid"):
        val = proto_fields.get(key)
        if val is not None:
            nexthop[key] = int(val)  # type: ignore[literal-required]

    return nexthop


def _is_skippable(line: str) -> bool:
    """Check if a line should be skipped during parsing."""
    stripped = line.strip()
    return not stripped or stripped.startswith("'") or stripped.startswith("%")


def _add_route(route_match: re.Match[str], routes: dict[str, Route]) -> str:
    """Create a Route from a prefix match and add it to the routes dict."""
    prefix = route_match.group("prefix")
    mask = int(route_match.group("mask"))
    route_key = f"{prefix}/{mask}"
    flags = _parse_flags(route_match.group("flags"))

    routes[route_key] = Route(
        prefix=prefix,
        mask=mask,
        ubest=int(route_match.group("ubest")),
        mbest=int(route_match.group("mbest")),
        attached=flags["attached"],
        direct=flags["direct"],
        pervasive=flags["pervasive"],
        pending=flags["pending"],
        next_hops=[],
    )
    return route_key


def _process_nexthop(
    line: str,
    current_route_key: str | None,
    routes: dict[str, Route],
) -> str | None:
    """Try to parse a next-hop line and append it to the current route."""
    nh_match = _NEXTHOP_PATTERN.match(line)
    if nh_match and current_route_key and current_route_key in routes:
        proto_fields = _parse_protocol_info(nh_match.group("protocol_info"))
        nexthop = _build_nexthop(nh_match, proto_fields)
        routes[current_route_key]["next_hops"].append(nexthop)
    return current_route_key


@register(OS.CISCO_NXOS, "show ip route")
class ShowIpRouteParser(BaseParser[ShowIpRouteResult]):
    """Parser for 'show ip route' command on NX-OS.

    Parses the IPv4 routing table including VRF context, multiple
    next-hops per route (ECMP), and VXLAN overlay attributes.
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpRouteResult:
        """Parse 'show ip route' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed routing table organized by VRF.

        Raises:
            ValueError: If no VRF header found in output.
        """
        vrfs: dict[str, VrfRoutes] = {}
        current_vrf: str | None = None
        current_routes: dict[str, Route] = {}
        current_route_key: str | None = None

        for line in output.splitlines():
            vrf_match = _VRF_HEADER_PATTERN.match(line)
            if vrf_match:
                if current_vrf is not None:
                    vrfs[current_vrf] = VrfRoutes(routes=current_routes)
                current_vrf = vrf_match.group("vrf")
                current_routes = {}
                current_route_key = None
                continue

            if _is_skippable(line):
                continue

            route_match = _ROUTE_PREFIX_PATTERN.match(line)
            if route_match:
                current_route_key = _add_route(route_match, current_routes)
                continue

            current_route_key = _process_nexthop(
                line, current_route_key, current_routes
            )

        # Save last VRF
        if current_vrf is not None:
            vrfs[current_vrf] = VrfRoutes(routes=current_routes)

        if not vrfs:
            msg = "No VRF routing table found in output"
            raise ValueError(msg)

        return ShowIpRouteResult(vrfs=vrfs)
