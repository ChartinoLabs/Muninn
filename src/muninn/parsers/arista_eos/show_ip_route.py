"""Parser for 'show ip route' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

# --- Protocol code to name mapping ---
_PROTOCOL_MAP: dict[str, str] = {
    "C": "connected",
    "S": "static",
    "K": "kernel",
    "O": "ospf",
    "B": "bgp",
    "R": "rip",
    "I": "isis",
    "A": "aggregate",
    "NG": "nexthop-group",
    "V": "vxlan",
    "DH": "dhcp",
    "M": "martian",
    "DP": "dynamic-policy",
    "L": "vrf-leaked",
    "G": "gribi",
    "RC": "route-cache",
}

# --- Type/sub-protocol code to name mapping ---
_TYPE_MAP: dict[str, str] = {
    "E": "ebgp",
    "I": "ibgp",
    "IA": "inter-area",
    "E1": "external-type-1",
    "E2": "external-type-2",
    "N1": "nssa-type-1",
    "N2": "nssa-type-2",
    "L1": "level-1",
    "L2": "level-2",
    "B": "aggregate-bgp",
    "O": "aggregate-ospf",
}


class NextHopEntry(TypedDict):
    """Schema for a single next-hop entry."""

    next_hop: NotRequired[str]
    outgoing_interface: NotRequired[str]
    admin_distance: NotRequired[int]
    metric: NotRequired[int]


class RouteEntry(TypedDict):
    """Schema for a single route entry."""

    network: str
    mask: int
    protocol: str
    protocol_code: str
    type: NotRequired[str]
    type_code: NotRequired[str]
    next_hops: list[NextHopEntry]


class ShowIpRouteResult(TypedDict):
    """Schema for 'show ip route' parsed output on Arista EOS."""

    vrf: str
    gateway_of_last_resort: NotRequired[str]
    routes: dict[str, RouteEntry]


# --- Regex patterns ---

# VRF header: "VRF: name" or "VRF name: name"
_VRF_RE = re.compile(r"^VRF(?:\s+name)?:\s*(\S+)\s*$")

# Gateway of last resort
_GATEWAY_SET_RE = re.compile(r"^Gateway of last resort is (\S+)")
_GATEWAY_NOT_SET_RE = re.compile(r"^Gateway of last resort is not set")
_GATEWAY_EMPTY_RE = re.compile(r"^Gateway of last resort:\s*$")

# Codes section header
_CODES_RE = re.compile(r"^Codes:\s")

# Route entry: leading space, protocol code(s), optional type, prefix, rest
# Arista EOS format examples:
#  B E    10.1.31.100/32 [200/0] via 192.168.17.5, Ethernet18
#  C      10.1.31.102/32 is directly connected, Loopback100
#  O E1   0.0.0.0/0 [110/21] via 172.83.43.48, Vlan55
#  S      162.220.49.0/24 is directly connected, Null0
#  B I    74.119.147.148/32 [200/0] via 199.229.255.31, Vlan70
_ROUTE_RE = re.compile(
    r"^\s+"
    r"([A-Z][A-Z]?)"  # primary protocol code (1-2 chars)
    r"(?:\s+([A-Z]\w?))?"  # optional type/sub-protocol code
    r"\s+"
    rf"({IPV4_ADDRESS}/\d{{1,2}})"  # network/prefix
    r"\s+"
    r"(.+)$"  # rest of the line
)

# Next-hop with [AD/metric] via IP, interface
_NEXTHOP_VIA_RE = re.compile(
    r"\[(\d+)/(\d+)\]\s+via\s+"
    rf"({IPV4_ADDRESS})"
    r"(?:,\s*(\S+))?"  # optional interface
)

# Directly connected route
_DIRECTLY_CONNECTED_RE = re.compile(r"is directly connected,\s*(\S+)")

# ECMP continuation line (indented, starts with "via")
_CONTINUATION_RE = re.compile(
    r"^\s+via\s+"
    rf"({IPV4_ADDRESS})"
    r"(?:,\s*(\S+))?"
)

# Lines indicating IP routing not enabled or warning lines
_SKIP_LINE_RE = re.compile(r"^!\s|^WARNING:")


def _resolve_protocol(proto_code: str, type_code: str | None) -> tuple[str, str | None]:
    """Resolve protocol and type names from their codes.

    Args:
        proto_code: Primary protocol code (e.g. "B", "O", "C").
        type_code: Optional type code (e.g. "E", "I", "IA", "E1").

    Returns:
        Tuple of (protocol_name, type_name_or_none).
    """
    protocol = _PROTOCOL_MAP.get(proto_code, proto_code.lower())
    type_name: str | None = None
    if type_code:
        type_name = _TYPE_MAP.get(type_code, type_code.lower())
    return protocol, type_name


def _parse_nexthop_via(rest: str) -> NextHopEntry | None:
    """Parse a next-hop from [AD/metric] via IP, interface format."""
    m = _NEXTHOP_VIA_RE.search(rest)
    if not m:
        return None
    hop: NextHopEntry = {
        "admin_distance": int(m.group(1)),
        "metric": int(m.group(2)),
        "next_hop": m.group(3),
    }
    if m.group(4):
        hop["outgoing_interface"] = m.group(4)
    return hop


def _parse_directly_connected(rest: str) -> NextHopEntry | None:
    """Parse a directly connected route."""
    m = _DIRECTLY_CONNECTED_RE.search(rest)
    if not m:
        return None
    return {"outgoing_interface": m.group(1)}


def _parse_nexthop(rest: str) -> NextHopEntry:
    """Parse the next-hop from the rest of a route line."""
    hop = _parse_nexthop_via(rest)
    if hop is not None:
        return hop
    hop = _parse_directly_connected(rest)
    if hop is not None:
        return hop
    return {}


def _is_codes_continuation(line: str) -> bool:
    """Check if line is a continuation of the codes legend section."""
    stripped = line.strip()
    # Continuation lines of codes section are indented and contain " - "
    if not line.startswith(" "):
        return False
    return " - " in stripped


def _parse_continuation_hop(line: str) -> NextHopEntry | None:
    """Parse an ECMP continuation line (indented 'via ...')."""
    m = _CONTINUATION_RE.match(line)
    if not m:
        return None
    hop: NextHopEntry = {"next_hop": m.group(1)}
    if m.group(2):
        hop["outgoing_interface"] = m.group(2)
    return hop


def _build_route_entry(
    proto_code: str,
    type_code: str | None,
    prefix: str,
    rest: str,
) -> tuple[str, RouteEntry]:
    """Build a RouteEntry from parsed route components.

    Returns:
        Tuple of (route_key, route_entry).
    """
    network, _, mask_str = prefix.partition("/")
    mask = int(mask_str)
    protocol, type_name = _resolve_protocol(proto_code, type_code)

    full_code = proto_code
    if type_code:
        full_code = f"{proto_code} {type_code}"

    entry: RouteEntry = {
        "network": network,
        "mask": mask,
        "protocol": protocol,
        "protocol_code": full_code,
        "next_hops": [_parse_nexthop(rest)],
    }

    if type_code and type_name:
        entry["type_code"] = type_code
        entry["type"] = type_name

    return prefix, entry


def _copy_distance_to_continuation(route: RouteEntry, hop: NextHopEntry) -> None:
    """Copy admin_distance and metric from first hop to a continuation."""
    if route["next_hops"]:
        first = route["next_hops"][0]
        if "admin_distance" in first:
            hop["admin_distance"] = first["admin_distance"]
        if "metric" in first:
            hop["metric"] = first["metric"]


class _ParseState:
    """Mutable state for the route parsing loop."""

    __slots__ = ("vrf", "gateway", "routes", "current_route_key", "in_codes")

    def __init__(self) -> None:
        self.vrf: str = "default"
        self.gateway: str | None = None
        self.routes: dict[str, RouteEntry] = {}
        self.current_route_key: str | None = None
        self.in_codes: bool = False


def _process_header(stripped: str, state: _ParseState) -> bool:
    """Process VRF, codes, and gateway header lines.

    Returns True if the line was consumed.
    """
    vrf_match = _VRF_RE.match(stripped)
    if vrf_match:
        state.vrf = vrf_match.group(1)
        return True

    if _CODES_RE.match(stripped):
        state.in_codes = True
        return True

    if _GATEWAY_NOT_SET_RE.match(stripped):
        return True

    gw_match = _GATEWAY_SET_RE.match(stripped)
    if gw_match:
        state.gateway = gw_match.group(1)
        return True

    if _GATEWAY_EMPTY_RE.match(stripped):
        return True

    return False


def _process_route_line(line: str, state: _ParseState) -> bool:
    """Process a route entry line. Returns True if consumed."""
    route_match = _ROUTE_RE.match(line)
    if not route_match:
        return False

    proto_code = route_match.group(1)
    type_code = route_match.group(2)
    prefix = route_match.group(3)
    rest = route_match.group(4)

    route_key, entry = _build_route_entry(proto_code, type_code, prefix, rest)
    state.routes[route_key] = entry
    state.current_route_key = route_key
    return True


def _process_continuation(line: str, state: _ParseState) -> bool:
    """Process an ECMP continuation line. Returns True if consumed."""
    cont_hop = _parse_continuation_hop(line)
    if cont_hop is None:
        return False

    key = state.current_route_key
    if key and key in state.routes:
        _copy_distance_to_continuation(state.routes[key], cont_hop)
        state.routes[key]["next_hops"].append(cont_hop)
    return True


def _process_line(line: str, stripped: str, state: _ParseState) -> None:
    """Process a single non-empty, non-codes line."""
    if _SKIP_LINE_RE.match(stripped):
        return
    if _process_header(stripped, state):
        return
    if _process_continuation(line, state):
        return
    _process_route_line(line, state)


def _parse_routes(output: str) -> ShowIpRouteResult:
    """Parse all lines into a routing result."""
    state = _ParseState()

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped:
            state.in_codes = False
            continue

        if state.in_codes:
            if _is_codes_continuation(line):
                continue
            state.in_codes = False

        _process_line(line, stripped, state)

    if not state.routes:
        msg = "No routes found in output"
        raise ValueError(msg)

    result: dict[str, object] = {
        "vrf": state.vrf,
        "routes": state.routes,
    }

    if state.gateway is not None:
        result["gateway_of_last_resort"] = state.gateway

    return cast(ShowIpRouteResult, result)


@register(OS.ARISTA_EOS, "show ip route")
class ShowIpRouteParser(BaseParser[ShowIpRouteResult]):
    """Parser for 'show ip route' command on Arista EOS.

    Parses the IPv4 routing table including VRF context, multiple
    next-hops per route (ECMP), and various routing protocols.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    _VRF_RE: ClassVar[re.Pattern[str]] = _VRF_RE
    _GATEWAY_SET_RE: ClassVar[re.Pattern[str]] = _GATEWAY_SET_RE
    _GATEWAY_NOT_SET_RE: ClassVar[re.Pattern[str]] = _GATEWAY_NOT_SET_RE
    _GATEWAY_EMPTY_RE: ClassVar[re.Pattern[str]] = _GATEWAY_EMPTY_RE
    _CODES_RE: ClassVar[re.Pattern[str]] = _CODES_RE
    _ROUTE_RE: ClassVar[re.Pattern[str]] = _ROUTE_RE
    _SKIP_LINE_RE: ClassVar[re.Pattern[str]] = _SKIP_LINE_RE

    @classmethod
    def parse(cls, output: str) -> ShowIpRouteResult:
        """Parse 'show ip route' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed routing table with VRF, gateway, and routes.

        Raises:
            ValueError: If no routes found in output.
        """
        return _parse_routes(output)
