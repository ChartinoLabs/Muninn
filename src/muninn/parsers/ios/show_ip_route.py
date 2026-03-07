"""Parser for 'show ip route' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# --- Protocol code to name mapping ---
_PROTOCOL_MAP: dict[str, str] = {
    "C": "connected",
    "L": "local",
    "S": "static",
    "R": "rip",
    "M": "mobile",
    "B": "bgp",
    "D": "eigrp",
    "O": "ospf",
    "i": "isis",
    "H": "nhrp",
    "l": "lisp",
    "a": "application",
    "o": "odr",
    "P": "periodic",
    "U": "per-user-static",
    "n": "nat",
    "Ni": "nat-inside",
    "No": "nat-outside",
    "Nd": "nat-dia",
    "m": "omp",
    "G": "nhrp-registered",
    "g": "nhrp-summary",
}

# --- Type code to name mapping ---
_TYPE_MAP: dict[str, str] = {
    "E1": "external-type-1",
    "E2": "external-type-2",
    "IA": "inter-area",
    "N1": "nssa-type-1",
    "N2": "nssa-type-2",
    "EX": "external",
    "L1": "level-1",
    "L2": "level-2",
    "ia": "inter-area",
    "su": "summary",
}

# --- Route flags ---
_FLAG_CANDIDATE_DEFAULT = "*"
_FLAG_REPLICATED = "+"
_FLAG_NEXT_HOP_OVERRIDE = "%"
_FLAG_PFR_OVERRIDE = "p"
_FLAG_REPLICATED_LOCAL_OVERRIDE = "&"


class GatewayOfLastResortEntry(TypedDict):
    """Schema for gateway of last resort."""

    next_hop: str
    destination: str


class NextHopEntry(TypedDict):
    """Schema for a single next-hop entry."""

    outgoing_interface: NotRequired[str]
    next_hop: NotRequired[str]
    admin_distance: NotRequired[int]
    metric: NotRequired[int]
    age: NotRequired[str]
    vrf_leak: NotRequired[str]


class RouteEntry(TypedDict):
    """Schema for a single route entry."""

    network: str
    mask: str
    protocol: str
    protocol_code: str
    type: NotRequired[str]
    type_code: NotRequired[str]
    candidate_default: NotRequired[bool]
    replicated: NotRequired[bool]
    next_hop_override: NotRequired[bool]
    pfr_override: NotRequired[bool]
    replicated_local_override: NotRequired[bool]
    next_hops: list[NextHopEntry]


class ShowIpRouteResult(TypedDict):
    """Schema for 'show ip route' parsed output."""

    vrf: str
    gateway_of_last_resort: NotRequired[GatewayOfLastResortEntry]
    routes: dict[str, RouteEntry]


# --- Regex patterns ---

# Gateway of last resort line
_GATEWAY_RE = re.compile(r"^Gateway of last resort is (\S+) to network (\S+)\s*$")
_GATEWAY_NOT_SET_RE = re.compile(r"^Gateway of last resort is not set\s*$")

# VRF/Routing Table line
_VRF_RE = re.compile(r"^Routing Table:\s*(\S+)\s*$")

# Subnet summary lines (ignored)
_SUBNET_SUMMARY_RE = re.compile(
    r"^\s+\d+\.\d+\.\d+\.\d+/\d+ is (?:variably )?subnetted"
)

# Route entry line - captures flags, protocol code, type code, and the rest
# Examples:
#   C        10.12.90.0/24 is directly connected, GigabitEthernet2.90
#   D        10.16.2.2 [90/10752] via 10.12.90.2, 4d19h, GigabitEthernet2.90
#   O E2    4.4.0.0 [110/20] via 194.0.0.2, 1d18h, FastEthernet0/0.100
#   i L1     10.23.115.0/24 [115/20] via 10.12.115.2, 4d19h, GigabitEthernet2.115
#   O*E2 0.0.0.0/0 [110/1] via 194.0.0.2, 00:05:35, FastEthernet0/0.100
#   B*    0.0.0.0/0 [200/0] via 10.10.254.3, 1d05h
#   S   %    10.34.0.1 [1/0] via 192.168.16.1
#   C   p    10.34.0.2 is directly connected, Loopback0
_ROUTE_RE = re.compile(
    r"^([A-Za-z][\w]?)\s*"  # protocol code (1-2 chars)
    r"([*+%p&]*)?\s*"  # optional flags after protocol
    r"(?:(IA|E[12]|N[12]|EX|L[12]|ia|su)\s+)?"  # optional type code
    r"(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s*"  # network/prefix
    r"(.*)$"  # rest of the line (may be empty for multi-line routes)
)

# Continuation next-hop line (indented, starts with [AD/metric])
# Groups: 1=AD, 2=metric, 3=next_hop_ip, 4=vrf_leak, 5=age, 6=interface
_CONTINUATION_RE = re.compile(
    r"^\s+\[(\d+)/(\d+)\]\s+via\s+"
    r"(\d+\.\d+\.\d+\.\d+)"  # next-hop IP
    r"(?:\s+\((\S+)\))?"  # optional VRF leak
    r"(?:,\s*(\S+))?"  # optional age or interface
    r"(?:,\s*(\S+))?"  # optional interface
    r"\s*$"
)

# Next-hop with [AD/metric] via IP
# Groups: 1=AD, 2=metric, 3=next_hop_ip, 4=vrf_leak, 5=age, 6=interface
_NEXTHOP_VIA_RE = re.compile(
    r"\[(\d+)/(\d+)\]\s+via\s+"
    r"(\d+\.\d+\.\d+\.\d+)"  # next-hop IP
    r"(?:\s+\((\S+)\))?"  # optional VRF leak
    r"(?:,\s*(\S+))?"  # optional age or interface
    r"(?:,\s*(\S+))?"  # optional interface
    r"\s*$"
)

# Directly connected route
_DIRECTLY_CONNECTED_RE = re.compile(
    r"is directly connected,?\s*(?:(\S+),\s*)?(\S+)\s*$"
)

# Summary route: "is a summary, AGE, INTERFACE"
_SUMMARY_RE = re.compile(r"is a summary,\s*(\S+),\s*(\S+)\s*$")

# BGP with age and interface but no "via": [AD/metric], AGE, INTERFACE
_METRIC_AGE_INTF_RE = re.compile(r"\[(\d+)/(\d+)\],?\s*(\S+),\s*(\S+)\s*$")

# Codes section detection
_CODES_RE = re.compile(r"^Codes:\s")


def _parse_flags(flag_str: str) -> dict[str, bool]:
    """Extract boolean flags from flag characters."""
    flags: dict[str, bool] = {}
    if _FLAG_CANDIDATE_DEFAULT in flag_str:
        flags["candidate_default"] = True
    if _FLAG_REPLICATED in flag_str:
        flags["replicated"] = True
    if _FLAG_NEXT_HOP_OVERRIDE in flag_str:
        flags["next_hop_override"] = True
    if _FLAG_PFR_OVERRIDE in flag_str:
        flags["pfr_override"] = True
    if _FLAG_REPLICATED_LOCAL_OVERRIDE in flag_str:
        flags["replicated_local_override"] = True
    return flags


def _normalize_prefix(network: str, last_classful: str) -> str:
    """Normalize a route prefix, applying classful mask if needed.

    When a route is listed under a subnet summary header without an explicit
    mask, we use the mask from the most recent summary header.
    """
    if "/" in network:
        return network
    # Apply the mask from the last subnet summary header
    if last_classful and "/" in last_classful:
        mask = last_classful.split("/")[1]
        return f"{network}/{mask}"
    return f"{network}/32"


def _safe_interface(name: str) -> str:
    """Normalize interface name, handling non-interface values."""
    # Some values like age strings should not be normalized
    if re.match(r"^\d+[wdhms:]", name):
        return name
    return canonical_interface_name(name, os=OS.CISCO_IOS)


def _classify_age_or_interface(token: str, hop: NextHopEntry) -> None:
    """Classify a trailing token as either an age or interface and set it on hop."""
    if re.match(r"\d+[wdhms:]|\d+:\d+", token):
        hop["age"] = token
    else:
        hop["outgoing_interface"] = _safe_interface(token)


def _set_trailing_tokens(
    hop: NextHopEntry, token1: str | None, token2: str | None
) -> None:
    """Set age and interface from one or two optional trailing tokens."""
    if token1 and token2:
        hop["age"] = token1
        hop["outgoing_interface"] = _safe_interface(token2)
    elif token1:
        _classify_age_or_interface(token1, hop)


def _parse_summary(rest: str) -> NextHopEntry | None:
    """Try to parse 'is a summary' route."""
    m = _SUMMARY_RE.search(rest)
    if not m:
        return None
    return {"age": m.group(1), "outgoing_interface": _safe_interface(m.group(2))}


def _parse_directly_connected(rest: str) -> NextHopEntry | None:
    """Try to parse 'is directly connected' route."""
    m = _DIRECTLY_CONNECTED_RE.search(rest)
    if not m:
        return None
    hop: NextHopEntry = {"outgoing_interface": _safe_interface(m.group(2))}
    if m.group(1):
        hop["age"] = m.group(1)
    return hop


def _parse_metric_no_via(rest: str) -> NextHopEntry | None:
    """Try to parse [AD/metric], AGE, INTERFACE (no 'via', e.g. BGP to Null0)."""
    if "via" in rest:
        return None
    m = _METRIC_AGE_INTF_RE.search(rest)
    if not m:
        return None
    return {
        "admin_distance": int(m.group(1)),
        "metric": int(m.group(2)),
        "age": m.group(3),
        "outgoing_interface": _safe_interface(m.group(4)),
    }


def _parse_via_nexthop(rest: str) -> NextHopEntry | None:
    """Try to parse [AD/metric] via NEXTHOP route."""
    m = _NEXTHOP_VIA_RE.search(rest)
    if not m:
        return None
    hop: NextHopEntry = {
        "admin_distance": int(m.group(1)),
        "metric": int(m.group(2)),
        "next_hop": m.group(3),
    }
    if m.group(4):
        hop["vrf_leak"] = m.group(4)
    _set_trailing_tokens(hop, m.group(5), m.group(6))
    return hop


# Ordered list of nexthop parsers to try
_NEXTHOP_PARSERS = [
    _parse_summary,
    _parse_directly_connected,
    _parse_metric_no_via,
    _parse_via_nexthop,
]


def _parse_nexthop_rest(rest: str) -> NextHopEntry:
    """Parse the rest of a route line after the prefix."""
    for parser in _NEXTHOP_PARSERS:
        result = parser(rest)
        if result is not None:
            return result
    return {}


def _parse_continuation(line: str) -> NextHopEntry | None:
    """Parse a continuation next-hop line."""
    m = _CONTINUATION_RE.match(line)
    if not m:
        return None
    hop: NextHopEntry = {
        "admin_distance": int(m.group(1)),
        "metric": int(m.group(2)),
        "next_hop": m.group(3),
    }
    if m.group(4):
        hop["vrf_leak"] = m.group(4)
    _set_trailing_tokens(hop, m.group(5), m.group(6))
    return hop


def _is_skip_line(line: str) -> bool:
    """Check if a line should be skipped (prompt, codes, empty, etc.)."""
    stripped = line.strip()
    if not stripped:
        return True
    if _CODES_RE.match(stripped):
        return True
    if _SUBNET_SUMMARY_RE.match(line):
        return True
    if _GATEWAY_RE.match(stripped) or _GATEWAY_NOT_SET_RE.match(stripped):
        return True
    if _VRF_RE.match(stripped):
        return True
    return False


def _is_codes_section(line: str) -> bool:
    """Check if line is part of the codes legend section."""
    stripped = line.strip()
    # Lines in the codes section are indented and contain " - " descriptions
    # or start with known keywords
    if stripped.startswith(
        (
            "D -",
            "N1",
            "E1",
            "i -",
            "ia",
            "o -",
            "a -",
            "+ -",
            "& -",
            "H -",
            "n -",
            "l -",
            "L -",
            "su -",
            "G -",
            "P -",
            "U -",
            "M -",
            "S -",
            "R -",
            "B -",
            "C -",
        )
    ):
        return True
    return False


def _parse_route_line(line: str) -> tuple[str, str, str | None, str, dict] | None:
    """Parse a route entry line.

    Returns (protocol_code, flags, type_code, prefix, rest_as_dict) or None.
    """
    m = _ROUTE_RE.match(line.strip())
    if not m:
        return None
    proto_code = m.group(1)
    flags = m.group(2) or ""
    type_code = m.group(3)
    prefix = m.group(4)
    rest = m.group(5)
    return proto_code, flags, type_code, prefix, {"rest": rest}


def _build_route_entry(
    proto_code: str,
    flags: str,
    type_code: str | None,
    prefix: str,
    next_hops: list[NextHopEntry],
) -> RouteEntry:
    """Build a RouteEntry dict from parsed components."""
    network, _, mask = prefix.partition("/")
    protocol = _PROTOCOL_MAP.get(proto_code, proto_code)

    entry: RouteEntry = {
        "network": network,
        "mask": mask,
        "protocol": protocol,
        "protocol_code": proto_code,
        "next_hops": next_hops,
    }

    if type_code:
        entry["type_code"] = type_code
        type_name = _TYPE_MAP.get(type_code)
        if type_name:
            entry["type"] = type_name

    flag_dict = _parse_flags(flags)
    entry.update(flag_dict)

    return entry


def _parse_gateway(line: str) -> GatewayOfLastResortEntry | None:
    """Parse gateway of last resort line."""
    m = _GATEWAY_RE.match(line.strip())
    if m:
        return {"next_hop": m.group(1), "destination": m.group(2)}
    return None


def _extract_vrf(line: str) -> str | None:
    """Extract VRF name from a routing table header line."""
    m = _VRF_RE.match(line.strip())
    if m:
        return m.group(1)
    return None


def _get_subnet_mask(line: str) -> str | None:
    """Extract the classful prefix from a subnet summary line."""
    m = re.match(r"\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+is\s+", line)
    if m:
        return m.group(1)
    return None


def _handle_summary_type(rest: str, entry: RouteEntry) -> None:
    """Set type to 'summary' if route uses 'is a summary' syntax."""
    if "is a summary" in rest:
        entry["type"] = "summary"


# Regex for detecting prompt and debug lines
_PROMPT_RE = re.compile(r".*#.*show", re.IGNORECASE)
_DEBUG_PREFIX_RE = re.compile(r"^\d+:\s+\+\+\+")


def _is_codes_line(line: str, stripped: str, in_codes: bool) -> bool | None:
    """Check if line is part of the codes legend.

    Returns True to skip, False to stop codes section, None if not codes.
    """
    if _CODES_RE.match(stripped):
        return True
    if in_codes:
        if _is_codes_section(stripped):
            return True
        if line.startswith(" ") and " - " in stripped:
            return True
        return False
    return None


class _ParseState:
    """Mutable state for the route parsing loop."""

    __slots__ = (
        "vrf",
        "gateway",
        "routes",
        "last_classful",
        "in_codes",
        "current_prefix",
    )

    def __init__(self) -> None:
        self.vrf: str = "default"
        self.gateway: GatewayOfLastResortEntry | None = None
        self.routes: dict[str, RouteEntry] = {}
        self.last_classful: str = ""
        self.in_codes: bool = False
        self.current_prefix: str | None = None


def _process_header_line(stripped: str, state: _ParseState) -> bool:
    """Process VRF, gateway, and subnet summary lines.

    Returns True if the line was consumed.
    """
    vrf_name = _extract_vrf(stripped)
    if vrf_name:
        state.vrf = vrf_name
        return True

    gw = _parse_gateway(stripped)
    if gw:
        state.gateway = gw
        return True

    if _GATEWAY_NOT_SET_RE.match(stripped):
        return True

    return False


def _process_subnet_summary(line: str, state: _ParseState) -> bool:
    """Process subnet summary header lines. Returns True if consumed."""
    if _SUBNET_SUMMARY_RE.match(line):
        mask_str = _get_subnet_mask(line)
        if mask_str:
            state.last_classful = mask_str
        return True
    return False


def _process_continuation(line: str, stripped: str, state: _ParseState) -> bool:
    """Process ECMP continuation lines. Returns True if consumed."""
    if not line.startswith(" ") or _ROUTE_RE.match(stripped):
        return False
    hop = _parse_continuation(line)
    if hop and state.current_prefix and state.current_prefix in state.routes:
        state.routes[state.current_prefix]["next_hops"].append(hop)
    return True


def _process_route(stripped: str, state: _ParseState) -> bool:
    """Process a route entry line. Returns True if consumed."""
    parsed = _parse_route_line(stripped)
    if not parsed:
        return False

    proto_code, flags, type_code, raw_prefix, rest_dict = parsed
    prefix = _normalize_prefix(raw_prefix, state.last_classful)
    rest = rest_dict["rest"]

    # Build next-hops (may be empty for multi-line routes like RIP)
    initial_hops = [_parse_nexthop_rest(rest)] if rest.strip() else []
    entry = _build_route_entry(proto_code, flags, type_code, prefix, initial_hops)
    _handle_summary_type(rest, entry)

    state.routes[prefix] = entry
    state.current_prefix = prefix
    return True


def _process_line(line: str, stripped: str, state: _ParseState) -> None:
    """Process a single non-empty, non-codes line."""
    if _PROMPT_RE.match(stripped) or _DEBUG_PREFIX_RE.match(stripped):
        return
    if _process_header_line(stripped, state):
        return
    if _process_subnet_summary(line, state):
        return
    if _process_continuation(line, stripped, state):
        return
    _process_route(stripped, state)


def _parse_routes(lines: list[str]) -> ShowIpRouteResult:
    """Parse all lines into a single VRF routing result."""
    state = _ParseState()

    for line in lines:
        stripped = line.strip()

        if not stripped:
            state.in_codes = False
            continue

        # Handle codes legend section
        codes_result = _is_codes_line(line, stripped, state.in_codes)
        if codes_result is True:
            state.in_codes = True
            continue
        if codes_result is False:
            state.in_codes = False

        _process_line(line, stripped, state)

    result: ShowIpRouteResult = {
        "vrf": state.vrf,
        "routes": state.routes,
    }
    if state.gateway:
        result["gateway_of_last_resort"] = state.gateway

    return result


@register(OS.CISCO_IOS, "show ip route")
@register(OS.CISCO_IOSXE, "show ip route")
class ShowIpRouteParser(BaseParser[ShowIpRouteResult]):
    """Parser for 'show ip route' on IOS/IOS-XE."""

    @classmethod
    def parse(cls, output: str) -> ShowIpRouteResult:
        """Parse 'show ip route' output into structured data."""
        lines = output.splitlines()
        return _parse_routes(lines)
