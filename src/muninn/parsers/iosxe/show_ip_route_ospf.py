"""Parser for 'show ip route ospf' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# --- Type code to name mapping (OSPF-specific) ---
_TYPE_MAP: dict[str, str] = {
    "E1": "external-type-1",
    "E2": "external-type-2",
    "IA": "inter-area",
    "N1": "nssa-type-1",
    "N2": "nssa-type-2",
}

# --- Regex patterns ---

_GATEWAY_NOT_SET_RE = re.compile(r"^Gateway of last resort is not set\s*$")
_GATEWAY_RE = re.compile(r"^Gateway of last resort is (\S+) to network (\S+)\s*$")

_VRF_RE = re.compile(r"^Routing Table:\s*(\S+)\s*$")

_SUBNET_SUMMARY_RE = re.compile(rf"^\s+{IPV4_ADDRESS}/\d+ is (?:variably )?subnetted")

_CODES_RE = re.compile(r"^Codes:\s")

# Route entry line for OSPF routes
# Examples:
#   O        10.0.1.0/30 [110/2] via 10.0.3.1, 2w1d, GigabitEthernet1/0/2
#   O IA     192.168.1.0/24 [110/21] via 10.0.3.1, 1d2h, Gi1/0/2
#   O E2     0.0.0.0/0 [110/1] via 10.0.3.1, 3d4h, GigabitEthernet1/0/2
_ROUTE_RE = re.compile(
    r"^O\s*"
    r"(?:(IA|E[12]|N[12])\s+)?"
    rf"({IPV4_ADDRESS}(?:/\d+)?)\s+"
    r"\[(\d+)/(\d+)\]\s+via\s+"
    rf"({IPV4_ADDRESS})"
    r"(?:,\s*(\S+))?"
    r"(?:,\s*(\S+))?"
    r"\s*$"
)

# Continuation next-hop line (indented, starts with [AD/metric])
_CONTINUATION_RE = re.compile(
    r"^\s+\[(\d+)/(\d+)\]\s+via\s+"
    rf"({IPV4_ADDRESS})"
    r"(?:,\s*(\S+))?"
    r"(?:,\s*(\S+))?"
    r"\s*$"
)


class NextHopEntry(TypedDict):
    """Schema for a single next-hop entry."""

    next_hop: str
    admin_distance: int
    metric: int
    age: NotRequired[str]
    outgoing_interface: NotRequired[str]


class RouteEntry(TypedDict):
    """Schema for a single OSPF route entry."""

    network: str
    mask: str
    type: NotRequired[str]
    type_code: NotRequired[str]
    next_hops: list[NextHopEntry]


class ShowIpRouteOspfResult(TypedDict):
    """Schema for 'show ip route ospf' parsed output."""

    vrf: str
    routes: dict[str, RouteEntry]


def _is_age_token(token: str) -> bool:
    """Check if a token looks like an age string (e.g. 2w1d, 1d2h, 00:05:35)."""
    return bool(re.match(r"\d+[wdhms:]|\d+:\d+", token))


def _safe_interface(name: str) -> str:
    """Normalize interface name via canonical_interface_name."""
    return canonical_interface_name(name, os=OS.CISCO_IOSXE)


def _set_trailing_tokens(
    hop: NextHopEntry, token1: str | None, token2: str | None
) -> None:
    """Set age and interface from one or two optional trailing tokens."""
    if token1 and token2:
        hop["age"] = token1
        hop["outgoing_interface"] = _safe_interface(token2)
    elif token1:
        if _is_age_token(token1):
            hop["age"] = token1
        else:
            hop["outgoing_interface"] = _safe_interface(token1)


def _normalize_prefix(network: str, last_classful: str) -> str:
    """Normalize a route prefix, applying classful mask if needed."""
    if "/" in network:
        return network
    if last_classful and "/" in last_classful:
        mask = last_classful.split("/")[1]
        return f"{network}/{mask}"
    return f"{network}/32"


def _is_codes_continuation(line: str) -> bool:
    """Check if a line is part of the codes legend section."""
    stripped = line.strip()
    if _CODES_RE.match(stripped):
        return True
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
    if line.startswith(" ") and " - " in stripped:
        return True
    return False


def _build_hop_from_match(m: re.Match[str]) -> NextHopEntry:
    """Build a NextHopEntry from a route or continuation regex match.

    Expects groups: (1) AD, (2) metric, (3) next_hop, (4) token1, (5) token2.
    For _ROUTE_RE the groups are offset: (3) AD, (4) metric, (5) next_hop,
    (6) token1, (7) token2 — caller must pass the correct match.
    """
    hop: NextHopEntry = {
        "next_hop": m.group(3),
        "admin_distance": int(m.group(1)),
        "metric": int(m.group(2)),
    }
    _set_trailing_tokens(hop, m.group(4), m.group(5))
    return hop


def _build_route_entry(
    route_m: re.Match[str], last_classful: str
) -> tuple[str, RouteEntry]:
    """Build a RouteEntry from a _ROUTE_RE match. Returns (prefix, entry)."""
    type_code = route_m.group(1)
    raw_prefix = route_m.group(2)
    ad = int(route_m.group(3))
    metric = int(route_m.group(4))
    next_hop_ip = route_m.group(5)
    token1 = route_m.group(6)
    token2 = route_m.group(7)

    prefix = _normalize_prefix(raw_prefix, last_classful)
    network, _, mask = prefix.partition("/")

    hop: NextHopEntry = {
        "next_hop": next_hop_ip,
        "admin_distance": ad,
        "metric": metric,
    }
    _set_trailing_tokens(hop, token1, token2)

    entry: dict[str, object] = {
        "network": network,
        "mask": mask,
        "next_hops": [hop],
    }
    if type_code:
        entry["type_code"] = type_code
        type_name = _TYPE_MAP.get(type_code)
        if type_name:
            entry["type"] = type_name

    return prefix, cast(RouteEntry, entry)


def _is_skip_line(line: str, stripped: str) -> bool:
    """Return True if the line is a gateway or subnet summary to skip."""
    if _GATEWAY_NOT_SET_RE.match(stripped) or _GATEWAY_RE.match(stripped):
        return True
    return bool(_SUBNET_SUMMARY_RE.match(line))


def _extract_classful(line: str) -> str:
    """Extract classful prefix from a subnet summary line, or empty string."""
    m = re.match(rf"\s+({IPV4_ADDRESS}/\d+)\s+is\s+", line)
    return m.group(1) if m else ""


class _ParseState:
    """Mutable state for the route parsing loop."""

    __slots__ = ("current_prefix", "in_codes", "last_classful", "routes", "vrf")

    def __init__(self) -> None:
        self.vrf: str = "default"
        self.routes: dict[str, RouteEntry] = {}
        self.last_classful: str = ""
        self.current_prefix: str | None = None
        self.in_codes: bool = False


def _try_route_or_continuation(line: str, stripped: str, state: _ParseState) -> None:
    """Try to match a route entry or continuation hop line."""
    cont_m = _CONTINUATION_RE.match(line)
    if cont_m and state.current_prefix and state.current_prefix in state.routes:
        hop = _build_hop_from_match(cont_m)
        state.routes[state.current_prefix]["next_hops"].append(hop)
        return

    route_m = _ROUTE_RE.match(stripped)
    if route_m:
        prefix, entry = _build_route_entry(route_m, state.last_classful)
        state.routes[prefix] = entry
        state.current_prefix = prefix


def _process_line(line: str, stripped: str, state: _ParseState) -> None:
    """Process a single non-empty, non-codes line."""
    vrf_m = _VRF_RE.match(stripped)
    if vrf_m:
        state.vrf = vrf_m.group(1)
        return

    if _SUBNET_SUMMARY_RE.match(line):
        state.last_classful = _extract_classful(line) or state.last_classful
        return

    if _is_skip_line(line, stripped):
        return

    _try_route_or_continuation(line, stripped, state)


def _parse_output(output: str) -> ShowIpRouteOspfResult:
    """Parse show ip route ospf output into structured data."""
    state = _ParseState()

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped:
            state.in_codes = False
            continue

        if state.in_codes or _is_codes_continuation(line):
            state.in_codes = True
            continue

        _process_line(line, stripped, state)

    return cast(ShowIpRouteOspfResult, {"vrf": state.vrf, "routes": state.routes})


@register(OS.CISCO_IOSXE, "show ip route ospf")
class ShowIpRouteOspfParser(BaseParser[ShowIpRouteOspfResult]):
    """Parser for 'show ip route ospf' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.ROUTING, ParserTag.OSPF}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpRouteOspfResult:
        """Parse 'show ip route ospf' output into structured data."""
        return _parse_output(output)
