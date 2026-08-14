"""Parser for 'show route' command on Cisco FTD.

Parses the routing table from Cisco Firepower Threat Defense devices.
Handles BGP, connected, local, and static routes including ECMP
(Equal-Cost Multi-Path) entries with multiple next-hops per prefix.
Also handles line-wrapped entries where long interface names cause
the "is directly connected" portion to wrap to the next line.
"""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class NextHopEntry(TypedDict):
    """Schema for a single next-hop entry within a route."""

    next_hop: str
    interface: NotRequired[str]
    admin_distance: NotRequired[int]
    metric: NotRequired[int]
    uptime: NotRequired[str]


class RouteEntry(TypedDict):
    """Schema for a single route entry in the routing table."""

    code: str
    next_hops: list[NextHopEntry]


class ShowRouteResult(TypedDict):
    """Schema for 'show route' parsed output on Cisco FTD."""

    gateway_of_last_resort: str | None
    routes: dict[str, RouteEntry]


def _mask_to_prefix_length(mask: str) -> int:
    """Convert a dotted-decimal subnet mask to a CIDR prefix length.

    Args:
        mask: Dotted-decimal mask string (e.g., "255.255.255.0").

    Returns:
        Integer prefix length (e.g., 24).
    """
    octets = mask.split(".")
    binary = "".join(f"{int(octet):08b}" for octet in octets)
    return binary.count("1")


# --- Regex patterns ---

# Gateway of last resort line
_GATEWAY_RE = re.compile(r"^Gateway of last resort is (\S+) to network (\S+)\s*$")
_GATEWAY_NOT_SET_RE = re.compile(r"^Gateway of last resort is not set\s*$")

# Route entry line:
# Examples:
#   B*       0.0.0.0 0.0.0.0 [20/0] via 172.16.2.135, 20:41:24
#   C        192.168.1.0 255.255.255.0 is directly connected, HA
#   L        192.168.1.1 255.255.255.255 is directly connected, HA
#   S        172.16.9.0 255.255.192.0 [1/0] is directly connected, Null0
_ROUTE_RE = re.compile(
    r"^([A-Z])(\*)?\s+"
    rf"({IPV4_ADDRESS})\s+"
    rf"({IPV4_ADDRESS})\s*"
    r"(.*)$"
)

# Continuation next-hop line (indented, starts with [AD/metric])
# Example: [20/0] via 172.16.2.134, 20:41:24
_CONTINUATION_RE = re.compile(
    r"^\s+\[(\d+)/(\d+)\]\s+via\s+"
    rf"({IPV4_ADDRESS})"
    r"(?:,\s*(\S+))?\s*$"
)

# Next-hop with [AD/metric] via IP on a route line
_VIA_NEXTHOP_RE = re.compile(
    r"\[(\d+)/(\d+)\]\s+via\s+"
    rf"({IPV4_ADDRESS})"
    r"(?:,\s*(\S+))?"
    r"\s*$"
)

# Directly connected route (with optional AD/metric prefix for static routes)
_DIRECTLY_CONNECTED_RE = re.compile(
    r"(?:\[(\d+)/(\d+)\]\s+)?is directly connected,\s*(\S+)\s*$"
)

# Wrapped continuation: indented "is directly connected, INTERFACE"
_WRAPPED_CONNECTED_RE = re.compile(r"^\s+is directly connected,\s*(\S+)\s*$")

# Codes legend detection
_CODES_RE = re.compile(r"^Codes:\s")


def _parse_gateway_line(line: str) -> str | None:
    """Extract the gateway of last resort from a gateway line.

    Returns the next-hop IP address or None if the gateway is not set.
    """
    m = _GATEWAY_RE.match(line)
    if m:
        return m.group(1)
    if _GATEWAY_NOT_SET_RE.match(line):
        return None
    return None


def _parse_route_nexthop(rest: str) -> NextHopEntry | None:
    """Parse the next-hop portion of a route entry line.

    Handles both "via" next-hops and "is directly connected" entries.
    """
    # Try "is directly connected" first
    m = _DIRECTLY_CONNECTED_RE.search(rest)
    if m:
        hop: NextHopEntry = {
            "next_hop": "directly connected",
            "interface": m.group(3),
        }
        if m.group(1) is not None:
            hop["admin_distance"] = int(m.group(1))
            hop["metric"] = int(m.group(2))
        return hop

    # Try [AD/metric] via next-hop
    m = _VIA_NEXTHOP_RE.search(rest)
    if m:
        hop = {
            "next_hop": m.group(3),
            "admin_distance": int(m.group(1)),
            "metric": int(m.group(2)),
        }
        if m.group(4):
            hop["uptime"] = m.group(4)
        return hop

    return None


def _parse_continuation_line(line: str) -> NextHopEntry | None:
    """Parse an indented ECMP continuation line."""
    m = _CONTINUATION_RE.match(line)
    if not m:
        return None
    hop: NextHopEntry = {
        "next_hop": m.group(3),
        "admin_distance": int(m.group(1)),
        "metric": int(m.group(2)),
    }
    if m.group(4):
        hop["uptime"] = m.group(4)
    return hop


def _is_codes_section_line(line: str, in_codes: bool) -> bool:
    """Determine if a line is part of the Codes legend section."""
    stripped = line.strip()
    if _CODES_RE.match(stripped):
        return True
    if in_codes and stripped and not _GATEWAY_RE.match(stripped):
        # Legend continuation lines are indented or contain " - "
        if line.startswith(" ") and " - " in stripped:
            return True
        # Lines that start with code definitions
        if stripped[0:2] in (
            "D ",
            "N1",
            "E1",
            "E2",
            "i ",
            "ia",
            "o ",
            "su",
            "SI",
            "BI",
        ):
            return True
    return False


class _ParseState:
    """Mutable state for the route parsing loop."""

    __slots__ = ("gateway", "routes", "current_prefix", "in_codes", "pending_route")

    def __init__(self) -> None:
        self.gateway: str | None = None
        self.routes: dict[str, RouteEntry] = {}
        self.current_prefix: str | None = None
        self.in_codes: bool = False
        self.pending_route: tuple[str, str] | None = None


def _handle_wrapped_line(line: str, state: _ParseState) -> bool:
    """Handle a wrapped 'is directly connected' continuation line.

    Returns True if the line was consumed.
    """
    m_wrapped = _WRAPPED_CONNECTED_RE.match(line)
    if not m_wrapped or state.pending_route is None:
        return False

    prefix_key, code = state.pending_route
    hop: NextHopEntry = {
        "next_hop": "directly connected",
        "interface": m_wrapped.group(1),
    }
    if prefix_key in state.routes:
        state.routes[prefix_key]["next_hops"].append(hop)
    else:
        state.routes[prefix_key] = {"code": code, "next_hops": [hop]}
    state.current_prefix = prefix_key
    state.pending_route = None
    return True


def _handle_continuation(line: str, stripped: str, state: _ParseState) -> bool:
    """Handle an ECMP continuation line (indented next-hop).

    Returns True if the line was consumed.
    """
    if not line.startswith(" ") or _ROUTE_RE.match(stripped):
        return False
    hop_entry = _parse_continuation_line(line)
    if hop_entry and state.current_prefix and state.current_prefix in state.routes:
        state.routes[state.current_prefix]["next_hops"].append(hop_entry)
    return True


def _handle_route_entry(stripped: str, state: _ParseState) -> bool:
    """Handle a primary route entry line.

    Returns True if the line was consumed.
    """
    m_route = _ROUTE_RE.match(stripped)
    if not m_route:
        return False

    state.pending_route = None
    code = m_route.group(1)
    if m_route.group(2):
        code = code + "*"
    network = m_route.group(3)
    mask = m_route.group(4)
    rest = m_route.group(5)

    prefix_len = _mask_to_prefix_length(mask)
    prefix_key = f"{network}/{prefix_len}"

    nexthop = _parse_route_nexthop(rest)
    if nexthop:
        if prefix_key in state.routes:
            state.routes[prefix_key]["next_hops"].append(nexthop)
        else:
            state.routes[prefix_key] = {"code": code, "next_hops": [nexthop]}
        state.current_prefix = prefix_key
    else:
        state.pending_route = (prefix_key, code)
        state.current_prefix = prefix_key

    return True


def _parse_lines(lines: list[str]) -> ShowRouteResult:
    """Parse all lines of 'show route' output into structured data."""
    state = _ParseState()

    for line in lines:
        stripped = line.strip()

        if not stripped:
            state.in_codes = False
            continue

        # Handle codes legend section
        if _is_codes_section_line(line, state.in_codes):
            state.in_codes = True
            continue
        if state.in_codes and not line.startswith(" "):
            state.in_codes = False

        # Handle gateway of last resort
        if stripped.startswith("Gateway of last resort"):
            state.gateway = _parse_gateway_line(stripped)
            continue

        # Dispatch to line-type handlers
        if _handle_wrapped_line(line, state):
            continue
        if _handle_continuation(line, stripped, state):
            continue
        _handle_route_entry(stripped, state)

    if not state.routes:
        msg = "No route entries found in output"
        raise ValueError(msg)

    return {
        "gateway_of_last_resort": state.gateway,
        "routes": state.routes,
    }


@register(OS.CISCO_FTD, "show route")
class ShowRouteParser(BaseParser["ShowRouteResult"]):
    """Parser for 'show route' command on Cisco FTD.

    Parses the FTD routing table including BGP, connected, local, and
    static routes. Supports ECMP (multiple next-hops per prefix) and
    handles line-wrapped entries for long interface names.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteResult:
        """Parse 'show route' output on Cisco FTD.

        Args:
            output: Raw CLI output from the 'show route' command.

        Returns:
            Parsed routing table with gateway of last resort and routes
            keyed by network/prefix (e.g., "172.16.1.0/28").

        Raises:
            ValueError: If no route entries are found in the output.
        """
        return _parse_lines(output.splitlines())
