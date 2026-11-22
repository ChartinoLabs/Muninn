"""Parser for 'show ipv6 route' command on IOS/IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Header: "IPv6 Routing Table - {vrf} - {count} entries"
_HEADER_RE = re.compile(r"^IPv6 Routing Table\s*-\s*(\S+)\s*-\s*(\d+)\s+entries\s*$")

# Route line: protocol code(s), prefix, [AD/metric], optional tag
# Leading whitespace allowed (some VRF outputs indent route lines)
_ROUTE_RE = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9]*(?:\s+[A-Za-z][A-Za-z0-9]*)*)\s+"
    r"(\S+/\d+)\s+"
    r"\[(\d+)/(\d+)\]"
    r"(?:,\s*tag\s+(\d+))?"
)

# Via line: indented "via ..."
_VIA_RE = re.compile(r"^\s+via\s+(.+?)\s*$")


class NextHopEntry(TypedDict):
    """Schema for a single next-hop entry."""

    type: str
    next_hop: NotRequired[str]
    interface: NotRequired[str]
    next_hop_vrf: NotRequired[str]
    interface_vrf: NotRequired[str]


class RouteEntry(TypedDict):
    """Schema for a single route entry."""

    protocol: str
    network: str
    admin_distance: int
    metric: int
    tag: NotRequired[int]
    next_hops: list[NextHopEntry]


class ShowIpv6RouteResult(TypedDict):
    """Schema for 'show ipv6 route' parsed output."""

    vrf: str
    entry_count: int
    routes: dict[str, RouteEntry]


def _parse_via(via_text: str) -> NextHopEntry:
    """Parse a single 'via' line payload into a NextHopEntry."""
    entry: NextHopEntry = {"type": "via"}

    # Check for "directly connected" suffix
    if via_text.endswith(", directly connected"):
        entry["type"] = "directly connected"
        iface_part = via_text.removesuffix(", directly connected").strip()
        entry["interface"] = canonical_interface_name(iface_part, os=OS.CISCO_IOS)
        return entry

    # Check for "receive" suffix
    if via_text.endswith(", receive"):
        entry["type"] = "receive"
        iface_part = via_text.removesuffix(", receive").strip()
        entry["interface"] = canonical_interface_name(iface_part, os=OS.CISCO_IOS)
        return entry

    # Split on ", " to separate next-hop from interface
    parts = [p.strip() for p in via_text.split(", ", maxsplit=1)]

    if len(parts) == 1:
        # Only next-hop address, no interface
        _apply_next_hop(entry, parts[0])
    else:
        _apply_next_hop(entry, parts[0])
        _apply_interface(entry, parts[1])

    return entry


def _apply_next_hop(entry: NextHopEntry, raw: str) -> None:
    """Extract next-hop address and optional VRF from raw string."""
    if "%" in raw:
        addr, vrf = raw.split("%", maxsplit=1)
        entry["next_hop"] = addr
        entry["next_hop_vrf"] = vrf
    else:
        entry["next_hop"] = raw


def _apply_interface(entry: NextHopEntry, raw: str) -> None:
    """Extract interface name and optional VRF from raw string."""
    if "%" in raw:
        iface, vrf = raw.split("%", maxsplit=1)
        entry["interface"] = canonical_interface_name(iface, os=OS.CISCO_IOS)
        entry["interface_vrf"] = vrf
    else:
        entry["interface"] = canonical_interface_name(raw, os=OS.CISCO_IOS)


def _parse_header(line: str) -> tuple[str, int] | None:
    """Parse header line, returning (vrf, entry_count) or None."""
    m = _HEADER_RE.match(line)
    if m:
        return m.group(1), int(m.group(2))
    return None


def _parse_route_line(line: str) -> RouteEntry | None:
    """Parse a route line into a RouteEntry or None."""
    m = _ROUTE_RE.match(line)
    if not m:
        return None
    # Collapse whitespace in protocol code (e.g. "I1" stays, "LC" stays)
    protocol = m.group(1).replace(" ", "")
    route: RouteEntry = {
        "protocol": protocol,
        "network": m.group(2),
        "admin_distance": int(m.group(3)),
        "metric": int(m.group(4)),
        "next_hops": [],
    }
    if m.group(5) is not None:
        route["tag"] = int(m.group(5))
    return route


@register(OS.CISCO_IOS, "show ipv6 route")
@register(OS.CISCO_IOSXE, "show ipv6 route")
class ShowIpv6RouteParser(BaseParser[ShowIpv6RouteResult]):
    """Parser for 'show ipv6 route' on IOS/IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpv6RouteResult:
        """Parse 'show ipv6 route' output into structured data."""
        vrf = "default"
        entry_count = 0
        routes: dict[str, RouteEntry] = {}
        current_route: RouteEntry | None = None

        for line in output.splitlines():
            # Try header
            header = _parse_header(line)
            if header is not None:
                vrf, entry_count = header
                continue

            # Try route line
            route = _parse_route_line(line)
            if route is not None:
                current_route = route
                routes[route["network"]] = route
                continue

            # Try via line
            m = _VIA_RE.match(line)
            if m and current_route is not None:
                hop = _parse_via(m.group(1))
                current_route["next_hops"].append(hop)
                continue

        return {
            "vrf": vrf,
            "entry_count": entry_count,
            "routes": routes,
        }
