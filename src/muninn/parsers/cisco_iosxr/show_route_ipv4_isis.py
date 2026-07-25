"""Parser for 'show route ipv4 isis' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisNextHop(TypedDict):
    """Schema for a single IS-IS next-hop entry."""

    next_hop: str
    distance: int
    metric: int
    uptime: str
    interface: str


class IsisRoute(TypedDict):
    """Schema for a single IS-IS route entry."""

    prefix: str
    mask: int
    protocol: str
    next_hops: list[IsisNextHop]


class ShowRouteIpv4IsisResult(TypedDict):
    """Schema for 'show route ipv4 isis' parsed output on IOS-XR."""

    routes: dict[str, IsisRoute]


# IS-IS route: i L1/L2/ia/su prefix [dist/metric] via next_hop, uptime, intf
_ISIS_ROUTE_PATTERN = re.compile(
    r"^(?P<protocol>i\s+(?:L1|L2|ia|su))\s+"
    rf"(?P<prefix>{IPV4_ADDRESS})/(?P<mask>\d{{1,2}})\s+"
    r"\[(?P<distance>\d+)/(?P<metric>\d+)\]\s+"
    r"via\s+(?P<next_hop>\S+),\s*"
    r"(?P<uptime>\S+),\s*"
    r"(?P<interface>\S+)"
    r"\s*$"
)

# Continuation next-hop line (indented, no protocol/prefix)
_CONTINUATION_PATTERN = re.compile(
    r"^\s+"
    r"\[(?P<distance>\d+)/(?P<metric>\d+)\]\s+"
    r"via\s+(?P<next_hop>\S+),\s*"
    r"(?P<uptime>\S+),\s*"
    r"(?P<interface>\S+)"
    r"\s*$"
)

# Timestamp line (e.g. "Tue Jul  7 22:59:58.261 EDT")
_TIMESTAMP_PATTERN = re.compile(r"^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d")

# Trailing status line (e.g. "22:59:59.350 3 of 138 command(s) had errors")
_STATUS_LINE_PATTERN = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+of\s+\d+")


def _build_nexthop(match: re.Match[str]) -> IsisNextHop:
    """Build an IsisNextHop from a regex match."""
    return IsisNextHop(
        next_hop=match.group("next_hop"),
        distance=int(match.group("distance")),
        metric=int(match.group("metric")),
        uptime=match.group("uptime"),
        interface=canonical_interface_name(match.group("interface"), os=OS.CISCO_IOSXR),
    )


def _is_skippable(line: str) -> bool:
    """Check if a line should be skipped."""
    if _TIMESTAMP_PATTERN.match(line):
        return True
    if _STATUS_LINE_PATTERN.match(line):
        return True
    return False


def _process_continuation(
    match: re.Match[str],
    current_route_key: str | None,
    routes: dict[str, IsisRoute],
) -> None:
    """Append a continuation next-hop to the current route."""
    if current_route_key and current_route_key in routes:
        nexthop = _build_nexthop(match)
        routes[current_route_key]["next_hops"].append(nexthop)


def _process_route(
    match: re.Match[str],
    routes: dict[str, IsisRoute],
) -> str:
    """Process an IS-IS route line, returning the route key."""
    prefix = match.group("prefix")
    mask = int(match.group("mask"))
    route_key = f"{prefix}/{mask}"
    protocol = re.sub(r"\s+", " ", match.group("protocol").strip())

    nexthop = _build_nexthop(match)

    if route_key in routes:
        routes[route_key]["next_hops"].append(nexthop)
    else:
        routes[route_key] = IsisRoute(
            prefix=prefix,
            mask=mask,
            protocol=protocol,
            next_hops=[nexthop],
        )

    return route_key


@register(OS.CISCO_IOSXR, "show route ipv4 isis")
class ShowRouteIpv4IsisParser(BaseParser[ShowRouteIpv4IsisResult]):
    """Parser for 'show route ipv4 isis' on Cisco IOS-XR.

    Parses IS-IS IPv4 routes including ECMP paths with
    admin distance, metric, uptime, and outgoing interface.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.ISIS, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowRouteIpv4IsisResult:
        """Parse 'show route ipv4 isis' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IS-IS routing table keyed by prefix.

        Raises:
            ValueError: If no routes found in output.
        """
        routes: dict[str, IsisRoute] = {}
        current_route_key: str | None = None

        for line in output.splitlines():
            if not line.strip() or _is_skippable(line):
                continue

            cont = _CONTINUATION_PATTERN.match(line)
            if cont:
                _process_continuation(cont, current_route_key, routes)
                continue

            route_match = _ISIS_ROUTE_PATTERN.match(line)
            if route_match:
                current_route_key = _process_route(route_match, routes)
                continue

        if not routes:
            msg = "No IS-IS routes found in output"
            raise ValueError(msg)

        return ShowRouteIpv4IsisResult(routes=routes)
