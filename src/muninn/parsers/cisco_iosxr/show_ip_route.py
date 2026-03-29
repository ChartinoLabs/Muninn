"""Parser for 'show ip route' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class NextHop(TypedDict):
    """Schema for a single next-hop entry."""

    next_hop: str
    distance: NotRequired[int]
    metric: NotRequired[int]
    uptime: str
    interface: NotRequired[str]
    is_backup: bool


class Route(TypedDict):
    """Schema for a single route entry."""

    prefix: str
    mask: int
    protocol: str
    next_hops: list[NextHop]


class ShowIpRouteResult(TypedDict):
    """Schema for 'show ip route' parsed output on IOS-XR."""

    routes: dict[str, Route]


# Route with [distance/metric] via next_hop
_ROUTE_VIA_PATTERN = re.compile(
    r"^(?P<protocol>[A-Za-z][A-Za-z *]*?)\s+"
    rf"(?P<prefix>{IPV4_ADDRESS})/(?P<mask>\d{{1,2}})\s+"
    r"\[(?P<distance>\d+)/(?P<metric>\d+)\]\s+"
    r"via\s+(?P<next_hop>\S+),\s*"
    r"(?P<uptime>\S+)"
    r"(?:,\s*(?P<interface>[A-Za-z]\S+))?"
    r"(?:\s*(?P<flag>\(\S+\)))?"
    r"\s*$"
)

# Connected/local route: C/L prefix is directly connected
_ROUTE_CONNECTED_PATTERN = re.compile(
    r"^(?P<protocol>[CL])\s+"
    rf"(?P<prefix>{IPV4_ADDRESS})/(?P<mask>\d{{1,2}})\s+"
    r"is directly connected,\s*"
    r"(?P<uptime>\S+)"
    r"(?:,\s*(?P<interface>\S+))?"
    r"\s*$"
)

# Continuation next-hop line (indented, no protocol/prefix)
_CONTINUATION_PATTERN = re.compile(
    r"^\s+"
    r"\[(?P<distance>\d+)/(?P<metric>\d+)\]\s+"
    r"via\s+(?P<next_hop>\S+),\s*"
    r"(?P<uptime>\S+)"
    r"(?:,\s*(?P<interface>[A-Za-z]\S+))?"
    r"(?:\s*(?P<flag>\(\S+\)))?"
    r"\s*$"
)

# Legend continuation lines (indented descriptions of codes)
_LEGEND_CONTINUATION = re.compile(r"^\s{2,}[A-Z]\w?\s+-\s")

# Timestamp line (e.g. "Mon Jan 29 19:00:32.892 UTC")
_TIMESTAMP_PATTERN = re.compile(r"^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d")

# FRR backup path marker
_FRR_BACKUP_FLAG = "(!)"


def _has_backup_flag(match: re.Match[str]) -> bool:
    """Check if a route match has the FRR backup flag."""
    flag = match.group("flag")
    return flag == _FRR_BACKUP_FLAG if flag else False


def _build_nexthop(
    next_hop_str: str,
    uptime: str,
    *,
    distance: int | None = None,
    metric: int | None = None,
    interface: str | None = None,
    is_backup: bool = False,
) -> NextHop:
    """Build a NextHop dict, omitting optional fields."""
    nexthop: NextHop = {
        "next_hop": next_hop_str,
        "uptime": uptime,
        "is_backup": is_backup,
    }

    if distance is not None:
        nexthop["distance"] = distance
    if metric is not None:
        nexthop["metric"] = metric
    if interface is not None:
        nexthop["interface"] = interface

    return nexthop


def _nexthop_from_match(match: re.Match[str]) -> NextHop:
    """Build a NextHop from a via-style regex match."""
    interface = match.group("interface")
    return _build_nexthop(
        match.group("next_hop"),
        match.group("uptime"),
        distance=int(match.group("distance")),
        metric=int(match.group("metric")),
        interface=interface if interface else None,
        is_backup=_has_backup_flag(match),
    )


def _is_legend_line(line: str) -> bool:
    """Check if a line is part of the codes legend block."""
    return _LEGEND_CONTINUATION.match(line) is not None


def _is_skippable(line: str) -> bool:
    """Check if a line should be skipped (gateway/timestamp)."""
    if line.startswith("Gateway of last resort"):
        return True
    return _TIMESTAMP_PATTERN.match(line) is not None


def _skip_legend(line: str, in_legend: bool) -> tuple[bool, bool]:
    """Handle legend block detection and skipping.

    Returns:
        (in_legend, should_skip) tuple.
    """
    if line.startswith("Codes:"):
        return True, True
    if in_legend:
        if _is_legend_line(line):
            return True, True
        return False, False
    return False, False


def _process_continuation(
    match: re.Match[str],
    current_key: str | None,
    routes: dict[str, Route],
) -> bool:
    """Append a continuation next-hop to the current route."""
    if current_key and current_key in routes:
        nexthop = _nexthop_from_match(match)
        routes[current_key]["next_hops"].append(nexthop)
        return True
    return False


def _process_via_route(
    match: re.Match[str],
    routes: dict[str, Route],
) -> str:
    """Process a via-style route line, return route key."""
    prefix = match.group("prefix")
    mask = int(match.group("mask"))
    route_key = f"{prefix}/{mask}"
    protocol = match.group("protocol").strip()

    nexthop = _nexthop_from_match(match)

    if route_key in routes:
        routes[route_key]["next_hops"].append(nexthop)
    else:
        routes[route_key] = Route(
            prefix=prefix,
            mask=mask,
            protocol=protocol,
            next_hops=[nexthop],
        )

    return route_key


def _process_connected_route(
    match: re.Match[str],
    routes: dict[str, Route],
) -> str:
    """Process a connected/local route line, return route key."""
    prefix = match.group("prefix")
    mask = int(match.group("mask"))
    route_key = f"{prefix}/{mask}"
    protocol = match.group("protocol").strip()

    interface = match.group("interface")
    nexthop = _build_nexthop(
        "directly connected",
        match.group("uptime"),
        interface=interface if interface else None,
    )

    routes[route_key] = Route(
        prefix=prefix,
        mask=mask,
        protocol=protocol,
        next_hops=[nexthop],
    )

    return route_key


@register(OS.CISCO_IOSXR, "show ip route")
class ShowIpRouteParser(BaseParser[ShowIpRouteResult]):
    """Parser for 'show ip route' on Cisco IOS-XR.

    Parses the IPv4 routing table including connected, static,
    and dynamic protocol routes with ECMP and FRR backup paths.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    _ROUTE_VIA = _ROUTE_VIA_PATTERN
    _ROUTE_CONNECTED = _ROUTE_CONNECTED_PATTERN
    _CONTINUATION = _CONTINUATION_PATTERN

    @classmethod
    def parse(cls, output: str) -> ShowIpRouteResult:
        """Parse 'show ip route' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed routing table keyed by prefix.

        Raises:
            ValueError: If no routes found in output.
        """
        routes: dict[str, Route] = {}
        current_route_key: str | None = None
        in_legend = False

        for line in output.splitlines():
            if not line.strip():
                continue

            # Detect and skip the codes legend block
            in_legend, skip = _skip_legend(line, in_legend)
            if skip:
                continue

            if _is_skippable(line):
                continue

            # Continuation next-hop (indented)
            cont = cls._CONTINUATION.match(line)
            if cont:
                _process_continuation(cont, current_route_key, routes)
                continue

            # Via route (protocol + prefix + [dist/metric])
            via = cls._ROUTE_VIA.match(line)
            if via:
                current_route_key = _process_via_route(via, routes)
                continue

            # Connected/local route
            conn = cls._ROUTE_CONNECTED.match(line)
            if conn:
                current_route_key = _process_connected_route(conn, routes)
                continue

        if not routes:
            msg = "No routes found in output"
            raise ValueError(msg)

        return cast(ShowIpRouteResult, ShowIpRouteResult(routes=routes))
