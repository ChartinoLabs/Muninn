"""Parser for 'ip route show' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NextHopEntry(TypedDict):
    """Schema for a single next-hop within a route."""

    nexthop_ip: NotRequired[str]
    nexthop_if: str
    protocol: NotRequired[str]
    scope: NotRequired[str]
    src: NotRequired[str]
    metric: NotRequired[int]
    flags: NotRequired[list[str]]


class RouteEntry(TypedDict):
    """Schema for a route grouped by destination network."""

    network: str
    route_type: NotRequired[str]
    next_hops: list[NextHopEntry]


IpRouteShowResult = dict[str, RouteEntry]


# Route line pattern. Handles optional route type prefix (unreachable, blackhole,
# prohibit, broadcast, local, etc.), destination, and key-value attributes.
#
# Examples:
#   default via 10.0.0.4 dev brblue
#   10.0.0.0/24 dev brblue proto kernel scope link src 10.0.0.1
#   unreachable default metric 4278198272
#   broadcast 10.0.0.0 dev brblue proto kernel scope link src 10.0.0.1
#   local 10.0.0.1 dev brblue proto kernel scope host src 10.0.0.1
_ROUTE_TYPE_PREFIX_RE = re.compile(
    r"^(?P<route_type>unreachable|blackhole|prohibit|broadcast|local|throw|"
    r"unicast|nat|multicast)\s+"
)

_VIA_RE = re.compile(r"\bvia\s+(?P<nexthop_ip>\S+)")
_DEV_RE = re.compile(r"\bdev\s+(?P<nexthop_if>\S+)")
_PROTO_RE = re.compile(r"\bproto\s+(?P<protocol>\S+)")
_SCOPE_RE = re.compile(r"\bscope\s+(?P<scope>\S+)")
_SRC_RE = re.compile(r"\bsrc\s+(?P<src>\S+)")
_METRIC_RE = re.compile(r"\bmetric\s+(?P<metric>\d+)")

# Known trailing flags that appear without a value
_KNOWN_FLAGS = frozenset({"onlink", "linkdown", "pervasive"})


def _parse_flags(line: str) -> list[str]:
    """Extract trailing flags (onlink, linkdown, etc.) from a route line."""
    flags: list[str] = []
    for flag in _KNOWN_FLAGS:
        if re.search(rf"\b{flag}\b", line):
            flags.append(flag)
    if flags:
        flags.sort()
    return flags


def _extract_hop_attributes(remainder: str, hop: NextHopEntry) -> None:
    """Populate a NextHopEntry with attributes parsed from the route line."""
    via_match = _VIA_RE.search(remainder)
    if via_match:
        hop["nexthop_ip"] = via_match.group("nexthop_ip")

    proto_match = _PROTO_RE.search(remainder)
    if proto_match:
        hop["protocol"] = proto_match.group("protocol")

    scope_match = _SCOPE_RE.search(remainder)
    if scope_match:
        hop["scope"] = scope_match.group("scope")

    src_match = _SRC_RE.search(remainder)
    if src_match:
        hop["src"] = src_match.group("src")

    metric_match = _METRIC_RE.search(remainder)
    if metric_match:
        hop["metric"] = int(metric_match.group("metric"))

    flags = _parse_flags(remainder)
    if flags:
        hop["flags"] = flags


def _parse_route_line(line: str) -> tuple[str, str, NextHopEntry] | None:
    """Parse a single route line into (network, route_type, NextHopEntry).

    Returns None if the line cannot be parsed as a route.
    """
    stripped = line.strip()
    if not stripped:
        return None

    route_type = ""
    remainder = stripped

    # Check for route type prefix
    type_match = _ROUTE_TYPE_PREFIX_RE.match(remainder)
    if type_match:
        route_type = type_match.group("route_type")
        remainder = remainder[type_match.end() :]

    # Extract destination (first token)
    dest_match = re.match(r"(\S+)", remainder)
    if not dest_match:
        return None
    network = dest_match.group(1)

    # Extract next-hop interface (required for a valid route)
    dev_match = _DEV_RE.search(remainder)
    if not dev_match:
        # Routes like "unreachable default metric N" have no dev
        return None

    hop: NextHopEntry = {"nexthop_if": dev_match.group("nexthop_if")}
    _extract_hop_attributes(remainder, hop)

    return network, route_type, hop


@register(OS.LINUX, "ip route show")
class IpRouteShowParser(BaseParser[IpRouteShowResult]):
    """Parser for 'ip route show' command on Linux.

    Parses the kernel routing table into a dict-of-dicts keyed by
    route destination (e.g., ``"default"``, ``"10.0.0.0/24"``).
    Multiple next-hops for the same destination are aggregated into
    the ``next_hops`` list of the corresponding entry.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> IpRouteShowResult:
        """Parse 'ip route show' output on Linux.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of route entries keyed by destination network.

        Raises:
            ValueError: If no routes can be parsed from the output.
        """
        result: dict[str, RouteEntry] = {}

        for line in output.splitlines():
            parsed = _parse_route_line(line)
            if parsed is None:
                continue

            network, route_type, hop = parsed

            if network in result:
                result[network]["next_hops"].append(hop)
            else:
                entry: RouteEntry = {
                    "network": network,
                    "next_hops": [hop],
                }
                if route_type:
                    entry["route_type"] = route_type
                result[network] = entry

        if not result:
            msg = "No routes found in output"
            raise ValueError(msg)

        return cast(IpRouteShowResult, result)
