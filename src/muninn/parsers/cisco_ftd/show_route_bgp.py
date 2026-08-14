"""Parser for 'show route bgp' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NextHopEntry(TypedDict):
    """Schema for a single next-hop entry."""

    next_hop: str
    admin_distance: int
    metric: int
    uptime: str


class RouteEntry(TypedDict):
    """Schema for a single BGP route entry."""

    code: str
    next_hops: list[NextHopEntry]


class ShowRouteBgpResult(TypedDict):
    """Schema for 'show route bgp' parsed output on Cisco FTD."""

    gateway_of_last_resort: str
    routes: dict[str, RouteEntry]


# Route line: B*  0.0.0.0 0.0.0.0 [20/0] via 172.16.2.135, 20:41:31
_ROUTE_PATTERN = re.compile(
    r"^(?P<code>B\S*)\s+"
    r"(?P<network>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mask>\d+\.\d+\.\d+\.\d+)\s+"
    r"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+"
    r"via\s+(?P<next_hop>\d+\.\d+\.\d+\.\d+),\s*"
    r"(?P<uptime>\S+)\s*$"
)

# ECMP continuation line: [20/0] via 172.16.2.134, 20:41:31
_CONTINUATION_PATTERN = re.compile(
    r"^\s+"
    r"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+"
    r"via\s+(?P<next_hop>\d+\.\d+\.\d+\.\d+),\s*"
    r"(?P<uptime>\S+)\s*$"
)

# Gateway of last resort line
_GATEWAY_PATTERN = re.compile(
    r"^Gateway of last resort is (?P<gateway>.+) to network (?P<network>\S+)$"
)


def _mask_to_prefix_length(mask: str) -> int:
    """Convert dotted-decimal subnet mask to CIDR prefix length."""
    octets = mask.split(".")
    binary = "".join(f"{int(octet):08b}" for octet in octets)
    return binary.count("1")


def _build_next_hop(match: re.Match[str]) -> NextHopEntry:
    """Build a NextHopEntry from a regex match."""
    return NextHopEntry(
        next_hop=match.group("next_hop"),
        admin_distance=int(match.group("ad")),
        metric=int(match.group("metric")),
        uptime=match.group("uptime"),
    )


@register(
    OS.CISCO_FTD, r"show route bgp\s*(?P<asn>\d*)", doc_template="show route bgp <asn>"
)
class ShowRouteBgpParser(BaseParser[ShowRouteBgpResult]):
    """Parser for 'show route bgp' on Cisco FTD.

    Parses BGP routes including ECMP paths with admin distance,
    metric, and uptime. Supports optional ASN argument.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteBgpResult:
        """Parse 'show route bgp' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BGP routing table with gateway and routes keyed by CIDR prefix.

        Raises:
            ValueError: If no BGP routes found in output.
        """
        routes: dict[str, RouteEntry] = {}
        gateway_of_last_resort = ""
        current_route_key: str | None = None

        for line in output.splitlines():
            if not line.strip():
                continue

            # Check for gateway of last resort
            gw_match = _GATEWAY_PATTERN.match(line)
            if gw_match:
                gateway_of_last_resort = gw_match.group("gateway")
                continue

            # Check for ECMP continuation line
            cont_match = _CONTINUATION_PATTERN.match(line)
            if cont_match:
                if current_route_key and current_route_key in routes:
                    routes[current_route_key]["next_hops"].append(
                        _build_next_hop(cont_match)
                    )
                continue

            # Check for route line
            route_match = _ROUTE_PATTERN.match(line)
            if route_match:
                network = route_match.group("network")
                mask = route_match.group("mask")
                prefix_len = _mask_to_prefix_length(mask)
                current_route_key = f"{network}/{prefix_len}"
                code = route_match.group("code")
                next_hop = _build_next_hop(route_match)

                if current_route_key in routes:
                    routes[current_route_key]["next_hops"].append(next_hop)
                else:
                    routes[current_route_key] = RouteEntry(
                        code=code,
                        next_hops=[next_hop],
                    )
                continue

        if not routes:
            msg = "No BGP routes found in output"
            raise ValueError(msg)

        return ShowRouteBgpResult(
            gateway_of_last_resort=gateway_of_last_resort,
            routes=routes,
        )
