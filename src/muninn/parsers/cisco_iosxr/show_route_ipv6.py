"""Parsers for 'show route ipv6' commands on Cisco IOS-XR."""

from typing import ClassVar, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.cisco_iosxr._show_route_common import (
    ShowRouteDetailResult,
    ShowRouteResult,
    entry_re,
    parse_route_detail,
    parse_route_table,
    route_line_re,
)
from muninn.registry import register
from muninn.tags import ParserTag

# Loose IPv6 address (incl. IPv4-mapped "::ffff:10.0.0.1"); requires a colon.
_IPV6_ADDRESS = r"[0-9A-Fa-f]*:[0-9A-Fa-f:.]*"

_ROUTE_LINE_RE = route_line_re(_IPV6_ADDRESS)
_ENTRY_RE = entry_re(_IPV6_ADDRESS)


@register(OS.CISCO_IOSXR, "show route ipv6")
@register(OS.CISCO_IOSXR, "show route ipv6 local-srv6")
# "vrf all" is excluded: its VRF-sectioned output needs a vrf-all parser + fixture.
@register(
    OS.CISCO_IOSXR,
    r"show route vrf (?P<vrf>(?!all\b)\S+) ipv6",
    doc_template="show route vrf <vrf> ipv6",
)
class ShowRouteIpv6Parser(BaseParser[ShowRouteResult]):
    """Parser for 'show route [vrf <vrf>] ipv6 [local-srv6]' on Cisco IOS-XR.

    Parses the IPv6 routing table keyed by prefix, including ECMP and FRR
    backup paths, SRv6 endpoint descriptions and the gateway of last resort.
    Protocol codes are kept as printed (``i*L2``, ``a*``, ``i L2``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteResult:
        """Parse 'show route ipv6' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed routing table keyed by prefix.

        Raises:
            ValueError: If no routes found in output.
        """
        return cast(ShowRouteResult, parse_route_table(output, _ROUTE_LINE_RE))


@register(
    OS.CISCO_IOSXR,
    rf"show route(?: vrf (?P<vrf>\S+))? ipv6 (?P<prefix>{_IPV6_ADDRESS}(?:/\d{{1,3}})?)"
    r"(?: detail)?",
    doc_template="show route [vrf <vrf>] ipv6 <prefix> [detail]",
)
class ShowRouteIpv6DetailParser(BaseParser[ShowRouteDetailResult]):
    """Parser for 'show route [vrf <vrf>] ipv6 <prefix> [detail]' on IOS-XR.

    Parses ``Routing entry for`` blocks: source protocol, distance, metric,
    tag, install time, per-path next hop / interface / FRR role, and the
    extra attributes shown with ``detail``.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteDetailResult:
        """Parse 'show route ipv6 <prefix>' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Detailed route entries keyed by prefix.

        Raises:
            ValueError: If no route entry found in output.
        """
        return cast(ShowRouteDetailResult, parse_route_detail(output, _ENTRY_RE))
