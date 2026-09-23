"""Parsers for 'show route ipv4' commands on Cisco IOS-XR."""

from typing import ClassVar, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.cisco_iosxr._show_route_common import (
    ShowRouteDetailResult,
    ShowRouteResult,
    ShowRouteVrfAllResult,
    entry_re,
    parse_route_detail,
    parse_route_table,
    route_line_re,
)
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

_ROUTE_LINE_RE = route_line_re(IPV4_ADDRESS)
_ENTRY_RE = entry_re(IPV4_ADDRESS)


@register(OS.CISCO_IOSXR, "show route ipv4")
@register(OS.CISCO_IOSXR, r"show route vrf (?P<vrf>\S+) ipv4")
class ShowRouteIpv4Parser(BaseParser[ShowRouteResult]):
    """Parser for 'show route [vrf <vrf>] ipv4' on Cisco IOS-XR.

    Parses the IPv4 routing table keyed by prefix, including ECMP and FRR
    backup paths and the gateway of last resort. Protocol codes are kept as
    printed (``S*``, ``O*E2``, ``i L2``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteResult:
        """Parse 'show route ipv4' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed routing table keyed by prefix.

        Raises:
            ValueError: If no routes found in output.
        """
        return cast(ShowRouteResult, parse_route_table(output, _ROUTE_LINE_RE))


@register(OS.CISCO_IOSXR, "show route vrf all ipv4")
class ShowRouteVrfAllIpv4Parser(BaseParser[ShowRouteVrfAllResult]):
    """Parser for 'show route vrf all ipv4' on Cisco IOS-XR.

    Parses each ``VRF: <name>`` section into its own routing table, keyed by
    VRF name, then prefix. VRFs with no routes map to an empty ``routes``.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteVrfAllResult:
        """Parse 'show route vrf all ipv4' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Routing tables keyed by VRF name.

        Raises:
            ValueError: If no VRF sections found in output.
        """
        return cast(
            ShowRouteVrfAllResult,
            parse_route_table(output, _ROUTE_LINE_RE, vrf_all=True),
        )


@register(
    OS.CISCO_IOSXR,
    rf"show route(?: vrf (?P<vrf>\S+))? ipv4 (?P<prefix>{IPV4_ADDRESS}(?:/\d{{1,2}})?)"
    r"(?: detail)?",
    doc_template="show route [vrf <vrf>] ipv4 <prefix> [detail]",
)
class ShowRouteIpv4DetailParser(BaseParser[ShowRouteDetailResult]):
    """Parser for 'show route [vrf <vrf>] ipv4 <prefix> [detail]' on IOS-XR.

    Parses ``Routing entry for`` blocks: source protocol, distance, metric,
    tag, install time, per-path next hop / interface / FRR role, and the
    extra attributes shown with ``detail``.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteDetailResult:
        """Parse 'show route ipv4 <prefix>' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Detailed route entries keyed by prefix.

        Raises:
            ValueError: If no route entry found in output.
        """
        return cast(ShowRouteDetailResult, parse_route_detail(output, _ENTRY_RE))
