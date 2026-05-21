"""Parser for 'show ip route vrf * summary' command on IOS-XE.

This command emits the equivalent of 'show ip route summary' once per VRF
configured on the device.  The output of each VRF block is identical in
format to 'show ip route summary', so the per-VRF parsing logic is reused
from that parser.
"""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.ios.show_ip_route_summary import (
    RouteSourceEntry,
    RoutingTableInfo,
    ShowIpRouteSummaryResult,
    TotalEntry,
    _detect_column_count,
    _parse_all_lines,
)
from muninn.registry import register
from muninn.tags import ParserTag

__all__ = ["ShowIpRouteVrfAllSummaryParser"]


class ShowIpRouteVrfAllSummaryResult(TypedDict):
    """Schema for 'show ip route vrf * summary' parsed output on IOS-XE."""

    vrfs: dict[str, ShowIpRouteSummaryResult]


# Header marking the start of a new VRF block.  The token captured here is
# treated as the VRF name (e.g. ``default``, ``Mgmt-intf``, ``BLUE``).
_VRF_BLOCK_HEADER_RE = re.compile(
    r"^IP routing table name is (?P<name>.+?)\s*(?:\([\w\d]+\))?\s*$"
)

# Trailing footer emitted on some devices, e.g.:
#   ``23:38:22.809 1 of 20 command(s) had errors``
_TRAILING_FOOTER_RE = re.compile(
    r"^\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\s+\d+\s+of\s+\d+\s+command\(s\)"
)


def _split_into_vrf_blocks(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Split output lines into ``(vrf_name, block_lines)`` tuples.

    Each block begins at an ``IP routing table name is <vrf>`` header.  Lines
    before the first such header are discarded.  Trailing diagnostic footers
    are stripped from the final block.
    """
    blocks: list[tuple[str, list[str]]] = []
    current_vrf: str | None = None
    current_lines: list[str] = []

    for line in lines:
        header_match = _VRF_BLOCK_HEADER_RE.match(line.strip())
        if header_match:
            if current_vrf is not None:
                blocks.append((current_vrf, current_lines))
            current_vrf = header_match.group("name").strip()
            current_lines = [line]
            continue
        if current_vrf is None:
            continue
        if _TRAILING_FOOTER_RE.match(line.strip()):
            continue
        current_lines.append(line)

    if current_vrf is not None:
        blocks.append((current_vrf, current_lines))

    return blocks


def _parse_vrf_block(block_lines: list[str]) -> ShowIpRouteSummaryResult:
    """Parse a single VRF block using the shared ``show ip route summary`` logic."""
    block_text = "\n".join(block_lines)
    col_count = _detect_column_count(block_text)
    routing_table: RoutingTableInfo = {}
    route_sources: dict[str, RouteSourceEntry] = {}

    total: TotalEntry | None = _parse_all_lines(
        block_lines, col_count, routing_table, route_sources
    )

    if total is None:
        msg = "No Total row found in VRF block"
        raise ValueError(msg)

    result: ShowIpRouteSummaryResult = {
        "route_sources": route_sources,
        "total": total,
    }
    if routing_table:
        result["routing_table"] = routing_table
    return result


@register(OS.CISCO_IOSXE, "show ip route vrf * summary")
class ShowIpRouteVrfAllSummaryParser(
    BaseParser["ShowIpRouteVrfAllSummaryResult"],
):
    """Parser for 'show ip route vrf * summary' on IOS-XE.

    Example output::

        IP routing table name is default (0x0)
        IP routing table maximum-paths is 32
        Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
        connected       0           3           0           336         936
        ...
        Total           3           4           0           448         2624

        IP routing table name is Mgmt-intf (0x1)
        ...

    Each VRF block is parsed using the same logic as 'show ip route summary'
    and keyed by the VRF name in the returned ``vrfs`` mapping.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.ROUTING, ParserTag.VRF},
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpRouteVrfAllSummaryResult:
        """Parse 'show ip route vrf * summary' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed data with one entry per VRF, keyed by VRF name.

        Raises:
            ValueError: If no VRF blocks are found in the output.
        """
        blocks = _split_into_vrf_blocks(output.splitlines())
        if not blocks:
            msg = "No 'IP routing table name is ...' VRF blocks found in output"
            raise ValueError(msg)

        vrfs: dict[str, ShowIpRouteSummaryResult] = {}
        for vrf_name, block_lines in blocks:
            vrfs[vrf_name] = _parse_vrf_block(block_lines)

        return {"vrfs": vrfs}
