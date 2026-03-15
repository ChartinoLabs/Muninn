"""Parser for 'show ip eigrp topology' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PathEntry(TypedDict):
    """Schema for a single EIGRP path (next-hop)."""

    next_hop: str
    interface: NotRequired[str]
    reported_distance: NotRequired[int]


class TopologyEntry(TypedDict):
    """Schema for a single EIGRP topology table entry."""

    code: str
    successor_count: int
    feasible_distance: NotRequired[int]
    tag: NotRequired[int]
    paths: list[PathEntry]


class AutonomousSystemEntry(TypedDict):
    """Schema for a single EIGRP autonomous system topology section."""

    as_number: int
    router_id: str
    routes: dict[str, TopologyEntry]


class ShowIpEigrpTopologyResult(TypedDict):
    """Schema for 'show ip eigrp topology' parsed output."""

    autonomous_systems: dict[str, AutonomousSystemEntry]


# Header line identifying AS and router ID
# Matches both "IP-EIGRP Topology Table" and "EIGRP-IPv4 Topology Table"
_AS_HEADER_RE = re.compile(
    r"^(?:IP-EIGRP|EIGRP-IPv4)\s+Topology Table for AS\((\d+)\)/ID\((\S+)\)\s*$"
)

# Route prefix line: P 10.1.1.0/24, 2 successors, FD is 264448[, tag is 53471]
_ROUTE_RE = re.compile(
    r"^(?P<code>[PpAaUuQqRrSs])\s+"
    r"(?P<prefix>\S+/\d+),\s+"
    r"(?P<successors>\d+)\s+successors?,\s+"
    r"FD is (?P<fd>\S+)"
    r"(?:,\s+tag is (?P<tag>\d+))?\s*$"
)

# Via line: via <next_hop> [(<composite>/<reported>)], <interface>
_VIA_RE = re.compile(
    r"^\s*via\s+(?P<next_hop>\S+)"
    r"(?:\s+\((?P<composite>\d+)/(?P<reported>\d+)\))?"
    r"(?:,\s+(?P<interface>\S+))?\s*$"
)


def _is_noise_line(line: str) -> bool:
    """Return True if the line is a codes legend or blank."""
    if not line:
        return True
    return line.startswith("Codes:") or line.startswith("       ") and "reply" in line


def _parse_routes(lines: list[str]) -> dict[str, TopologyEntry]:
    """Parse route entries from a set of lines within one AS section."""
    routes: dict[str, TopologyEntry] = {}
    current_entry: TopologyEntry | None = None
    current_prefix: str | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        route_match = _ROUTE_RE.match(stripped)
        if route_match:
            current_prefix = route_match.group("prefix")
            fd_str = route_match.group("fd")
            current_entry = TopologyEntry(
                code=route_match.group("code"),
                successor_count=int(route_match.group("successors")),
                paths=[],
            )
            # FD can be "Inaccessible" for unreachable routes
            if fd_str != "Inaccessible":
                current_entry["feasible_distance"] = int(fd_str)
            tag_str = route_match.group("tag")
            if tag_str is not None:
                current_entry["tag"] = int(tag_str)
            routes[current_prefix] = current_entry
            continue

        via_match = _VIA_RE.match(stripped)
        if via_match and current_entry is not None:
            path: PathEntry = {"next_hop": via_match.group("next_hop")}
            reported = via_match.group("reported")
            if reported is not None:
                path["reported_distance"] = int(reported)
            interface = via_match.group("interface")
            if interface is not None:
                path["interface"] = interface
            current_entry["paths"].append(path)

    return routes


@register(OS.CISCO_IOS, "show ip eigrp topology")
class ShowIpEigrpTopologyParser(BaseParser["ShowIpEigrpTopologyResult"]):
    """Parser for 'show ip eigrp topology' command.

    Example output:
        IP-EIGRP Topology Table for AS(100)/ID(10.255.11.6)
        P 66.128.208.232/32, 2 successors, FD is 264448
                via 10.254.11.9, TenGigabitEthernet1/1
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpEigrpTopologyResult:
        """Parse 'show ip eigrp topology' output.

        Args:
            output: Raw CLI output from 'show ip eigrp topology' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        autonomous_systems: dict[str, AutonomousSystemEntry] = {}
        lines = output.splitlines()

        # Split into AS sections
        sections: list[tuple[int, str, list[str]]] = []
        current_as: int | None = None
        current_rid: str | None = None
        current_lines: list[str] = []

        for line in lines:
            stripped = line.strip()
            header_match = _AS_HEADER_RE.match(stripped)
            if header_match:
                if current_as is not None:
                    sections.append((current_as, current_rid, current_lines))  # type: ignore[arg-type]
                current_as = int(header_match.group(1))
                current_rid = header_match.group(2)
                current_lines = []
            elif current_as is not None:
                current_lines.append(line)

        if current_as is not None:
            sections.append((current_as, current_rid, current_lines))  # type: ignore[arg-type]

        for as_number, router_id, section_lines in sections:
            routes = _parse_routes(section_lines)
            as_key = str(as_number)
            autonomous_systems[as_key] = {
                "as_number": as_number,
                "router_id": router_id,
                "routes": routes,
            }

        if not autonomous_systems:
            msg = "No EIGRP topology data found in output"
            raise ValueError(msg)

        return {"autonomous_systems": autonomous_systems}
