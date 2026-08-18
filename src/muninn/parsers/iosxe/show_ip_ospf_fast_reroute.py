"""Parser for 'show ip ospf fast-reroute' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

# Header line: OSPF Router with ID (X.X.X.X) (Process ID N)
_PROCESS_HEADER_RE = re.compile(
    rf"OSPF Router with ID \((?P<router_id>{IPV4_ADDRESS})\)"
    r" \(Process ID (?P<process_id>\d+)\)"
)

# Status line when LFA FRR is not configured
_NOT_CONFIGURED_RE = re.compile(r"^\s*Loop-free Fast Reroute not configured\.\s*$")

# Area section header
_AREA_RE = re.compile(r"^\s*Area (?P<area>\S+)\s*$")

# Topology name line
_TOPOLOGY_RE = re.compile(r"^\s*Topology name:\s*(?P<topology>\S+)\s*$")

# Tiebreaker line: name (index) Enabled|Disabled
_TIEBREAKER_RE = re.compile(
    r"^\s*(?P<name>\S+)\s*\((?P<index>\d+)\)\s+"
    r"(?P<state>Enabled|Disabled)\s*$"
)


class TiebreakerEntry(TypedDict):
    """Schema for a single LFA tiebreaker."""

    index: int
    enabled: bool


class AreaFrrEntry(TypedDict):
    """Schema for per-area fast-reroute configuration."""

    topology: NotRequired[str]
    tiebreakers: NotRequired[dict[str, TiebreakerEntry]]


class ProcessEntry(TypedDict):
    """Schema for a single OSPF process fast-reroute state."""

    router_id: str
    configured: bool
    areas: NotRequired[dict[str, AreaFrrEntry]]


class ShowIpOspfFastRerouteResult(TypedDict):
    """Schema for 'show ip ospf fast-reroute' parsed output."""

    processes: dict[str, ProcessEntry]


def _try_area_detail(
    line: str,
    current_area: str | None,
    current_areas: dict[str, AreaFrrEntry],
) -> tuple[str | None, bool]:
    """Try to parse area, topology, or tiebreaker lines.

    Returns:
        Tuple of (updated current_area, whether the line was consumed).
    """
    area_match = _AREA_RE.match(line)
    if area_match:
        area = area_match.group("area")
        current_areas[area] = {}
        return area, True

    if current_area is None:
        return None, False

    topo_match = _TOPOLOGY_RE.match(line)
    if topo_match:
        current_areas[current_area]["topology"] = topo_match.group("topology")
        return current_area, True

    tb_match = _TIEBREAKER_RE.match(line)
    if tb_match:
        tiebreakers = current_areas[current_area].setdefault("tiebreakers", {})
        tiebreakers[tb_match.group("name")] = {
            "index": int(tb_match.group("index")),
            "enabled": tb_match.group("state") == "Enabled",
        }
        return current_area, True

    return current_area, False


def _finalize_process(
    processes: dict[str, ProcessEntry],
    pid: str,
    configured: bool,
    areas: dict[str, AreaFrrEntry],
) -> None:
    """Finalize a process entry with its configured state and areas."""
    entry = processes[pid]
    entry["configured"] = configured
    if areas:
        entry["areas"] = areas


@register(OS.CISCO_IOSXE, "show ip ospf fast-reroute")
class ShowIpOspfFastRerouteParser(
    BaseParser[ShowIpOspfFastRerouteResult],
):
    """Parser for 'show ip ospf fast-reroute' on IOS-XE.

    Parses the OSPF Loop-Free Alternate (LFA) Fast Reroute status
    for each OSPF process, including per-area tiebreaker configuration
    when LFA FRR is enabled.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfFastRerouteResult:
        """Parse 'show ip ospf fast-reroute' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed OSPF fast-reroute state keyed by process ID.
        """
        processes: dict[str, ProcessEntry] = {}
        current_pid: str | None = None
        current_area: str | None = None
        current_areas: dict[str, AreaFrrEntry] = {}
        configured = False

        for line in output.splitlines():
            header_match = _PROCESS_HEADER_RE.search(line)
            if header_match:
                if current_pid is not None:
                    _finalize_process(processes, current_pid, configured, current_areas)
                current_pid = header_match.group("process_id")
                processes[current_pid] = {
                    "router_id": header_match.group("router_id"),
                    "configured": False,
                }
                current_area = None
                current_areas = {}
                configured = False
                continue

            if current_pid is None:
                continue

            if _NOT_CONFIGURED_RE.match(line):
                continue

            current_area, consumed = _try_area_detail(line, current_area, current_areas)
            if consumed:
                configured = True

        if current_pid is not None:
            _finalize_process(processes, current_pid, configured, current_areas)

        return cast(ShowIpOspfFastRerouteResult, {"processes": processes})
