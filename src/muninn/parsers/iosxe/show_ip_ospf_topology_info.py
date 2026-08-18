"""Parser for 'show ip ospf topology-info' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_PROCESS_RE = re.compile(r"OSPF Router with ID \((\S+)\) \(Process ID (\d+)\)")
_MTID_RE = re.compile(r"Base Topology \(MTID (\d+)\)")
_TOPOLOGY_PRIORITY_RE = re.compile(r"Topology priority is (\d+)")
_MAX_METRIC_RE = re.compile(
    r"Router is (not )?originating router-LSAs with maximum metric"
)
_TRANSIT_CAPABLE_RE = re.compile(r"Number of areas transit capable is (\d+)")
_SPF_INITIAL_RE = re.compile(r"Initial SPF schedule delay (\d+) msecs")
_SPF_MIN_HOLD_RE = re.compile(
    r"Minimum hold time between two consecutive SPFs (\d+) msecs"
)
_SPF_MAX_WAIT_RE = re.compile(
    r"Maximum wait time between two consecutive SPFs (\d+) msecs"
)
_AREA_RE = re.compile(r"^\s+Area (\S+\(\d+\))\s*$")
_SPF_LAST_RE = re.compile(r"SPF algorithm last executed (.+) ago")
_SPF_EXEC_RE = re.compile(r"SPF algorithm executed (\d+) times")


class SpfTimers(TypedDict):
    """SPF timer configuration."""

    initial_delay_ms: int
    min_hold_ms: int
    max_wait_ms: int


class AreaEntry(TypedDict):
    """Schema for a single OSPF area in topology-info."""

    spf_last_executed: NotRequired[str]
    spf_executions: NotRequired[int]


class TopologyEntry(TypedDict):
    """Schema for a base topology within an OSPF process."""

    mtid: int
    topology_priority: int
    originating_max_metric: bool
    num_transit_capable_areas: int
    spf_timers: SpfTimers
    areas: NotRequired[dict[str, AreaEntry]]


class ProcessEntry(TypedDict):
    """Schema for a single OSPF process in topology-info output."""

    router_id: str
    topology: TopologyEntry


class ShowIpOspfTopologyInfoResult(TypedDict):
    """Schema for 'show ip ospf topology-info' parsed output."""

    processes: dict[str, ProcessEntry]


def _try_topology_fields(line: str, topology: dict) -> bool:
    """Attempt to parse topology-level fields from a line.

    Returns True if the line was consumed.
    """
    match = _MTID_RE.search(line)
    if match:
        topology["mtid"] = int(match.group(1))
        return True

    match = _TOPOLOGY_PRIORITY_RE.search(line)
    if match:
        topology["topology_priority"] = int(match.group(1))
        return True

    match = _MAX_METRIC_RE.search(line)
    if match:
        topology["originating_max_metric"] = match.group(1) is None
        return True

    match = _TRANSIT_CAPABLE_RE.search(line)
    if match:
        topology["num_transit_capable_areas"] = int(match.group(1))
        return True

    return False


def _try_spf_timers(line: str, topology: dict) -> bool:
    """Attempt to parse SPF timer fields from a line.

    Returns True if the line was consumed.
    """
    match = _SPF_INITIAL_RE.search(line)
    if match:
        topology.setdefault("spf_timers", {})["initial_delay_ms"] = int(match.group(1))
        return True

    match = _SPF_MIN_HOLD_RE.search(line)
    if match:
        topology.setdefault("spf_timers", {})["min_hold_ms"] = int(match.group(1))
        return True

    match = _SPF_MAX_WAIT_RE.search(line)
    if match:
        topology.setdefault("spf_timers", {})["max_wait_ms"] = int(match.group(1))
        return True

    return False


def _try_area_fields(
    line: str, areas: dict[str, dict], current_area_id: str | None
) -> str | None:
    """Attempt to parse area-level fields from a line.

    Returns the current area ID (may be updated if a new area is found).
    """
    match = _AREA_RE.match(line)
    if match:
        area_id = match.group(1)
        areas.setdefault(area_id, {})
        return area_id

    if current_area_id is not None:
        match = _SPF_LAST_RE.search(line)
        if match:
            areas[current_area_id]["spf_last_executed"] = match.group(1)
            return current_area_id

        match = _SPF_EXEC_RE.search(line)
        if match:
            areas[current_area_id]["spf_executions"] = int(match.group(1))
            return current_area_id

    return current_area_id


def _finalize_process(
    processes: dict[str, ProcessEntry],
    process_id: str | None,
    topology: dict | None,
    areas: dict[str, dict],
) -> None:
    """Finalize and store a parsed process entry."""
    if process_id is None or topology is None:
        return

    entry: dict = {
        "router_id": topology["router_id"],
        "topology": {
            "mtid": topology.get("mtid", 0),
            "topology_priority": topology["topology_priority"],
            "originating_max_metric": topology["originating_max_metric"],
            "num_transit_capable_areas": topology["num_transit_capable_areas"],
            "spf_timers": topology["spf_timers"],
        },
    }
    if areas:
        entry["topology"]["areas"] = areas

    processes[process_id] = cast(ProcessEntry, entry)


@register(OS.CISCO_IOSXE, "show ip ospf topology-info")
class ShowIpOspfTopologyInfoParser(
    BaseParser[ShowIpOspfTopologyInfoResult],
):
    """Parser for 'show ip ospf topology-info' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.OSPF})

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfTopologyInfoResult:
        """Parse show ip ospf topology-info output."""
        processes: dict[str, ProcessEntry] = {}
        current_process_id: str | None = None
        current_topology: dict | None = None
        current_area_id: str | None = None
        current_areas: dict[str, dict] = {}

        for line in output.splitlines():
            match = _PROCESS_RE.search(line)
            if match:
                _finalize_process(
                    processes,
                    current_process_id,
                    current_topology,
                    current_areas,
                )
                current_process_id = match.group(2)
                current_topology = {"router_id": match.group(1)}
                current_areas = {}
                current_area_id = None
                continue

            if current_topology is None:
                continue

            if _try_topology_fields(line, current_topology):
                continue

            if _try_spf_timers(line, current_topology):
                continue

            current_area_id = _try_area_fields(line, current_areas, current_area_id)

        _finalize_process(
            processes, current_process_id, current_topology, current_areas
        )

        if not processes:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfTopologyInfoResult, {"processes": processes})
