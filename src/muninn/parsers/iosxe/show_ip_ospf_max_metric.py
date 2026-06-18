"""Parser for 'show ip ospf max-metric' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

_PROCESS_HEADER_RE = re.compile(
    rf"OSPF Router with ID \((?P<router_id>{IPV4_ADDRESS})\)"
    r" \(Process ID (?P<process_id>\d+)\)"
)
_MTID_RE = re.compile(r"Base Topology \(MTID (?P<mtid>\d+)\)")
_START_TIME_RE = re.compile(
    r"Start time:\s+(?P<start_time>\S+),\s+"
    r"Time elapsed:\s+(?P<time_elapsed>\S+)"
)
_NOT_ORIGINATING_RE = re.compile(
    r"Router is not originating router-LSAs with maximum metric"
)
_ORIGINATING_RE = re.compile(r"Router is originating router-LSAs with maximum metric")
_CONDITION_RE = re.compile(
    r"Condition:\s+(?P<condition>.+?)(?:,\s+State:\s+(?P<state>.+))?"
)
_ADVERTISE_STUB_RE = re.compile(
    r"Advertise stub links with maximum metric in router-LSAs"
)
_ADVERTISE_SUMMARY_RE = re.compile(
    r"Advertise summary-LSAs with metric (?P<metric>\d+)"
)
_ADVERTISE_EXTERNAL_RE = re.compile(
    r"Advertise external-LSAs with metric (?P<metric>\d+)"
)
_UNSET_REASON_RE = re.compile(
    r"Unset reason:\s+(?P<reason>.+?)(?:,\s+Unset time:\s+(?P<time>.+))?"
)


class TopologyEntry(TypedDict):
    """Schema for a single Base Topology (MTID) block."""

    start_time: NotRequired[str]
    time_elapsed: NotRequired[str]
    max_metric_active: bool
    condition: NotRequired[str]
    state: NotRequired[str]
    advertise_stub_links: NotRequired[bool]
    summary_lsa_metric: NotRequired[int]
    external_lsa_metric: NotRequired[int]
    unset_reason: NotRequired[str]
    unset_time: NotRequired[str]


class ProcessEntry(TypedDict):
    """Schema for a single OSPF process."""

    router_id: str
    topologies: dict[str, TopologyEntry]


ShowIpOspfMaxMetricResult = dict[str, ProcessEntry]


def _try_topology_line(line: str, topo: dict) -> bool:
    """Try to parse a single line within a topology block.

    Returns True if the line was consumed, False otherwise.
    """
    start_match = _START_TIME_RE.match(line)
    if start_match:
        topo["start_time"] = start_match.group("start_time")
        topo["time_elapsed"] = start_match.group("time_elapsed")
        return True

    if _NOT_ORIGINATING_RE.match(line):
        topo["max_metric_active"] = False
        return True

    if _ORIGINATING_RE.match(line):
        topo["max_metric_active"] = True
        return True

    cond_match = _CONDITION_RE.match(line)
    if cond_match:
        topo["condition"] = cond_match.group("condition")
        if cond_match.group("state"):
            topo["state"] = cond_match.group("state")
        return True

    return _try_advertise_line(line, topo)


def _try_advertise_line(line: str, topo: dict) -> bool:
    """Try to parse advertise and unset lines within a topology block."""
    if _ADVERTISE_STUB_RE.match(line):
        topo["advertise_stub_links"] = True
        return True

    summary_match = _ADVERTISE_SUMMARY_RE.match(line)
    if summary_match:
        topo["summary_lsa_metric"] = int(summary_match.group("metric"))
        return True

    external_match = _ADVERTISE_EXTERNAL_RE.match(line)
    if external_match:
        topo["external_lsa_metric"] = int(external_match.group("metric"))
        return True

    unset_match = _UNSET_REASON_RE.match(line)
    if unset_match:
        topo["unset_reason"] = unset_match.group("reason")
        if unset_match.group("time"):
            topo["unset_time"] = unset_match.group("time")
        return True

    return False


def _finalize_process(
    result: dict[str, ProcessEntry],
    process: dict | None,
    process_id: str | None,
    topo: dict | None,
    mtid: str | None,
) -> None:
    """Finalize the current process by saving the last topology."""
    if process is None or process_id is None:
        return
    if topo is not None and mtid is not None:
        process["topologies"][mtid] = topo
    result[process_id] = cast(ProcessEntry, process)


def _parse_output(output: str) -> ShowIpOspfMaxMetricResult:
    """Parse show ip ospf max-metric output into structured data."""
    result: dict[str, ProcessEntry] = {}
    current_process: dict | None = None
    current_process_id: str | None = None
    current_topo: dict | None = None
    current_mtid: str | None = None

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        process_match = _PROCESS_HEADER_RE.search(stripped)
        if process_match:
            _finalize_process(
                result,
                current_process,
                current_process_id,
                current_topo,
                current_mtid,
            )
            current_process_id = process_match.group("process_id")
            current_process = {
                "router_id": process_match.group("router_id"),
                "topologies": {},
            }
            current_topo = None
            current_mtid = None
            continue

        if current_process is None:
            continue

        mtid_match = _MTID_RE.search(stripped)
        if mtid_match:
            if current_topo is not None and current_mtid is not None:
                current_process["topologies"][current_mtid] = current_topo
            current_mtid = mtid_match.group("mtid")
            current_topo = {"max_metric_active": False}
            continue

        if current_topo is not None:
            _try_topology_line(stripped, current_topo)

    _finalize_process(
        result,
        current_process,
        current_process_id,
        current_topo,
        current_mtid,
    )

    if not result:
        msg = "No OSPF process information found in output"
        raise ValueError(msg)

    return cast(ShowIpOspfMaxMetricResult, result)


@register(OS.CISCO_IOSXE, "show ip ospf max-metric")
class ShowIpOspfMaxMetricParser(BaseParser[ShowIpOspfMaxMetricResult]):
    """Parser for 'show ip ospf max-metric' on IOS-XE.

    Parses max-metric status per OSPF process and topology.
    Output is keyed by process ID (string).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.OSPF})

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfMaxMetricResult:
        """Parse 'show ip ospf max-metric' output."""
        return _parse_output(output)
