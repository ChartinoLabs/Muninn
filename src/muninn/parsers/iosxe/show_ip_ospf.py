"""Parser for 'show ip ospf' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class AreaEntry(TypedDict):
    """Schema for a single OSPF area."""

    area_type: str
    num_interfaces: int
    num_loopback_interfaces: NotRequired[int]
    authentication: NotRequired[str]
    spf_last_executed: NotRequired[str]
    spf_executions: NotRequired[int]
    num_lsa: NotRequired[int]
    lsa_checksum_sum: NotRequired[str]
    num_opaque_link_lsa: NotRequired[int]
    num_dcbitless_lsa: NotRequired[int]
    num_indication_lsa: NotRequired[int]
    num_donotage_lsa: NotRequired[int]
    flood_list_length: NotRequired[int]


class SpfTimers(TypedDict):
    """Schema for SPF timer configuration."""

    initial_delay_ms: int
    min_hold_ms: int
    max_wait_ms: int


class LsaThrottle(TypedDict):
    """Schema for LSA throttle configuration."""

    initial_delay_ms: int
    min_hold_ms: int
    max_wait_ms: int
    min_arrival_ms: int


class OspfProcessEntry(TypedDict):
    """Schema for a single OSPF process."""

    router_id: str
    vrf: NotRequired[str]
    domain_id: NotRequired[str]
    is_abr: NotRequired[bool]
    is_asbr: NotRequired[bool]
    bfd_enabled: NotRequired[bool]
    reference_bandwidth_mbps: NotRequired[int]
    spf_timers: NotRequired[SpfTimers]
    lsa_throttle: NotRequired[LsaThrottle]
    lsa_group_pacing_secs: NotRequired[int]
    num_external_lsa: NotRequired[int]
    external_lsa_checksum: NotRequired[str]
    num_opaque_as_lsa: NotRequired[int]
    num_areas: NotRequired[int]
    num_normal_areas: NotRequired[int]
    num_stub_areas: NotRequired[int]
    num_nssa_areas: NotRequired[int]
    nsf_ietf_helper: NotRequired[bool]
    nsf_cisco_helper: NotRequired[bool]
    adjacency_limit_initial: NotRequired[int]
    adjacency_limit_max: NotRequired[int]
    max_lsa_allowed: NotRequired[int]
    current_non_self_lsa: NotRequired[int]
    areas: dict[str, AreaEntry]


class ShowIpOspfResult(TypedDict):
    """Schema for 'show ip ospf' parsed output."""

    processes: dict[str, OspfProcessEntry]


_PROCESS_HEADER = re.compile(
    r'^\s*Routing Process "ospf (?P<pid>\d+)" with ID (?P<rid>\S+)'
)
_DOMAIN_ID = re.compile(
    r"^\s*Domain ID type \S+, value (?P<value>\S+)"
)
_VRF_LINE = re.compile(
    r"^\s*Connected to MPLS VPN Superbackbone, VRF (?P<vrf>\S+)"
)
_ABR_LINE = re.compile(r"^\s*It is an area border router")
_ASBR_LINE = re.compile(r"^\s*It is an autonomous system boundary router")
_BFD_LINE = re.compile(r"^\s*BFD is enabled")
_REF_BW = re.compile(
    r"^\s*Reference bandwidth unit is (?P<bw>\d+) mbps"
)
_SPF_INITIAL = re.compile(
    r"^\s*Initial SPF schedule delay (?P<val>\d+) msecs"
)
_SPF_MIN_HOLD = re.compile(
    r"^\s*Minimum hold time between two consecutive SPFs (?P<val>\d+) msecs"
)
_SPF_MAX_WAIT = re.compile(
    r"^\s*Maximum wait time between two consecutive SPFs (?P<val>\d+) msecs"
)
_LSA_INITIAL = re.compile(
    r"^\s*Initial LSA throttle delay (?P<val>\d+) msecs"
)
_LSA_MIN_HOLD = re.compile(
    r"^\s*Minimum hold time for LSA throttle (?P<val>\d+) msecs"
)
_LSA_MAX_WAIT = re.compile(
    r"^\s*Maximum wait time for LSA throttle (?P<val>\d+) msecs"
)
_LSA_MIN_ARRIVAL = re.compile(
    r"^\s*Minimum LSA arrival (?P<val>\d+) msecs"
)
_LSA_GROUP_PACING = re.compile(
    r"^\s*LSA group pacing timer (?P<val>\d+) secs"
)
_NUM_EXT_LSA = re.compile(
    r"^\s*Number of external LSA (?P<count>\d+)\. Checksum Sum (?P<cksum>\S+)"
)
_NUM_OPAQUE_AS = re.compile(
    r"^\s*Number of opaque AS LSA (?P<count>\d+)\."
)
_NUM_AREAS = re.compile(
    r"^\s*Number of areas in this router is (?P<total>\d+)\."
    r"\s+(?P<normal>\d+) normal\s+(?P<stub>\d+) stub\s+(?P<nssa>\d+) nssa"
)
_NSF_IETF = re.compile(r"^\s*IETF NSF helper support enabled")
_NSF_CISCO = re.compile(r"^\s*Cisco NSF helper support enabled")
_ADJ_LIMIT = re.compile(
    r"^\s*EXCHANGE/LOADING adjacency limit: initial (?P<init>\d+),"
    r"\s*process maximum (?P<max>\d+)"
)
_MAX_LSA = re.compile(
    r"^\s*Maximum number of non self-generated LSA allowed (?P<val>\d+)"
)
_CURRENT_LSA = re.compile(
    r"^\s*Current number of non self-generated LSA (?P<val>\d+)"
)
_AREA_HEADER = re.compile(
    r"^\s+Area (?:BACKBONE\((?P<bb>\d+)\)|(?P<id>\d+(?:\.\d+\.\d+\.\d+)?))\s*$"
)
_AREA_FALSE_POSITIVE = re.compile(
    r"^\s+Area (?:has |ranges )", re.IGNORECASE
)
_AREA_INTERFACES = re.compile(
    r"^\s*Number of interfaces in this area is (?P<count>\d+)"
    r"(?:\s+\((?P<loopback>\d+) loopback\))?"
)
_AREA_AUTH = re.compile(r"^\s*Area has (?P<auth>.+?)$")
_AREA_SPF_LAST = re.compile(
    r"^\s*SPF algorithm last executed (?P<ago>\S+) ago"
)
_AREA_SPF_COUNT = re.compile(
    r"^\s*SPF algorithm executed (?P<count>\d+) times"
)
_AREA_NUM_LSA = re.compile(
    r"^\s*Number of LSA (?P<count>\d+)\. Checksum Sum (?P<cksum>\S+)"
)
_AREA_OPAQUE_LINK = re.compile(
    r"^\s*Number of opaque link LSA (?P<count>\d+)\."
)
_AREA_DCBITLESS = re.compile(
    r"^\s*Number of DCbitless LSA (?P<count>\d+)"
)
_AREA_INDICATION = re.compile(
    r"^\s*Number of indication LSA (?P<count>\d+)"
)
_AREA_DONOTAGE = re.compile(
    r"^\s*Number of DoNotAge LSA (?P<count>\d+)"
)
_AREA_FLOOD_LIST = re.compile(
    r"^\s*Flood list length (?P<count>\d+)"
)


def _parse_area(lines: list[str], idx: int) -> tuple[AreaEntry, int]:
    """Parse an area section starting after the area header line."""
    area: AreaEntry = {"area_type": "normal", "num_interfaces": 0}
    while idx < len(lines):
        line = lines[idx]
        if _PROCESS_HEADER.match(line) or (
            _AREA_HEADER.match(line) and idx > 0
        ):
            break

        if m := _AREA_INTERFACES.match(line):
            area["num_interfaces"] = int(m.group("count"))
            if m.group("loopback"):
                area["num_loopback_interfaces"] = int(m.group("loopback"))
        elif m := _AREA_AUTH.match(line):
            area["authentication"] = m.group("auth").strip()
        elif m := _AREA_SPF_LAST.match(line):
            area["spf_last_executed"] = m.group("ago")
        elif m := _AREA_SPF_COUNT.match(line):
            area["spf_executions"] = int(m.group("count"))
        elif m := _AREA_NUM_LSA.match(line):
            area["num_lsa"] = int(m.group("count"))
            area["lsa_checksum_sum"] = m.group("cksum")
        elif m := _AREA_OPAQUE_LINK.match(line):
            area["num_opaque_link_lsa"] = int(m.group("count"))
        elif m := _AREA_DCBITLESS.match(line):
            area["num_dcbitless_lsa"] = int(m.group("count"))
        elif m := _AREA_INDICATION.match(line):
            area["num_indication_lsa"] = int(m.group("count"))
        elif m := _AREA_DONOTAGE.match(line):
            area["num_donotage_lsa"] = int(m.group("count"))
        elif m := _AREA_FLOOD_LIST.match(line):
            area["flood_list_length"] = int(m.group("count"))

        idx += 1
    return area, idx


def _parse_process(lines: list[str], idx: int, pid: str, rid: str) -> tuple[OspfProcessEntry, int]:
    """Parse a single OSPF process section."""
    proc: OspfProcessEntry = {"router_id": rid, "areas": {}}
    spf_parts: dict[str, int] = {}
    lsa_parts: dict[str, int] = {}

    idx += 1
    while idx < len(lines):
        line = lines[idx]
        if _PROCESS_HEADER.match(line):
            break

        if m := _DOMAIN_ID.match(line):
            proc["domain_id"] = m.group("value")
        elif m := _VRF_LINE.match(line):
            proc["vrf"] = m.group("vrf")
        elif _ABR_LINE.match(line):
            proc["is_abr"] = True
        elif _ASBR_LINE.match(line):
            proc["is_asbr"] = True
        elif _BFD_LINE.match(line):
            proc["bfd_enabled"] = True
        elif m := _REF_BW.match(line):
            proc["reference_bandwidth_mbps"] = int(m.group("bw"))
        elif m := _SPF_INITIAL.match(line):
            spf_parts["initial_delay_ms"] = int(m.group("val"))
        elif m := _SPF_MIN_HOLD.match(line):
            spf_parts["min_hold_ms"] = int(m.group("val"))
        elif m := _SPF_MAX_WAIT.match(line):
            spf_parts["max_wait_ms"] = int(m.group("val"))
        elif m := _LSA_INITIAL.match(line):
            lsa_parts["initial_delay_ms"] = int(m.group("val"))
        elif m := _LSA_MIN_HOLD.match(line):
            lsa_parts["min_hold_ms"] = int(m.group("val"))
        elif m := _LSA_MAX_WAIT.match(line):
            lsa_parts["max_wait_ms"] = int(m.group("val"))
        elif m := _LSA_MIN_ARRIVAL.match(line):
            lsa_parts["min_arrival_ms"] = int(m.group("val"))
        elif m := _LSA_GROUP_PACING.match(line):
            proc["lsa_group_pacing_secs"] = int(m.group("val"))
        elif m := _NUM_EXT_LSA.match(line):
            proc["num_external_lsa"] = int(m.group("count"))
            proc["external_lsa_checksum"] = m.group("cksum")
        elif m := _NUM_OPAQUE_AS.match(line):
            proc["num_opaque_as_lsa"] = int(m.group("count"))
        elif m := _NUM_AREAS.match(line):
            proc["num_areas"] = int(m.group("total"))
            proc["num_normal_areas"] = int(m.group("normal"))
            proc["num_stub_areas"] = int(m.group("stub"))
            proc["num_nssa_areas"] = int(m.group("nssa"))
        elif _NSF_IETF.match(line):
            proc["nsf_ietf_helper"] = True
        elif _NSF_CISCO.match(line):
            proc["nsf_cisco_helper"] = True
        elif m := _ADJ_LIMIT.match(line):
            proc["adjacency_limit_initial"] = int(m.group("init"))
            proc["adjacency_limit_max"] = int(m.group("max"))
        elif m := _MAX_LSA.match(line):
            proc["max_lsa_allowed"] = int(m.group("val"))
        elif m := _CURRENT_LSA.match(line):
            proc["current_non_self_lsa"] = int(m.group("val"))
        elif m := _AREA_HEADER.match(line):
            if not _AREA_FALSE_POSITIVE.match(line):
                area_id = m.group("bb") if m.group("bb") else m.group("id")
                area, idx = _parse_area(lines, idx + 1)
                proc["areas"][area_id] = area
                continue

        idx += 1

    if len(spf_parts) == 3:
        proc["spf_timers"] = SpfTimers(
            initial_delay_ms=spf_parts["initial_delay_ms"],
            min_hold_ms=spf_parts["min_hold_ms"],
            max_wait_ms=spf_parts["max_wait_ms"],
        )
    if len(lsa_parts) >= 3:
        proc["lsa_throttle"] = LsaThrottle(
            initial_delay_ms=lsa_parts["initial_delay_ms"],
            min_hold_ms=lsa_parts["min_hold_ms"],
            max_wait_ms=lsa_parts["max_wait_ms"],
            min_arrival_ms=lsa_parts.get("min_arrival_ms", 0),
        )

    return proc, idx


@register(OS.CISCO_IOSXE, "show ip ospf")
class ShowIpOspfParser(BaseParser[ShowIpOspfResult]):
    """Parser for 'show ip ospf' command.

    Parses OSPF process information including router ID, VRF, timers,
    LSA counts, and per-area details.

    Example output::

         Routing Process "ospf 1" with ID 192.0.2.2
         Start time: 00:33:53.020, Time elapsed: 4d17h
         ...
            Area BACKBONE(0)
                Number of interfaces in this area is 3 (1 loopback)
                Area has no authentication
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfResult:
        """Parse 'show ip ospf' output.

        Args:
            output: Raw CLI output from 'show ip ospf' command.

        Returns:
            Parsed OSPF process data keyed by process ID.

        Raises:
            ValueError: If no OSPF processes found.
        """
        processes: dict[str, OspfProcessEntry] = {}
        lines = output.splitlines()
        idx = 0

        while idx < len(lines):
            line = lines[idx]
            m = _PROCESS_HEADER.match(line)
            if m:
                pid = m.group("pid")
                rid = m.group("rid")
                proc, idx = _parse_process(lines, idx, pid, rid)
                processes[pid] = proc
                continue
            idx += 1

        if not processes:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return ShowIpOspfResult(processes=processes)
