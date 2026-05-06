"""Parser for 'show ip ospf' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
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
    opaque_link_lsa_checksum: NotRequired[str]
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
    min_arrival_ms: NotRequired[int]


class OspfProcessEntry(TypedDict):
    """Schema for a single OSPF process."""

    router_id: str
    vrf: NotRequired[str]
    domain_id: NotRequired[str]
    domain_id_type: NotRequired[str]
    is_abr: NotRequired[bool]
    is_asbr: NotRequired[bool]
    bfd_enabled: NotRequired[bool]
    reference_bandwidth_mbps: NotRequired[int]
    spf_timers: NotRequired[SpfTimers]
    lsa_throttle: NotRequired[LsaThrottle]
    lsa_group_pacing_secs: NotRequired[int]
    interface_flood_pacing_timer_ms: NotRequired[int]
    retransmission_pacing_timer_ms: NotRequired[int]
    incremental_spf_enabled: NotRequired[bool]
    per_prefix_distribution_enabled: NotRequired[bool]
    event_log_enabled: NotRequired[bool]
    event_log_max_events: NotRequired[int]
    event_log_mode: NotRequired[str]
    num_external_lsa: NotRequired[int]
    external_lsa_checksum: NotRequired[str]
    num_opaque_as_lsa: NotRequired[int]
    opaque_as_lsa_checksum: NotRequired[str]
    num_dcbitless_external_opaque_as_lsa: NotRequired[int]
    num_donotage_external_opaque_as_lsa: NotRequired[int]
    num_areas: NotRequired[int]
    num_normal_areas: NotRequired[int]
    num_stub_areas: NotRequired[int]
    num_nssa_areas: NotRequired[int]
    num_transit_capable_areas: NotRequired[int]
    external_flood_list_length: NotRequired[int]
    nsf_ietf_helper: NotRequired[bool]
    nsf_cisco_helper: NotRequired[bool]
    adjacency_limit_initial: NotRequired[int]
    adjacency_limit_max: NotRequired[int]
    max_lsa_allowed: NotRequired[int]
    current_non_self_lsa: NotRequired[int]
    max_lsa_warning_threshold_pct: NotRequired[int]
    max_lsa_ignore_time_mins: NotRequired[int]
    max_lsa_reset_time_mins: NotRequired[int]
    max_lsa_ignore_count_allowed: NotRequired[int]
    max_lsa_current_ignore_count: NotRequired[int]
    areas: dict[str, AreaEntry]


class ShowIpOspfResult(TypedDict):
    """Schema for 'show ip ospf' parsed output."""

    processes: dict[str, OspfProcessEntry]


_PROCESS_HEADER = re.compile(
    rf'^\s*Routing Process "ospf (?P<pid>\d+)" with ID (?P<rid>{IPV4_ADDRESS})'
)
_DOMAIN_ID = re.compile(r"^\s*Domain ID type (?P<type>\S+), value (?P<value>\S+)")
_VRF_LINE = re.compile(r"^\s*Connected to MPLS VPN Superbackbone, VRF (?P<vrf>\S+)")
_ABR_LINE = re.compile(r"^\s*It is an area border router")
_ASBR_LINE = re.compile(r"^\s*It is an autonomous system boundary router")
_BFD_LINE = re.compile(r"^\s*BFD is enabled")
_REF_BW = re.compile(r"^\s*Reference bandwidth unit is (?P<bw>\d+) mbps")
_SPF_INITIAL = re.compile(r"^\s*Initial SPF schedule delay (?P<val>\d+) msecs")
_SPF_MIN_HOLD = re.compile(
    r"^\s*Minimum hold time between two consecutive SPFs (?P<val>\d+) msecs"
)
_SPF_MAX_WAIT = re.compile(
    r"^\s*Maximum wait time between two consecutive SPFs (?P<val>\d+) msecs"
)
_LSA_INITIAL = re.compile(r"^\s*Initial LSA throttle delay (?P<val>\d+) msecs")
_LSA_MIN_HOLD = re.compile(r"^\s*Minimum hold time for LSA throttle (?P<val>\d+) msecs")
_LSA_MAX_WAIT = re.compile(r"^\s*Maximum wait time for LSA throttle (?P<val>\d+) msecs")
_LSA_MIN_ARRIVAL = re.compile(r"^\s*Minimum LSA arrival (?P<val>\d+) msecs")
_LSA_GROUP_PACING = re.compile(r"^\s*LSA group pacing timer (?P<val>\d+) secs")
_INTERFACE_FLOOD_PACING = re.compile(
    r"^\s*Interface flood pacing timer (?P<val>\d+) msecs"
)
_RETRANSMIT_PACING = re.compile(r"^\s*Retransmission pacing timer (?P<val>\d+) msecs")
_INCREMENTAL_SPF = re.compile(r"^\s*Incremental-SPF (?P<state>enabled|disabled)")
_PER_PREFIX_DIST = re.compile(
    r"^\s*Per-prefix-distribution (?P<state>enabled|disabled)"
)
_EVENT_LOG_ENABLED = re.compile(
    r"^\s*Event-log enabled, Maximum number of events:\s*(?P<max>\d+),"
    r"\s*Mode:\s*(?P<mode>\S+)"
)
_EVENT_LOG_DISABLED = re.compile(r"^\s*Event-log disabled")
_NUM_EXT_LSA = re.compile(
    r"^\s*Number of external LSA (?P<count>\d+)\. Checksum Sum (?P<cksum>\S+)"
)
_NUM_OPAQUE_AS = re.compile(
    r"^\s*Number of opaque AS LSA (?P<count>\d+)\. Checksum Sum (?P<cksum>\S+)"
)
_NUM_DCBITLESS_EXT_OPAQUE = re.compile(
    r"^\s*Number of DCbitless external and opaque AS LSA (?P<count>\d+)"
)
_NUM_DONOTAGE_EXT_OPAQUE = re.compile(
    r"^\s*Number of DoNotAge external and opaque AS LSA (?P<count>\d+)"
)
_NUM_AREAS = re.compile(
    r"^\s*Number of areas in this router is (?P<total>\d+)\."
    r"\s+(?P<normal>\d+) normal\s+(?P<stub>\d+) stub\s+(?P<nssa>\d+) nssa"
)
_NUM_AREAS_TRANSIT = re.compile(
    r"^\s*Number of areas transit capable is (?P<count>\d+)"
)
_EXT_FLOOD_LIST = re.compile(r"^\s*External flood list length (?P<count>\d+)")
_NSF_IETF = re.compile(r"^\s*IETF NSF helper support enabled")
_NSF_CISCO = re.compile(r"^\s*Cisco NSF helper support enabled")
_ADJ_LIMIT = re.compile(
    r"^\s*EXCHANGE/LOADING adjacency limit: initial (?P<init>\d+),"
    r"\s*process maximum (?P<max>\d+)"
)
_MAX_LSA = re.compile(
    r"^\s*Maximum number of non self-generated LSA allowed (?P<val>\d+)"
)
_CURRENT_LSA = re.compile(r"^\s*Current number of non self-generated LSA (?P<val>\d+)")
_MAX_LSA_THRESHOLD = re.compile(r"^\s*Threshold for warning message (?P<pct>\d+)%")
_MAX_LSA_IGNORE_TIME = re.compile(
    r"^\s*Ignore-time (?P<ignore>\d+) minutes,"
    r"\s*reset-time (?P<reset>\d+) minutes"
)
_MAX_LSA_IGNORE_COUNT = re.compile(
    r"^\s*Ignore-count allowed (?P<allowed>\d+),"
    r"\s*current ignore-count (?P<current>\d+)"
)
_AREA_HEADER = re.compile(
    r"^\s+Area (?:BACKBONE\((?P<bb>\d+)\)|(?P<id>\d+(?:\.\d+\.\d+\.\d+)?))\s*$"
)
_AREA_STUB_MARKER = re.compile(r"^\s*It is a stub area", re.IGNORECASE)
_AREA_NSSA_MARKER = re.compile(r"^\s*It is a NSSA area", re.IGNORECASE)
_AREA_INTERFACES = re.compile(
    r"^\s*Number of interfaces in this area is (?P<count>\d+)"
    r"(?:\s+\((?P<loopback>\d+) loopback\))?"
)
_AREA_AUTH = re.compile(r"^\s*Area has (?P<auth>.+?)$")
_AREA_SPF_LAST = re.compile(r"^\s*SPF algorithm last executed (?P<ago>\S+) ago")
_AREA_SPF_COUNT = re.compile(r"^\s*SPF algorithm executed (?P<count>\d+) times")
_AREA_NUM_LSA = re.compile(
    r"^\s*Number of LSA (?P<count>\d+)\. Checksum Sum (?P<cksum>\S+)"
)
_AREA_OPAQUE_LINK = re.compile(
    r"^\s*Number of opaque link LSA (?P<count>\d+)\."
    r"\s*Checksum Sum (?P<cksum>\S+)"
)
_AREA_DCBITLESS = re.compile(r"^\s*Number of DCbitless LSA (?P<count>\d+)")
_AREA_INDICATION = re.compile(r"^\s*Number of indication LSA (?P<count>\d+)")
_AREA_DONOTAGE = re.compile(r"^\s*Number of DoNotAge LSA (?P<count>\d+)")
_AREA_FLOOD_LIST = re.compile(r"^\s*Flood list length (?P<count>\d+)")


_SPF_REQUIRED: frozenset[str] = frozenset(
    {"initial_delay_ms", "min_hold_ms", "max_wait_ms"}
)
_LSA_REQUIRED: frozenset[str] = frozenset(
    {"initial_delay_ms", "min_hold_ms", "max_wait_ms"}
)


_ProcessHandler = Callable[
    [OspfProcessEntry, dict[str, int], dict[str, int], re.Match[str]],
    None,
]
_AreaHandler = Callable[[AreaEntry, re.Match[str]], None]


def _h_domain(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["domain_id"] = m.group("value")
    proc["domain_id_type"] = m.group("type")


def _h_vrf(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["vrf"] = m.group("vrf")


def _h_abr(proc: OspfProcessEntry, _sp: dict, _lp: dict, _m: re.Match) -> None:
    proc["is_abr"] = True


def _h_asbr(proc: OspfProcessEntry, _sp: dict, _lp: dict, _m: re.Match) -> None:
    proc["is_asbr"] = True


def _h_bfd(proc: OspfProcessEntry, _sp: dict, _lp: dict, _m: re.Match) -> None:
    proc["bfd_enabled"] = True


def _h_ref_bw(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["reference_bandwidth_mbps"] = int(m.group("bw"))


def _h_spf_initial(_p: OspfProcessEntry, sp: dict, _lp: dict, m: re.Match) -> None:
    sp["initial_delay_ms"] = int(m.group("val"))


def _h_spf_min_hold(_p: OspfProcessEntry, sp: dict, _lp: dict, m: re.Match) -> None:
    sp["min_hold_ms"] = int(m.group("val"))


def _h_spf_max_wait(_p: OspfProcessEntry, sp: dict, _lp: dict, m: re.Match) -> None:
    sp["max_wait_ms"] = int(m.group("val"))


def _h_lsa_initial(_p: OspfProcessEntry, _sp: dict, lp: dict, m: re.Match) -> None:
    lp["initial_delay_ms"] = int(m.group("val"))


def _h_lsa_min_hold(_p: OspfProcessEntry, _sp: dict, lp: dict, m: re.Match) -> None:
    lp["min_hold_ms"] = int(m.group("val"))


def _h_lsa_max_wait(_p: OspfProcessEntry, _sp: dict, lp: dict, m: re.Match) -> None:
    lp["max_wait_ms"] = int(m.group("val"))


def _h_lsa_min_arrival(_p: OspfProcessEntry, _sp: dict, lp: dict, m: re.Match) -> None:
    lp["min_arrival_ms"] = int(m.group("val"))


def _h_lsa_group_pacing(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["lsa_group_pacing_secs"] = int(m.group("val"))


def _h_iface_flood_pacing(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["interface_flood_pacing_timer_ms"] = int(m.group("val"))


def _h_retransmit_pacing(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["retransmission_pacing_timer_ms"] = int(m.group("val"))


def _h_incremental_spf(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["incremental_spf_enabled"] = m.group("state") == "enabled"


def _h_per_prefix_dist(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["per_prefix_distribution_enabled"] = m.group("state") == "enabled"


def _h_event_log_enabled(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["event_log_enabled"] = True
    proc["event_log_max_events"] = int(m.group("max"))
    proc["event_log_mode"] = m.group("mode")


def _h_event_log_disabled(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, _m: re.Match
) -> None:
    proc["event_log_enabled"] = False


def _h_num_ext_lsa(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["num_external_lsa"] = int(m.group("count"))
    proc["external_lsa_checksum"] = m.group("cksum")


def _h_num_opaque_as(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["num_opaque_as_lsa"] = int(m.group("count"))
    proc["opaque_as_lsa_checksum"] = m.group("cksum")


def _h_num_dcbitless_ext(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["num_dcbitless_external_opaque_as_lsa"] = int(m.group("count"))


def _h_num_donotage_ext(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["num_donotage_external_opaque_as_lsa"] = int(m.group("count"))


def _h_num_areas(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["num_areas"] = int(m.group("total"))
    proc["num_normal_areas"] = int(m.group("normal"))
    proc["num_stub_areas"] = int(m.group("stub"))
    proc["num_nssa_areas"] = int(m.group("nssa"))


def _h_num_areas_transit(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["num_transit_capable_areas"] = int(m.group("count"))


def _h_ext_flood_list(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["external_flood_list_length"] = int(m.group("count"))


def _h_nsf_ietf(proc: OspfProcessEntry, _sp: dict, _lp: dict, _m: re.Match) -> None:
    proc["nsf_ietf_helper"] = True


def _h_nsf_cisco(proc: OspfProcessEntry, _sp: dict, _lp: dict, _m: re.Match) -> None:
    proc["nsf_cisco_helper"] = True


def _h_adj_limit(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["adjacency_limit_initial"] = int(m.group("init"))
    proc["adjacency_limit_max"] = int(m.group("max"))


def _h_max_lsa(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["max_lsa_allowed"] = int(m.group("val"))


def _h_current_lsa(proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match) -> None:
    proc["current_non_self_lsa"] = int(m.group("val"))


def _h_max_lsa_threshold(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["max_lsa_warning_threshold_pct"] = int(m.group("pct"))


def _h_max_lsa_ignore_time(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["max_lsa_ignore_time_mins"] = int(m.group("ignore"))
    proc["max_lsa_reset_time_mins"] = int(m.group("reset"))


def _h_max_lsa_ignore_count(
    proc: OspfProcessEntry, _sp: dict, _lp: dict, m: re.Match
) -> None:
    proc["max_lsa_ignore_count_allowed"] = int(m.group("allowed"))
    proc["max_lsa_current_ignore_count"] = int(m.group("current"))


_PROCESS_HANDLERS: list[tuple[re.Pattern[str], _ProcessHandler]] = [
    (_DOMAIN_ID, _h_domain),
    (_VRF_LINE, _h_vrf),
    (_ABR_LINE, _h_abr),
    (_ASBR_LINE, _h_asbr),
    (_BFD_LINE, _h_bfd),
    (_REF_BW, _h_ref_bw),
    (_SPF_INITIAL, _h_spf_initial),
    (_SPF_MIN_HOLD, _h_spf_min_hold),
    (_SPF_MAX_WAIT, _h_spf_max_wait),
    (_LSA_INITIAL, _h_lsa_initial),
    (_LSA_MIN_HOLD, _h_lsa_min_hold),
    (_LSA_MAX_WAIT, _h_lsa_max_wait),
    (_LSA_MIN_ARRIVAL, _h_lsa_min_arrival),
    (_LSA_GROUP_PACING, _h_lsa_group_pacing),
    (_INTERFACE_FLOOD_PACING, _h_iface_flood_pacing),
    (_RETRANSMIT_PACING, _h_retransmit_pacing),
    (_INCREMENTAL_SPF, _h_incremental_spf),
    (_PER_PREFIX_DIST, _h_per_prefix_dist),
    (_EVENT_LOG_ENABLED, _h_event_log_enabled),
    (_EVENT_LOG_DISABLED, _h_event_log_disabled),
    (_NUM_EXT_LSA, _h_num_ext_lsa),
    (_NUM_OPAQUE_AS, _h_num_opaque_as),
    (_NUM_DCBITLESS_EXT_OPAQUE, _h_num_dcbitless_ext),
    (_NUM_DONOTAGE_EXT_OPAQUE, _h_num_donotage_ext),
    (_NUM_AREAS, _h_num_areas),
    (_NUM_AREAS_TRANSIT, _h_num_areas_transit),
    (_EXT_FLOOD_LIST, _h_ext_flood_list),
    (_NSF_IETF, _h_nsf_ietf),
    (_NSF_CISCO, _h_nsf_cisco),
    (_ADJ_LIMIT, _h_adj_limit),
    (_MAX_LSA, _h_max_lsa),
    (_CURRENT_LSA, _h_current_lsa),
    (_MAX_LSA_THRESHOLD, _h_max_lsa_threshold),
    (_MAX_LSA_IGNORE_TIME, _h_max_lsa_ignore_time),
    (_MAX_LSA_IGNORE_COUNT, _h_max_lsa_ignore_count),
]


def _ah_stub(area: AreaEntry, _m: re.Match) -> None:
    area["area_type"] = "stub"


def _ah_nssa(area: AreaEntry, _m: re.Match) -> None:
    area["area_type"] = "nssa"


def _ah_interfaces(area: AreaEntry, m: re.Match) -> None:
    area["num_interfaces"] = int(m.group("count"))
    if m.group("loopback"):
        area["num_loopback_interfaces"] = int(m.group("loopback"))


def _ah_auth(area: AreaEntry, m: re.Match) -> None:
    area["authentication"] = m.group("auth").strip()


def _ah_spf_last(area: AreaEntry, m: re.Match) -> None:
    area["spf_last_executed"] = m.group("ago")


def _ah_spf_count(area: AreaEntry, m: re.Match) -> None:
    area["spf_executions"] = int(m.group("count"))


def _ah_num_lsa(area: AreaEntry, m: re.Match) -> None:
    area["num_lsa"] = int(m.group("count"))
    area["lsa_checksum_sum"] = m.group("cksum")


def _ah_opaque_link(area: AreaEntry, m: re.Match) -> None:
    area["num_opaque_link_lsa"] = int(m.group("count"))
    area["opaque_link_lsa_checksum"] = m.group("cksum")


def _ah_dcbitless(area: AreaEntry, m: re.Match) -> None:
    area["num_dcbitless_lsa"] = int(m.group("count"))


def _ah_indication(area: AreaEntry, m: re.Match) -> None:
    area["num_indication_lsa"] = int(m.group("count"))


def _ah_donotage(area: AreaEntry, m: re.Match) -> None:
    area["num_donotage_lsa"] = int(m.group("count"))


def _ah_flood_list(area: AreaEntry, m: re.Match) -> None:
    area["flood_list_length"] = int(m.group("count"))


_AREA_HANDLERS: list[tuple[re.Pattern[str], _AreaHandler]] = [
    (_AREA_STUB_MARKER, _ah_stub),
    (_AREA_NSSA_MARKER, _ah_nssa),
    (_AREA_INTERFACES, _ah_interfaces),
    (_AREA_SPF_LAST, _ah_spf_last),
    (_AREA_SPF_COUNT, _ah_spf_count),
    (_AREA_NUM_LSA, _ah_num_lsa),
    (_AREA_OPAQUE_LINK, _ah_opaque_link),
    (_AREA_DCBITLESS, _ah_dcbitless),
    (_AREA_INDICATION, _ah_indication),
    (_AREA_DONOTAGE, _ah_donotage),
    (_AREA_FLOOD_LIST, _ah_flood_list),
    (_AREA_AUTH, _ah_auth),
]


def _dispatch_process_line(
    line: str,
    proc: OspfProcessEntry,
    spf_parts: dict[str, int],
    lsa_parts: dict[str, int],
) -> None:
    """Dispatch a process-scope line to the first matching handler."""
    for regex, handler in _PROCESS_HANDLERS:
        m = regex.match(line)
        if m:
            handler(proc, spf_parts, lsa_parts, m)
            return


def _dispatch_area_line(line: str, area: AreaEntry) -> None:
    """Dispatch an area-scope line to the first matching handler."""
    for regex, handler in _AREA_HANDLERS:
        m = regex.match(line)
        if m:
            handler(area, m)
            return


def _area_id_and_default_type(m: re.Match[str]) -> tuple[str, str]:
    """Return (area_id, default_area_type) from an area-header match."""
    bb = m.group("bb")
    if bb is not None:
        return bb, "backbone"
    return m.group("id"), "normal"


def _finalize_timers(
    proc: OspfProcessEntry,
    spf_parts: dict[str, int],
    lsa_parts: dict[str, int],
) -> None:
    """Assemble spf_timers and lsa_throttle subdicts when complete."""
    if _SPF_REQUIRED <= spf_parts.keys():
        proc["spf_timers"] = SpfTimers(
            initial_delay_ms=spf_parts["initial_delay_ms"],
            min_hold_ms=spf_parts["min_hold_ms"],
            max_wait_ms=spf_parts["max_wait_ms"],
        )
    if _LSA_REQUIRED <= lsa_parts.keys():
        throttle: LsaThrottle = {
            "initial_delay_ms": lsa_parts["initial_delay_ms"],
            "min_hold_ms": lsa_parts["min_hold_ms"],
            "max_wait_ms": lsa_parts["max_wait_ms"],
        }
        if "min_arrival_ms" in lsa_parts:
            throttle["min_arrival_ms"] = lsa_parts["min_arrival_ms"]
        proc["lsa_throttle"] = throttle


def _parse_area(
    lines: list[str], idx: int, default_area_type: str
) -> tuple[AreaEntry, int]:
    """Parse an area section starting after the area header line."""
    area: AreaEntry = {"area_type": default_area_type, "num_interfaces": 0}
    while idx < len(lines):
        line = lines[idx]
        if _PROCESS_HEADER.match(line) or _AREA_HEADER.match(line):
            break
        _dispatch_area_line(line, area)
        idx += 1
    return area, idx


def _parse_process(
    lines: list[str], idx: int, _pid: str, rid: str
) -> tuple[OspfProcessEntry, int]:
    """Parse a single OSPF process section."""
    proc: OspfProcessEntry = {"router_id": rid, "areas": {}}
    spf_parts: dict[str, int] = {}
    lsa_parts: dict[str, int] = {}

    idx += 1
    while idx < len(lines):
        line = lines[idx]
        if _PROCESS_HEADER.match(line):
            break
        area_match = _AREA_HEADER.match(line)
        if area_match:
            area_id, default_type = _area_id_and_default_type(area_match)
            area, idx = _parse_area(lines, idx + 1, default_type)
            proc["areas"][area_id] = area
            continue
        _dispatch_process_line(line, proc, spf_parts, lsa_parts)
        idx += 1

    _finalize_timers(proc, spf_parts, lsa_parts)
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
