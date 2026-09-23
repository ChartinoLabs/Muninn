"""Parser for 'show ip protocols' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, IPV4_PREFIX
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class AreaCounts(TypedDict):
    """Schema for the OSPF 'Number of areas in this router' line."""

    total: int
    normal: int
    stub: int
    nssa: int


class IncomingMetricOffset(TypedDict):
    """Schema for 'Incoming routes will have N added to metric if on list L'."""

    offset: int
    access_list: str


class NeighborEntry(TypedDict):
    """Schema for a configured neighbor (RIP address list or BGP table row)."""

    filter_in: NotRequired[str]
    filter_out: NotRequired[str]
    distribute_in: NotRequired[str]
    distribute_out: NotRequired[str]
    weight: NotRequired[str]
    route_map: NotRequired[str]


class RipInterfaceEntry(TypedDict):
    """Schema for a row of the RIP per-interface version table."""

    send_version: str
    receive_version: str
    triggered_rip: bool
    key_chain: NotRequired[str]


class OspfNetwork(TypedDict):
    """Schema for an OSPF '<network> <wildcard> area <area>' network line."""

    network: str
    wildcard: str
    area: str


class AddressSummary(TypedDict):
    """Schema for '<prefix> for <interface>' summarization lines."""

    interfaces: list[str]


class InformationSource(TypedDict):
    """Schema for a 'Routing Information Sources' row."""

    distance: int
    last_update: str


class Distance(TypedDict):
    """Schema for the 'Distance:' line."""

    default: NotRequired[int]
    external: NotRequired[int]
    internal: NotRequired[int]
    local: NotRequired[int]


class ProtocolEntry(TypedDict):
    """Schema for one 'Routing Protocol is "..."' section."""

    protocol: str
    instance: NotRequired[str]
    output_delay_milliseconds: NotRequired[int]
    outgoing_update_filter_list: NotRequired[str]
    incoming_update_filter_list: NotRequired[str]
    incoming_metric_offset: NotRequired[IncomingMetricOffset]
    sending_updates_every_seconds: NotRequired[int]
    next_update_due_seconds: NotRequired[int]
    invalid_after_seconds: NotRequired[int]
    hold_down_seconds: NotRequired[int]
    flushed_after_seconds: NotRequired[int]
    default_redistribution_metric: NotRequired[int]
    router_id: NotRequired[str]
    area_border_router: NotRequired[bool]
    as_boundary_router: NotRequired[bool]
    number_of_areas: NotRequired[AreaCounts]
    redistributing: NotRequired[list[str]]
    igp_synchronization: NotRequired[bool]
    automatic_route_summarization: NotRequired[bool]
    automatic_network_summarization: NotRequired[bool]
    neighbors: NotRequired[dict[str, NeighborEntry]]
    default_send_version: NotRequired[str]
    default_receive_version: NotRequired[str]
    interfaces: NotRequired[dict[str, RipInterfaceEntry]]
    address_summarization: NotRequired[dict[str, AddressSummary]]
    maximum_path: NotRequired[int]
    routing_for_networks: NotRequired[list[str]]
    ospf_networks: NotRequired[dict[str, OspfNetwork]]
    routing_on_interfaces_configured_explicitly: NotRequired[dict[str, list[str]]]
    passive_interfaces: NotRequired[list[str]]
    routing_information_sources: NotRequired[dict[str, InformationSource]]
    distance: NotRequired[Distance]


class ShowIpProtocolsResult(TypedDict):
    """Schema for 'show ip protocols' parsed output."""

    nsf_aware: NotRequired[bool]
    protocols: dict[str, ProtocolEntry]


_NSF_RE = re.compile(r"^\*\*\* IP Routing is NSF aware \*\*\*$")
_PROTOCOL_RE = re.compile(r'^Routing Protocol is "(?P<name>[^"]+)"$')

_OUTPUT_DELAY_RE = re.compile(
    r"^Output delay (?P<delay>\d+) milliseconds between packets$"
)
_FILTER_RE = re.compile(
    r"^(?P<dir>Outgoing|Incoming) update filter list for all interfaces is "
    r"(?P<value>.+)$"
)
_METRIC_OFFSET_RE = re.compile(
    r"^Incoming routes will have (?P<offset>\d+) added to metric if on list "
    r"(?P<acl>\S+)$"
)
_SENDING_RE = re.compile(
    r"^Sending updates every (?P<every>\d+) seconds"
    r"(?:, next due in (?P<due>\d+) seconds)?$"
)
_TIMERS_RE = re.compile(
    r"^Invalid after (?P<invalid>\d+) seconds, hold down (?P<hold>\d+), "
    r"flushed after (?P<flush>\d+)$"
)
_DEFAULT_METRIC_RE = re.compile(r"^Default redistribution metric is (?P<m>\d+)$")
_ROUTER_ID_RE = re.compile(r"^Router ID (?P<rid>\S+)$")
_ROUTER_ROLE_RE = re.compile(r"^It is an? (?P<role>.+) router$")
_AREAS_RE = re.compile(
    r"^Number of areas in this router is (?P<total>\d+)\. (?P<normal>\d+) normal "
    r"(?P<stub>\d+) stub (?P<nssa>\d+) nssa$"
)
_REDISTRIBUTING_RE = re.compile(r"^Redistributing: (?P<list>.+)$")
_IGP_SYNC_RE = re.compile(r"^IGP synchronization is (?P<state>enabled|disabled)$")
_AUTO_ROUTE_SUM_RE = re.compile(
    r"^Automatic route summarization is (?P<state>enabled|disabled)$"
)
_AUTO_NET_SUM_RE = re.compile(
    r"^Automatic network summarization is (?P<state>(?:not )?in effect)$"
)
_VERSION_CONTROL_RE = re.compile(
    r"^Default version control: send version (?P<send>.+?), "
    r"receive version (?P<recv>.+)$"
)
_MAX_PATH_RE = re.compile(r"^Maximum path: (?P<n>\d+)$")
_DISTANCE_DEFAULT_RE = re.compile(r"^Distance: \(default is (?P<d>\d+)\)$")
_DISTANCE_BGP_RE = re.compile(
    r"^Distance: external (?P<external>\d+) internal (?P<internal>\d+) "
    r"local (?P<local>\d+)$"
)
_EXPLICIT_AREA_RE = re.compile(
    r"^Routing on Interfaces Configured Explicitly \(Area (?P<area>[^)]+)\):$"
)

_SOURCE_ROW_RE = re.compile(r"^(?P<gateway>\S+)\s+(?P<distance>\d+)\s+(?P<last>\S+)$")
_OSPF_NETWORK_RE = re.compile(
    rf"^(?P<network>{IPV4_ADDRESS}) (?P<wildcard>{IPV4_ADDRESS}) area (?P<area>\S+)$"
)
_SUMMARY_ROW_RE = re.compile(rf"^(?P<prefix>{IPV4_PREFIX}) for (?P<intf>\S+)$")
_RIP_INTF_ROW_RE = re.compile(
    r"^(?P<intf>\S+)\s+(?P<send>\d(?: \d)?)\s+(?P<recv>\d(?: \d)?)\s+"
    r"(?P<trig>Yes|No)(?:\s+(?P<key>\S+))?$"
)

# Section headers that introduce an indented list of items.
_LIST_SECTIONS = {
    "Neighbor(s):": "neighbors",
    "Address Summarization:": "address_summarization",
    "Routing for Networks:": "routing_for_networks",
    "Passive Interface(s):": "passive_interfaces",
    "Routing Information Sources:": "routing_information_sources",
}

_NEIGHBOR_COLUMNS = {
    "FiltIn": "filter_in",
    "FiltOut": "filter_out",
    "DistIn": "distribute_in",
    "DistOut": "distribute_out",
    "Weight": "weight",
    "RouteMap": "route_map",
}


def _canon(name: str) -> str:
    return canonical_interface_name(name, os=OS.CISCO_IOSXE)


def _new_protocol(name: str) -> dict:
    protocol, _, instance = name.partition(" ")
    entry: dict = {"protocol": protocol}
    if instance:
        entry["instance"] = instance
    return entry


def _kv_simple(proto: dict, line: str) -> bool:
    """Handle single-value key lines; return True if the line was consumed."""
    if m := _OUTPUT_DELAY_RE.match(line):
        proto["output_delay_milliseconds"] = int(m.group("delay"))
    elif m := _FILTER_RE.match(line):
        if m.group("value") != "not set":
            key = f"{m.group('dir').lower()}_update_filter_list"
            proto[key] = m.group("value")
    elif m := _METRIC_OFFSET_RE.match(line):
        proto["incoming_metric_offset"] = {
            "offset": int(m.group("offset")),
            "access_list": m.group("acl"),
        }
    elif m := _DEFAULT_METRIC_RE.match(line):
        proto["default_redistribution_metric"] = int(m.group("m"))
    elif m := _ROUTER_ID_RE.match(line):
        proto["router_id"] = m.group("rid")
    elif m := _MAX_PATH_RE.match(line):
        proto["maximum_path"] = int(m.group("n"))
    elif m := _REDISTRIBUTING_RE.match(line):
        proto["redistributing"] = m.group("list").split(", ")
    else:
        return False
    return True


def _kv_timers(proto: dict, line: str) -> bool:
    """Handle update/timer lines; return True if the line was consumed."""
    if m := _SENDING_RE.match(line):
        proto["sending_updates_every_seconds"] = int(m.group("every"))
        if m.group("due"):
            proto["next_update_due_seconds"] = int(m.group("due"))
    elif m := _TIMERS_RE.match(line):
        proto["invalid_after_seconds"] = int(m.group("invalid"))
        proto["hold_down_seconds"] = int(m.group("hold"))
        proto["flushed_after_seconds"] = int(m.group("flush"))
    elif m := _VERSION_CONTROL_RE.match(line):
        proto["default_send_version"] = m.group("send")
        proto["default_receive_version"] = m.group("recv")
    elif m := _DISTANCE_DEFAULT_RE.match(line):
        proto["distance"] = {"default": int(m.group("d"))}
    elif m := _DISTANCE_BGP_RE.match(line):
        proto["distance"] = {k: int(v) for k, v in m.groupdict().items()}
    else:
        return False
    return True


def _kv_flags(proto: dict, line: str) -> bool:
    """Handle boolean/state lines; return True if the line was consumed."""
    if m := _ROUTER_ROLE_RE.match(line):
        role = m.group("role")
        proto["area_border_router"] = "area border" in role
        proto["as_boundary_router"] = "autonomous system boundary" in role
    elif m := _AREAS_RE.match(line):
        proto["number_of_areas"] = {k: int(v) for k, v in m.groupdict().items()}
    elif m := _IGP_SYNC_RE.match(line):
        proto["igp_synchronization"] = m.group("state") == "enabled"
    elif m := _AUTO_ROUTE_SUM_RE.match(line):
        proto["automatic_route_summarization"] = m.group("state") == "enabled"
    elif m := _AUTO_NET_SUM_RE.match(line):
        proto["automatic_network_summarization"] = m.group("state") == "in effect"
    else:
        return False
    return True


_KV_HANDLERS: tuple[Callable[[dict, str], bool], ...] = (
    _kv_simple,
    _kv_timers,
    _kv_flags,
)


class _State:
    """Mutable parse state for the current protocol section."""

    def __init__(self) -> None:
        self.proto: dict | None = None
        self.section: str | None = None
        self.area: str | None = None
        self.columns: list[tuple[int, str]] = []


def _parse_neighbor_row(state: _State, raw: str) -> None:
    proto = cast(dict, state.proto)
    tokens = list(re.finditer(r"\S+", raw))
    entry: dict = {}
    for tok in tokens[1:]:
        # Assign each value to the last column header starting at or before it.
        key = None
        for start, name in state.columns:
            if start <= tok.start():
                key = name
        if key:
            entry[key] = tok.group()
    proto.setdefault("neighbors", {})[tokens[0].group()] = entry


def _item_neighbor(state: _State, proto: dict, raw: str) -> None:
    if raw.strip().startswith("Address "):
        state.columns = [
            (m.start(), _NEIGHBOR_COLUMNS[m.group()])
            for m in re.finditer(r"\S+", raw)
            if m.group() in _NEIGHBOR_COLUMNS
        ]
    else:
        _parse_neighbor_row(state, raw)


def _item_rip_interface(state: _State, proto: dict, raw: str) -> None:
    if m := _RIP_INTF_ROW_RE.match(raw.strip()):
        row: dict = {
            "send_version": m.group("send"),
            "receive_version": m.group("recv"),
            "triggered_rip": m.group("trig") == "Yes",
        }
        if m.group("key") and m.group("key") != "none":
            row["key_chain"] = m.group("key")
        proto.setdefault("interfaces", {})[_canon(m.group("intf"))] = row


def _item_source(state: _State, proto: dict, raw: str) -> None:
    if m := _SOURCE_ROW_RE.match(raw.strip()):
        proto.setdefault("routing_information_sources", {})[m.group("gateway")] = {
            "distance": int(m.group("distance")),
            "last_update": m.group("last"),
        }


def _item_network(state: _State, proto: dict, raw: str) -> None:
    line = raw.strip()
    if m := _OSPF_NETWORK_RE.match(line):
        key = f"{m.group('network')} {m.group('wildcard')}"
        proto.setdefault("ospf_networks", {})[key] = m.groupdict()
    else:
        proto.setdefault("routing_for_networks", []).append(line)


def _item_summary(state: _State, proto: dict, raw: str) -> None:
    # Only the "<prefix> for <interface>" form is seen in real output; the
    # "None" placeholder and any other form are skipped.
    if m := _SUMMARY_ROW_RE.match(raw.strip()):
        summary = proto.setdefault("address_summarization", {})
        entry = summary.setdefault(m.group("prefix"), {"interfaces": []})
        entry["interfaces"].append(_canon(m.group("intf")))


def _item_explicit(state: _State, proto: dict, raw: str) -> None:
    explicit = proto.setdefault("routing_on_interfaces_configured_explicitly", {})
    explicit.setdefault(state.area, []).append(_canon(raw.strip()))


def _item_passive(state: _State, proto: dict, raw: str) -> None:
    proto.setdefault("passive_interfaces", []).append(_canon(raw.strip()))


_ITEM_HANDLERS: dict[str, Callable[[_State, dict, str], None]] = {
    "neighbors": _item_neighbor,
    "rip_interfaces": _item_rip_interface,
    "routing_information_sources": _item_source,
    "explicit": _item_explicit,
    "passive_interfaces": _item_passive,
    "routing_for_networks": _item_network,
    "address_summarization": _item_summary,
}


def _parse_item(state: _State, raw: str) -> None:
    """Handle a 4-space-indented item line under the current section."""
    if state.section in _ITEM_HANDLERS:
        _ITEM_HANDLERS[state.section](state, cast(dict, state.proto), raw)


def _parse_key_line(state: _State, line: str) -> None:
    """Handle a protocol-level (2-space-indented) line."""
    proto = cast(dict, state.proto)
    state.section = _LIST_SECTIONS.get(line)
    if state.section:
        return
    if m := _EXPLICIT_AREA_RE.match(line):
        state.section, state.area = "explicit", m.group("area")
        return
    for handler in _KV_HANDLERS:
        if handler(proto, line):
            break
    if line.startswith("Default version control:"):
        state.section = "rip_interfaces"


@register(OS.CISCO_IOSXE, "show ip protocols")
class ShowIpProtocolsParser(BaseParser[ShowIpProtocolsResult]):
    """Parser for 'show ip protocols' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpProtocolsResult:
        """Parse 'show ip protocols' output into per-process sections."""
        result: dict = {"protocols": {}}
        state = _State()
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            if _NSF_RE.match(line):
                result["nsf_aware"] = True
            elif m := _PROTOCOL_RE.match(line):
                state = _State()
                state.proto = _new_protocol(m.group("name"))
                result["protocols"][m.group("name")] = state.proto
            elif state.proto is None:
                continue
            elif len(raw) - len(raw.lstrip()) >= 4:
                _parse_item(state, raw)
            else:
                _parse_key_line(state, line)
        if not result["protocols"]:
            msg = "No 'Routing Protocol is' sections found"
            raise ValueError(msg)
        return cast(ShowIpProtocolsResult, result)
