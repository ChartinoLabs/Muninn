"""Parser for 'show ospf interface' command on Cisco IOS-XR."""

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


class LabelStackEntry(TypedDict):
    """Segment-routing label stack for an interface."""

    primary_label: int
    backup_label: int
    srte_label: int


class NeighborEntry(TypedDict):
    """Adjacent OSPF neighbor on an interface (keyed by router ID)."""


class AuthenticationEntry(TypedDict):
    """OSPF authentication configuration."""

    type: str
    key_id: NotRequired[int]


class TtlSecurityEntry(TypedDict):
    """TTL security configuration."""

    enabled: bool
    hops: int


class FloodStatsEntry(TypedDict):
    """Flood queue and scan statistics."""

    index: str
    queue_length: int
    next: NotRequired[str]
    last_scan_length: NotRequired[int]
    max_scan_length: NotRequired[int]
    last_scan_time_msec: NotRequired[int]
    max_scan_time_msec: NotRequired[int]


class LsAckListEntry(TypedDict):
    """Link-state acknowledgement list statistics."""

    current_length: int
    high_water_mark: int


class OspfInterfaceEntry(TypedDict):
    """Schema for a single OSPF interface."""

    status: str
    line_protocol: str
    ip_address: str
    area: str
    router_id: str
    network_type: str
    cost: NotRequired[int]
    sid: NotRequired[int]
    strict_spf_sid: NotRequired[int]
    label_stack: NotRequired[LabelStackEntry]
    auto_path_capability: NotRequired[bool]
    stub_host: NotRequired[bool]
    igp_shortcut: NotRequired[str]
    ldp_sync_enabled: NotRequired[bool]
    ldp_sync_status: NotRequired[str]
    transmit_delay: NotRequired[int]
    state: NotRequired[str]
    priority: NotRequired[int]
    mtu: NotRequired[int]
    max_packet_size: NotRequired[int]
    forward_reference: NotRequired[bool]
    unnumbered: NotRequired[bool]
    bandwidth: NotRequired[int]
    bfd_enabled: NotRequired[bool]
    bfd_interval_msec: NotRequired[int]
    bfd_multiplier: NotRequired[int]
    bfd_mode: NotRequired[str]
    rib_lc_sync: NotRequired[bool]
    ttl_security: NotRequired[TtlSecurityEntry]
    hello_interval: NotRequired[int]
    dead_interval: NotRequired[int]
    wait_interval: NotRequired[int]
    retransmit_interval: NotRequired[int]
    nsf_enabled: NotRequired[bool]
    hello_due_in: NotRequired[str]
    passive: NotRequired[bool]
    flood_stats: NotRequired[FloodStatsEntry]
    ls_ack_list: NotRequired[LsAckListEntry]
    neighbor_count: NotRequired[int]
    adjacent_neighbor_count: NotRequired[int]
    neighbors: NotRequired[dict[str, NeighborEntry]]
    suppress_hello_count: NotRequired[int]
    authentication: NotRequired[AuthenticationEntry]
    multi_area_interface_count: NotRequired[int]
    sr_mpls_forwarding_enabled: NotRequired[bool]
    adjacency_hold_timer_expired_last: NotRequired[str]
    exchange_timer_expired_last: NotRequired[str]


class OspfProcessEntry(TypedDict):
    """Schema for interfaces within an OSPF process."""

    interfaces: dict[str, OspfInterfaceEntry]


class ShowOspfInterfaceResult(TypedDict):
    """Schema for 'show ospf interface' parsed output.

    Keyed by OSPF process ID, then canonical interface name.
    """

    processes: dict[str, OspfProcessEntry]


_INTERFACE_RE = re.compile(
    r"^(?P<interface>\S+) is (?P<status>.+?), line protocol is (?P<protocol>\S+)$"
)

_Handler = Callable[[dict, re.Match[str]], None]


def _yes(value: str) -> bool:
    return value.lower() in {"yes", "enabled"}


def _address(entry: dict, m: re.Match[str]) -> None:
    entry["ip_address"] = m.group("ip")
    entry["area"] = m.group("area")
    if m.group("sid") is not None:
        entry["sid"] = int(m.group("sid"))
        entry["strict_spf_sid"] = int(m.group("strict_sid"))


def _label_stack(entry: dict, m: re.Match[str]) -> None:
    entry["label_stack"] = {
        "primary_label": int(m.group("primary")),
        "backup_label": int(m.group("backup")),
        "srte_label": int(m.group("srte")),
    }


def _process(entry: dict, m: re.Match[str]) -> None:
    entry["_process_id"] = m.group("process_id")
    entry["router_id"] = m.group("router_id")
    entry["network_type"] = m.group("network_type")
    if m.group("cost") is not None:
        entry["cost"] = int(m.group("cost"))


def _ldp_sync(entry: dict, m: re.Match[str]) -> None:
    entry["ldp_sync_enabled"] = _yes(m.group("enabled"))
    if m.group("status") is not None:
        entry["ldp_sync_status"] = m.group("status")


def _transmit(entry: dict, m: re.Match[str]) -> None:
    entry["transmit_delay"] = int(m.group("delay"))
    entry["state"] = m.group("state")
    for key, group in (
        ("priority", "priority"),
        ("mtu", "mtu"),
        ("max_packet_size", "max_pkt"),
    ):
        if m.group(group) is not None:
            entry[key] = int(m.group(group))


def _forward_ref(entry: dict, m: re.Match[str]) -> None:
    entry["forward_reference"] = _yes(m.group("fwd"))
    entry["unnumbered"] = _yes(m.group("unnum"))
    if m.group("bw") is not None:
        entry["bandwidth"] = int(m.group("bw"))


def _bfd(entry: dict, m: re.Match[str]) -> None:
    entry["bfd_enabled"] = True
    entry["bfd_interval_msec"] = int(m.group("interval"))
    entry["bfd_multiplier"] = int(m.group("multiplier"))
    if m.group("mode") is not None:
        entry["bfd_mode"] = m.group("mode")


def _timers(entry: dict, m: re.Match[str]) -> None:
    for key in ("hello", "dead", "wait", "retransmit"):
        entry[f"{key}_interval"] = int(m.group(key))


def _flood_index(entry: dict, m: re.Match[str]) -> None:
    entry["flood_stats"] = {
        "index": m.group("index"),
        "queue_length": int(m.group("queue")),
    }


def _flood_stat(*keys: str) -> _Handler:
    def handler(entry: dict, m: re.Match[str]) -> None:
        flood = entry.get("flood_stats")
        if flood is None:
            return
        for key, value in zip(keys, m.groups(), strict=True):
            flood[key] = value if key == "next" else int(value)

    return handler


def _ls_ack(entry: dict, m: re.Match[str]) -> None:
    entry["ls_ack_list"] = {
        "current_length": int(m.group(1)),
        "high_water_mark": int(m.group(2)),
    }


def _neighbor_count(entry: dict, m: re.Match[str]) -> None:
    entry["neighbor_count"] = int(m.group(1))
    entry["adjacent_neighbor_count"] = int(m.group(2))


def _authentication(entry: dict, m: re.Match[str]) -> None:
    entry["authentication"] = {"type": m.group(1).lower().replace(" ", "_")}


def _key_id(entry: dict, m: re.Match[str]) -> None:
    if "authentication" in entry:
        entry["authentication"]["key_id"] = int(m.group(1))


def _set(key: str, convert: Callable[[str], object] = str) -> _Handler:
    def handler(entry: dict, m: re.Match[str]) -> None:
        entry[key] = convert(m.group(1))

    return handler


def _flag(key: str) -> _Handler:
    def handler(entry: dict, _m: re.Match[str]) -> None:
        entry[key] = True

    return handler


def _neighbor(entry: dict, m: re.Match[str]) -> None:
    entry.setdefault("neighbors", {})[m.group(1)] = {}


def _ttl(entry: dict, m: re.Match[str]) -> None:
    entry["ttl_security"] = {"enabled": True, "hops": int(m.group(1))}


_LINE_HANDLERS: tuple[tuple[re.Pattern[str], _Handler], ...] = (
    (
        re.compile(
            rf"^Internet Address (?P<ip>{IPV4_PREFIX}), Area (?P<area>[^,\s]+)"
            r"(?:, SID (?P<sid>\d+), Strict-SPF SID (?P<strict_sid>\d+))?$"
        ),
        _address,
    ),
    (
        re.compile(
            r"^Label stack Primary label (?P<primary>\d+) "
            r"Backup label (?P<backup>\d+) SRTE label (?P<srte>\d+)$"
        ),
        _label_stack,
    ),
    (
        re.compile(
            r"^Process ID (?P<process_id>\S+), "
            rf"Router ID (?P<router_id>{IPV4_ADDRESS}), "
            r"Network Type (?P<network_type>[^,\s]+)(?:, Cost: (?P<cost>\d+))?$"
        ),
        _process,
    ),
    (
        re.compile(
            r"^LDP Sync (?P<enabled>Enabled|Disabled)"
            r"(?:, Sync Status: (?P<status>\S+))?$"
        ),
        _ldp_sync,
    ),
    (
        re.compile(
            r"^Transmit Delay is (?P<delay>\d+) sec, State (?P<state>[^,\s]+)"
            r"(?:, Priority (?P<priority>\d+))?"
            r"(?:, MTU (?P<mtu>\d+), MaxPktSz (?P<max_pkt>\d+))?,?$"
        ),
        _transmit,
    ),
    (
        re.compile(
            r"^Forward reference (?P<fwd>\w+), Unnumbered (?P<unnum>\w+),"
            r"(?:\s+Bandwidth (?P<bw>\d+))?$"
        ),
        _forward_ref,
    ),
    (
        re.compile(
            r"^BFD enabled, BFD interval (?P<interval>\d+) msec, "
            r"BFD multiplier (?P<multiplier>\d+)(?:, Mode: (?P<mode>.+))?$"
        ),
        _bfd,
    ),
    (
        re.compile(
            r"^Timer intervals configured, Hello (?P<hello>\d+), "
            r"Dead (?P<dead>\d+), Wait (?P<wait>\d+), "
            r"Retransmit (?P<retransmit>\d+)$"
        ),
        _timers,
    ),
    (
        re.compile(r"^Index (?P<index>\S+), flood queue length (?P<queue>\d+)$"),
        _flood_index,
    ),
    (re.compile(r"^Next (\S+)$"), _flood_stat("next")),
    (
        re.compile(r"^Last flood scan length is (\d+), maximum is (\d+)$"),
        _flood_stat("last_scan_length", "max_scan_length"),
    ),
    (
        re.compile(r"^Last flood scan time is (\d+) msec, maximum is (\d+) msec$"),
        _flood_stat("last_scan_time_msec", "max_scan_time_msec"),
    ),
    (
        re.compile(r"^LS Ack List: current length (\d+), high water mark (\d+)$"),
        _ls_ack,
    ),
    (
        re.compile(r"^Neighbor Count is (\d+), Adjacent neighbor count is (\d+)$"),
        _neighbor_count,
    ),
    (re.compile(rf"^Adjacent with neighbor ({IPV4_ADDRESS})$"), _neighbor),
    (
        re.compile(r"^Suppress hello for (\d+) neighbor\(s\)$"),
        _set("suppress_hello_count", int),
    ),
    (
        re.compile(r"^(Message digest|Clear text) authentication enabled$"),
        _authentication,
    ),
    (re.compile(r"^Youngest key id is (\d+)$"), _key_id),
    (
        re.compile(r"^Multi-area interface Count is (\d+)$"),
        _set("multi_area_interface_count", int),
    ),
    (re.compile(r"^RIB LC sync (\w+)$"), _set("rib_lc_sync", _yes)),
    (re.compile(r"^TTL security enabled, hop count (\d+)$"), _ttl),
    (re.compile(r"^Hello due in (\S+)$"), _set("hello_due_in")),
    (
        re.compile(r"^Interface is a tunnel igp-shortcut \((.+)\)$"),
        _set("igp_shortcut"),
    ),
    (
        re.compile(r"^Segment Routing Forwarding MPLS enabled: (\w+)$"),
        _set("sr_mpls_forwarding_enabled", _yes),
    ),
    (
        re.compile(r"^Adjacency hold timer expired last : (.+)$"),
        _set("adjacency_hold_timer_expired_last"),
    ),
    (
        re.compile(r"^Exchange timer expired last : (.+)$"),
        _set("exchange_timer_expired_last"),
    ),
    (re.compile(r"^auto path capability supported$"), _flag("auto_path_capability")),
    (
        re.compile(r"^Loopback interface is treated as a stub Host$"),
        _flag("stub_host"),
    ),
    (re.compile(r"^Non-Stop Forwarding \(NSF\) enabled$"), _flag("nsf_enabled")),
    (re.compile(r"^No Hellos \(Passive interface\)$"), _flag("passive")),
)


@register(OS.CISCO_IOSXR, "show ospf interface")
@register(
    OS.CISCO_IOSXR,
    r"show ospf (?P<process_id>\S+) interface "
    r"(?P<interface>[A-Za-z][A-Za-z-]* ?\d\S*)",
    doc_template="show ospf <process-id> interface <interface>",
)
class ShowOspfInterfaceParser(BaseParser["ShowOspfInterfaceResult"]):
    """Parser for 'show ospf interface' on IOS-XR.

    Parses detailed per-interface OSPF state, grouped by OSPF process
    (taken from each interface's "Process ID" line) and keyed by
    canonical interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING, ParserTag.INTERFACES}
    )

    @classmethod
    def parse(cls, output: str) -> "ShowOspfInterfaceResult":
        """Parse 'show ospf interface' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data grouped by OSPF process and interface.

        Raises:
            ValueError: If no OSPF interface data found in output.
        """
        blocks: list[tuple[str, dict]] = []
        for line in output.splitlines():
            stripped = line.strip()
            m = _INTERFACE_RE.match(stripped)
            if m is not None:
                entry = {
                    "status": m.group("status"),
                    "line_protocol": m.group("protocol"),
                }
                blocks.append((m.group("interface"), entry))
            elif blocks:
                cls._apply_line(stripped, blocks[-1][1])

        processes: dict[str, OspfProcessEntry] = {}
        for name, entry in blocks:
            process_id = entry.pop("_process_id", None)
            if process_id is None or "ip_address" not in entry:
                msg = f"Incomplete OSPF interface block for {name}"
                raise ValueError(msg)
            interface = canonical_interface_name(name, os=OS.CISCO_IOSXR)
            interfaces = processes.setdefault(process_id, {"interfaces": {}})
            interfaces["interfaces"][interface] = cast("OspfInterfaceEntry", entry)

        if not processes:
            msg = "No OSPF interface data found in output"
            raise ValueError(msg)

        return {"processes": processes}

    @staticmethod
    def _apply_line(stripped: str, entry: dict) -> None:
        """Apply the first matching line handler to the entry."""
        for pattern, handler in _LINE_HANDLERS:
            m = pattern.match(stripped)
            if m is not None:
                handler(entry, m)
                return
