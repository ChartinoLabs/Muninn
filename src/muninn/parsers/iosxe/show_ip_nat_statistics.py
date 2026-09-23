"""Parser for 'show ip nat statistics' command on IOS and IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class AddressRange(TypedDict):
    """A start/end address range within a NAT pool."""

    start_address: str
    end_address: str


class NatPool(TypedDict):
    """Schema for a NAT pool referenced by a dynamic mapping."""

    id: NotRequired[int]
    netmask: str
    address_ranges: NotRequired[dict[str, AddressRange]]
    type: NotRequired[str]
    total_addresses: NotRequired[int]
    allocated_addresses: NotRequired[int]
    allocated_percent: NotRequired[int]
    misses: NotRequired[int]
    longest_chain: NotRequired[int]
    average_chain_length: NotRequired[int]
    chains: NotRequired[str]


class PortRange(TypedDict):
    """Low/high port counters as printed (``lo:N hi:N``)."""

    low: int
    high: int


class ReservedPortblockStats(TypedDict):
    """Schema for the ``Reserved portblock stats`` block."""

    tcp_ports_received_from_tpm: NotRequired[PortRange]
    udp_ports_received_from_tpm: NotRequired[PortRange]
    tcp_ports_available: NotRequired[PortRange]
    udp_ports_available: NotRequired[PortRange]
    tcp_ports_reserved_flag: NotRequired[int]
    udp_ports_reserved_flag: NotRequired[int]


class DynamicMapping(TypedDict):
    """Schema for a single ``[Id: N]`` dynamic mapping."""

    access_list: NotRequired[str]
    route_map: NotRequired[str]
    pool: NotRequired[str]
    interface: NotRequired[str]
    refcount: NotRequired[int]


class ShowIpNatStatisticsResult(TypedDict):
    """Schema for 'show ip nat statistics' parsed output."""

    total_active_translations: int
    static_translations: int
    dynamic_translations: int
    extended_translations: int
    peak_translations: NotRequired[int]
    peak_occurred_ago: NotRequired[str]
    outside_interfaces: NotRequired[list[str]]
    inside_interfaces: NotRequired[list[str]]
    hits: int
    misses: int
    cef_translated_packets: NotRequired[int]
    cef_punted_packets: NotRequired[int]
    reserved_port_setting: NotRequired[str]
    reserved_port_provisioned: NotRequired[str]
    dynamic_overload_mappings_configured: NotRequired[int]
    reserved_portblock_stats: NotRequired[ReservedPortblockStats]
    expired_translations: NotRequired[int]
    # Keyed by direction, then by ``[Id: N]``; older IOS omits the id, in which
    # case the mapping is keyed by its reference (e.g. ``access-list 1``).
    dynamic_mappings: NotRequired[dict[str, dict[str, DynamicMapping]]]
    pools: NotRequired[dict[str, NatPool]]
    total_doors: NotRequired[int]
    appl_doors: NotRequired[int]
    normal_doors: NotRequired[int]
    queued_packets: NotRequired[int]
    nat_limit_max_allowed: NotRequired[int]
    nat_limit_used: NotRequired[int]
    nat_limit_missed: NotRequired[int]
    in_to_out_drops: NotRequired[int]
    out_to_in_drops: NotRequired[int]
    pool_stats_drop: NotRequired[int]
    mapping_stats_drop: NotRequired[int]
    port_block_alloc_fail: NotRequired[int]
    ip_alias_add_fail: NotRequired[int]
    limit_entry_add_fail: NotRequired[int]


# Top-level counter lines; every named group is an int except those in _STR_FIELDS.
_SCALARS = (
    re.compile(
        r"^Total (?:active )?translations:\s*(?P<total_active_translations>\d+)\s*"
        r"\((?P<static_translations>\d+) static,\s*"
        r"(?P<dynamic_translations>\d+) dynamic;\s*"
        r"(?P<extended_translations>\d+) extended\)"
    ),
    re.compile(
        r"^Peak translations:\s*(?P<peak_translations>\d+)"
        r"(?:,\s*occurred\s+(?P<peak_occurred_ago>\S+)\s+ago)?"
    ),
    re.compile(r"^Hits:\s*(?P<hits>\d+)\s+Misses:\s*(?P<misses>\d+)"),
    re.compile(
        r"^CEF Translated packets:\s*(?P<cef_translated_packets>\d+),\s*"
        r"CEF Punted packets:\s*(?P<cef_punted_packets>\d+)"
    ),
    re.compile(
        r"^Reserved port setting (?P<reserved_port_setting>\S+) "
        r"provisioned (?P<reserved_port_provisioned>\S+)$"
    ),
    re.compile(
        r"^Dynamic overload mapping configured:\s*"
        r"(?P<dynamic_overload_mappings_configured>\d+)"
    ),
    re.compile(r"^Expired translations:\s*(?P<expired_translations>\d+)"),
    re.compile(r"^Total doors:\s*(?P<total_doors>\d+)"),
    re.compile(r"^Appl doors:\s*(?P<appl_doors>\d+)"),
    re.compile(r"^Normal doors:\s*(?P<normal_doors>\d+)"),
    re.compile(r"^Queued Packets:\s*(?P<queued_packets>\d+)"),
    re.compile(
        r"^max entry: max allowed (?P<nat_limit_max_allowed>\d+),\s*"
        r"used (?P<nat_limit_used>\d+),\s*missed (?P<nat_limit_missed>\d+)"
    ),
    re.compile(
        r"^In-to-out drops:\s*(?P<in_to_out_drops>\d+)\s+"
        r"Out-to-in drops:\s*(?P<out_to_in_drops>\d+)"
    ),
    re.compile(
        r"^Pool stats drop:\s*(?P<pool_stats_drop>\d+)\s+"
        r"Mapping stats drop:\s*(?P<mapping_stats_drop>\d+)"
    ),
    re.compile(r"^Port block alloc fail:\s*(?P<port_block_alloc_fail>\d+)"),
    re.compile(r"^IP alias add fail:\s*(?P<ip_alias_add_fail>\d+)"),
    re.compile(r"^Limit entry add fail:\s*(?P<limit_entry_add_fail>\d+)"),
)
_STR_FIELDS = frozenset(
    {"peak_occurred_ago", "reserved_port_setting", "reserved_port_provisioned"}
)

# Reserved portblock stats
# total tcp ports rcvd from tpm lo:0 hi:0
# tcp ports reserved flag 0 udp ports reserved flag 0
_PORTBLOCK_HEADER = re.compile(r"^Reserved portblock stats$")
_PORTBLOCK_RANGE = re.compile(
    r"^total (?P<proto>tcp|udp) ports (?P<kind>rcvd from tpm|available) "
    r"lo:(?P<low>\d+) hi:(?P<high>\d+)$"
)
_PORTBLOCK_KINDS = {"rcvd from tpm": "received_from_tpm", "available": "available"}
_PORTBLOCK_FLAGS = re.compile(
    r"^tcp ports reserved flag (?P<tcp_ports_reserved_flag>\d+) "
    r"udp ports reserved flag (?P<udp_ports_reserved_flag>\d+)$"
)

# Interfaces may follow on the header line (older IOS) or on later lines.
_INTERFACE_SECTION = re.compile(r"^(?P<side>Outside|Inside) interfaces:(?P<inline>.*)$")
_SECTION_END = re.compile(r"^(?:Dynamic mappings|nat-limit statistics):$")
_DIRECTION = re.compile(r"^--\s+(?P<direction>\S+ \S+)$")

# [Id: 1] access-list test-robot pool test-robot refcount 0
# [Id: 3] access-list 99 interface Serial0/0 refcount 1
# [Id: 4] route-map GENIE-MAP
# access-list 1 pool net-208 refcount 2   (older IOS, no id)
_MAPPING = re.compile(
    r"^(?:\[Id:\s*(?P<id>\d+)\]\s+)?(?P<kind>access-list|route-map)\s+(?P<name>\S+)"
    r"(?:\s+pool\s+(?P<pool>\S+))?"
    r"(?:\s+interface\s+(?P<interface>\S+))?"
    r"(?:\s+refcount\s+(?P<refcount>\d+))?$"
)

# pool inside-pool: id 1, netmask 255.255.255.0
_POOL = re.compile(
    r"^pool (?P<name>\S+): (?:id (?P<id>\d+), )?"
    rf"netmask (?P<netmask>{IPV4_ADDRESS})$"
)
_POOL_RANGE = re.compile(
    rf"^start (?P<start>{IPV4_ADDRESS}) end (?P<end>{IPV4_ADDRESS})$"
)
_POOL_USAGE = re.compile(
    r"^type (?P<type>\S+), total addresses (?P<total_addresses>\d+), "
    r"allocated (?P<allocated_addresses>\d+) \((?P<allocated_percent>\d+)%\), "
    r"misses (?P<misses>\d+)$"
)
# longest chain in pool: net-208's addr-hash: 6, average len 5,chains 256/256
_POOL_CHAIN = re.compile(
    r"^longest chain in pool: \S+ addr-hash: (?P<longest_chain>\d+), "
    r"average len (?P<average_chain_length>\d+),\s*chains (?P<chains>\S+)$"
)
_POOL_INT_FIELDS = frozenset(
    {
        "total_addresses",
        "allocated_addresses",
        "allocated_percent",
        "misses",
        "longest_chain",
        "average_chain_length",
    }
)


def _try_scalars(line: str, result: dict) -> bool:
    """Write top-level counters from *line* into *result*."""
    for pattern in _SCALARS:
        match = pattern.match(line)
        if match:
            for key, value in match.groupdict().items():
                if value is not None:
                    result[key] = value if key in _STR_FIELDS else int(value)
            return True
    return False


def _try_portblock(line: str, result: dict) -> bool:
    """Write ``Reserved portblock stats`` lines into *result*."""
    if _PORTBLOCK_HEADER.match(line):
        result.setdefault("reserved_portblock_stats", {})
        return True
    stats = result.get("reserved_portblock_stats")
    if stats is None:
        return False
    if match := _PORTBLOCK_RANGE.match(line):
        kind = _PORTBLOCK_KINDS[match.group("kind")]
        stats[f"{match.group('proto')}_ports_{kind}"] = {
            "low": int(match.group("low")),
            "high": int(match.group("high")),
        }
        return True
    if match := _PORTBLOCK_FLAGS.match(line):
        stats.update({k: int(v) for k, v in match.groupdict().items()})
        return True
    return False


def _add_mapping(match: re.Match[str], direction: str, result: dict) -> None:
    """Store a dynamic mapping under its direction and ``[Id]``."""
    mapping: dict = {match.group("kind").replace("-", "_"): match.group("name")}
    if match.group("pool"):
        mapping["pool"] = match.group("pool")
    if match.group("interface"):
        mapping["interface"] = canonical_interface_name(
            match.group("interface"), os=OS.CISCO_IOSXE
        )
    if match.group("refcount"):
        mapping["refcount"] = int(match.group("refcount"))
    mappings = result.setdefault("dynamic_mappings", {})
    key = match.group("id") or f"{match.group('kind')} {match.group('name')}"
    mappings.setdefault(direction, {})[key] = mapping


def _try_pool_detail(line: str, pool: dict) -> None:
    """Merge a pool range / usage / chain line into *pool*."""
    if match := _POOL_RANGE.match(line):
        pool.setdefault("address_ranges", {})[match.group("start")] = {
            "start_address": match.group("start"),
            "end_address": match.group("end"),
        }
        return
    for pattern in (_POOL_USAGE, _POOL_CHAIN):
        if match := pattern.match(line):
            for key, value in match.groupdict().items():
                pool[key] = int(value) if key in _POOL_INT_FIELDS else value
            return


def _start_pool(match: re.Match[str], result: dict) -> dict:
    """Create and return a pool entry from a ``pool <name>:`` header."""
    pool: dict = {"netmask": match.group("netmask")}
    if match.group("id"):
        pool["id"] = int(match.group("id"))
    result.setdefault("pools", {})[match.group("name")] = pool
    return pool


def _add_interfaces(line: str, side: str, result: dict) -> None:
    """Append comma-separated interfaces to the inside/outside list."""
    names = [name.strip() for name in line.split(",") if name.strip()]
    if names:
        result.setdefault(f"{side.lower()}_interfaces", []).extend(
            canonical_interface_name(name, os=OS.CISCO_IOSXE) for name in names
        )


class _State:
    """Mutable parse context for the current section / mapping / pool."""

    def __init__(self) -> None:
        self.side: str | None = None
        self.direction = "unknown"
        self.pool: dict | None = None


def _parse_line(line: str, state: _State, result: dict) -> None:
    """Dispatch one stripped output line."""
    if match := _INTERFACE_SECTION.match(line):
        state.side = match.group("side")
        _add_interfaces(match.group("inline"), state.side, result)
    elif (
        _try_scalars(line, result)
        or _try_portblock(line, result)
        or _SECTION_END.match(line)
    ):
        state.side = None
    elif state.side is not None:
        _add_interfaces(line, state.side, result)
    elif match := _DIRECTION.match(line):
        state.direction = match.group("direction").lower().replace(" ", "_")
    elif match := _MAPPING.match(line):
        _add_mapping(match, state.direction, result)
        state.pool = None
    elif match := _POOL.match(line):
        state.pool = _start_pool(match, result)
    elif state.pool is not None:
        _try_pool_detail(line, state.pool)


@register(OS.CISCO_IOS, "show ip nat statistics")
@register(OS.CISCO_IOSXE, "show ip nat statistics")
class ShowIpNatStatisticsParser(BaseParser[ShowIpNatStatisticsResult]):
    """Parser for 'show ip nat statistics' on IOS and IOS-XE.

    Example output::

        Total active translations: 1 (0 static, 1 dynamic; 1 extended)
        Outside interfaces:
          Serial0/0
        Inside interfaces:
          FastEthernet0/0
        Hits: 3  Misses: 1
        Dynamic mappings:
        -- Inside Source
        [Id: 3] access-list 99 interface Serial0/0 refcount 1
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.NAT})

    @classmethod
    def parse(cls, output: str) -> ShowIpNatStatisticsResult:
        """Parse 'show ip nat statistics' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed NAT statistics.

        Raises:
            ValueError: If the translation totals or hit/miss counters are missing.
        """
        result: dict = {}
        state = _State()
        for raw in output.splitlines():
            line = raw.strip()
            if line:
                _parse_line(line, state, result)

        for required in ("total_active_translations", "hits"):
            if required not in result:
                msg = f"Missing required field: {required}"
                raise ValueError(msg)
        return cast(ShowIpNatStatisticsResult, result)
