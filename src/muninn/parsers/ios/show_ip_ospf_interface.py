"""Parser for 'show ip ospf interface' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class TopologyEntry(TypedDict):
    """OSPF topology (MTID) entry."""

    cost: int
    disabled: bool
    shutdown: bool
    name: str


class NeighborEntry(TypedDict):
    """Adjacent OSPF neighbor on an interface."""

    role: NotRequired[str]


class AuthenticationEntry(TypedDict):
    """OSPF authentication configuration."""

    type: str
    key_id: NotRequired[int]


class TtlSecurityEntry(TypedDict):
    """TTL security configuration."""

    enabled: bool
    hops: int


class GracefulRestartEntry(TypedDict):
    """Graceful restart helper configuration."""

    cisco_nsf: bool
    ietf_nsf: bool


class FloodStatsEntry(TypedDict):
    """Flood scan statistics."""

    index: str
    queue_length: int
    last_scan_length: int
    max_scan_length: int
    last_scan_time_msec: int
    max_scan_time_msec: int


class OspfInterfaceEntry(TypedDict):
    """Schema for a single OSPF interface."""

    status: str
    line_protocol: str
    interface_id: int
    area: str
    attached_via: str
    process_id: int
    router_id: str
    network_type: str
    cost: int
    ip_address: NotRequired[str]
    unnumbered_interface: NotRequired[str]
    unnumbered_address: NotRequired[str]
    transmit_delay: NotRequired[int]
    state: NotRequired[str]
    priority: NotRequired[int]
    dr_router_id: NotRequired[str]
    dr_address: NotRequired[str]
    bdr_router_id: NotRequired[str]
    bdr_address: NotRequired[str]
    hello_interval: NotRequired[int]
    dead_interval: NotRequired[int]
    wait_interval: NotRequired[int]
    retransmit_interval: NotRequired[int]
    oob_resync_timeout: NotRequired[int]
    hello_due_in: NotRequired[str]
    passive: NotRequired[bool]
    lls: NotRequired[bool]
    graceful_restart: NotRequired[GracefulRestartEntry]
    authentication: NotRequired[AuthenticationEntry]
    ttl_security: NotRequired[TtlSecurityEntry]
    prefix_suppression: NotRequired[bool]
    demand_circuit: NotRequired[bool]
    stub_host: NotRequired[bool]
    bfd_enabled: NotRequired[bool]
    ipfrr_protected: NotRequired[bool]
    ipfrr_candidate: NotRequired[bool]
    ti_lfa_protected: NotRequired[bool]
    flood_stats: NotRequired[FloodStatsEntry]
    total_dcbitless_lsa: NotRequired[int]
    donotage_lsa_allowed: NotRequired[bool]
    neighbor_count: NotRequired[int]
    adjacent_neighbor_count: NotRequired[int]
    suppress_hello_count: NotRequired[int]
    neighbors: NotRequired[dict[str, NeighborEntry]]
    topology: NotRequired[dict[str, TopologyEntry]]


class ShowIpOspfInterfaceResult(TypedDict):
    """Schema for 'show ip ospf interface' parsed output."""

    interfaces: dict[str, OspfInterfaceEntry]


# --- Header / block splitting ---
_STATUS_RE = re.compile(
    r"^(\S+) is (.+?),\s*line protocol is (\S+)\s*(?:\((\S+)\))?\s*$"
)

# --- Address and area ---
_IP_AREA_RE = re.compile(
    r"^\s*Internet Address (\S+)/(\d+),\s*Interface ID (\d+),\s*Area (\S+)\s*$"
)
_UNNUMBERED_AREA_RE = re.compile(
    r"^\s*Interface is unnumbered,\s*Interface ID (\d+),\s*Area (\S+)\s*$"
)
_UNNUMBERED_ADDR_RE = re.compile(r"^\s*Using address of (\S+)\s+\((\S+)\)\s*$")

# --- Process info ---
_PROCESS_RE = re.compile(
    r"^\s*Process ID (\d+),.*?Router ID (\S+),"
    r"\s*Network Type (\S+),\s*Cost:\s*(\d+)\s*$"
)

# --- Attached via ---
_ATTACHED_RE = re.compile(r"^\s*Attached via (.+?)\s*$")

# --- State and DR/BDR ---
_STATE_RE = re.compile(
    r"^\s*Transmit Delay is (\d+) sec,\s*State (\S+)"
    r"(?:,\s*Priority (\d+))?\s*$"
)
_DR_RE = re.compile(
    r"^\s*Designated Router \(ID\) (\S+),\s*Interface address (\S+)\s*$"
)
_BDR_RE = re.compile(
    r"^\s*Backup Designated router \(ID\) (\S+),\s*Interface address (\S+)\s*$"
)

# --- Timers ---
_TIMERS_RE = re.compile(
    r"^\s*Timer intervals configured,\s*Hello (\d+),\s*Dead (\d+),"
    r"\s*Wait (\d+),\s*Retransmit (\d+)\s*$"
)
_OOB_RE = re.compile(r"^\s*oob-resync timeout (\d+)\s*$")
_HELLO_DUE_RE = re.compile(r"^\s*Hello due in (\S+)\s*$")
_PASSIVE_RE = re.compile(r"^\s*No Hellos \(Passive interface\)\s*$")

# --- Topology ---
_TOPOLOGY_HEADER_RE = re.compile(r"^\s*Topology-MTID\s+Cost\s+Disabled\s+Shutdown")
_TOPOLOGY_ROW_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(yes|no)\s+(yes|no)\s+(\S+)\s*$")

# --- Features ---
_LLS_RE = re.compile(r"^\s*Supports Link-local Signaling \(LLS\)\s*$")
_CISCO_NSF_RE = re.compile(r"^\s*Cisco NSF helper support enabled\s*$")
_IETF_NSF_RE = re.compile(r"^\s*IETF NSF helper support enabled\s*$")
_PREFIX_SUPP_RE = re.compile(r"^\s*Prefix-suppression is enabled\s*$")
_DEMAND_CIRCUIT_RE = re.compile(r"^\s*(?:Configured|Run) as demand circuit\s*$")
_STUB_HOST_RE = re.compile(r"^\s*Loopback interface is treated as a stub Host\s*$")
_BFD_RE = re.compile(r"^\s*BFD is enabled\s*$")

# --- Authentication ---
_SIMPLE_AUTH_RE = re.compile(r"^\s*Simple password authentication enabled\s*$")
_CRYPTO_AUTH_RE = re.compile(r"^\s*Cryptographic authentication enabled\s*$")
_KEY_ID_RE = re.compile(r"^\s*Youngest key id is (\d+)\s*$")

# --- TTL security ---
_TTL_RE = re.compile(
    r"^\s*Strict TTL checking enabled,\s*up to (\d+) hops? allowed\s*$"
)

# --- IPFRR / TI-LFA ---
_IPFRR_PROTECTED_RE = re.compile(
    r"^\s*Can be protected by per-prefix Loop-Free FastReroute\s*$"
)
_IPFRR_NOT_PROTECTED_RE = re.compile(
    r"^\s*Can not be protected by per-prefix Loop-Free FastReroute\s*$"
)
_IPFRR_CANDIDATE_RE = re.compile(
    r"^\s*Can be used for per-prefix Loop-Free FastReroute repair paths\s*$"
)
_IPFRR_NOT_CANDIDATE_RE = re.compile(
    r"^\s*Can not be used for per-prefix Loop-Free FastReroute repair paths\s*$"
)
_TILFA_PROTECTED_RE = re.compile(r"^\s*Protected by per-prefix TI-LFA\s*$")
_TILFA_NOT_PROTECTED_RE = re.compile(r"^\s*Not Protected by per-prefix TI-LFA\s*$")

# --- Flood stats ---
_INDEX_RE = re.compile(r"^\s*Index (\S+),\s*flood queue length (\d+)\s*$")
_FLOOD_SCAN_LEN_RE = re.compile(
    r"^\s*Last flood scan length is (\d+),\s*maximum is (\d+)\s*$"
)
_FLOOD_SCAN_TIME_RE = re.compile(
    r"^\s*Last flood scan time is (\d+) msec,\s*maximum is (\d+) msec\s*$"
)

# --- DCbitless / DoNotAge ---
_DCBITLESS_RE = re.compile(
    r"^\s*DoNotAge LSA not allowed \(Number of DCbitless LSA is (\d+)\)\s*$"
)
_DONOTAGE_ALLOWED_RE = re.compile(r"^\s*DoNotAge LSA allowed\.\s*$")

# --- Neighbors ---
_NEIGHBOR_COUNT_RE = re.compile(
    r"^\s*Neighbor Count is (\d+),\s*Adjacent neighbor count is (\d+)\s*$"
)
_ADJACENT_RE = re.compile(r"^\s*Adjacent with neighbor (\S+)\s*(?:\((.+?)\))?\s*$")
_SUPPRESS_RE = re.compile(r"^\s*Suppress hello for (\d+) neighbor\(s\)\s*$")


def _normalize_area(area: str) -> str:
    """Normalize area to dotted notation. '0' -> '0.0.0.0', '1' -> '0.0.0.1'."""
    if "." in area:
        return area
    num = int(area)
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"


def _split_blocks(output: str) -> list[tuple[str, list[str]]]:
    """Split output into per-interface blocks."""
    blocks: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _STATUS_RE.match(line)
        if m:
            if current_name is not None:
                blocks.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = [line]
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        blocks.append((current_name, current_lines))

    return blocks


def _parse_status_line(line: str) -> dict:
    """Parse the interface status line."""
    m = _STATUS_RE.match(line)
    if not m:
        return {}
    return {
        "status": m.group(2).strip(),
        "line_protocol": m.group(3),
    }


def _parse_address_area(lines: list[str], entry: dict) -> None:
    """Parse IP address/unnumbered and area information."""
    for line in lines:
        m = _IP_AREA_RE.match(line)
        if m:
            entry["ip_address"] = f"{m.group(1)}/{m.group(2)}"
            entry["interface_id"] = int(m.group(3))
            entry["area"] = _normalize_area(m.group(4))
            continue

        m = _UNNUMBERED_AREA_RE.match(line)
        if m:
            entry["interface_id"] = int(m.group(1))
            entry["area"] = _normalize_area(m.group(2))
            continue

        m = _UNNUMBERED_ADDR_RE.match(line)
        if m:
            entry["unnumbered_interface"] = canonical_interface_name(
                m.group(1), os=OS.CISCO_IOS
            )
            entry["unnumbered_address"] = m.group(2)


def _parse_process_info(lines: list[str], entry: dict) -> None:
    """Parse process ID, router ID, network type, and cost."""
    for line in lines:
        m = _PROCESS_RE.match(line)
        if m:
            entry["process_id"] = int(m.group(1))
            entry["router_id"] = m.group(2)
            entry["network_type"] = m.group(3)
            entry["cost"] = int(m.group(4))
            return

        m = _ATTACHED_RE.match(line)
        if m:
            entry["attached_via"] = m.group(1)


def _parse_state_dr(lines: list[str], entry: dict) -> None:
    """Parse transmit delay, state, priority, DR/BDR."""
    for line in lines:
        m = _STATE_RE.match(line)
        if m:
            entry["transmit_delay"] = int(m.group(1))
            entry["state"] = m.group(2)
            if m.group(3) is not None:
                entry["priority"] = int(m.group(3))
            continue

        m = _DR_RE.match(line)
        if m:
            entry["dr_router_id"] = m.group(1)
            entry["dr_address"] = m.group(2)
            continue

        m = _BDR_RE.match(line)
        if m:
            entry["bdr_router_id"] = m.group(1)
            entry["bdr_address"] = m.group(2)


def _parse_timers(lines: list[str], entry: dict) -> None:
    """Parse timer intervals, oob-resync, hello due/passive."""
    for line in lines:
        m = _TIMERS_RE.match(line)
        if m:
            entry["hello_interval"] = int(m.group(1))
            entry["dead_interval"] = int(m.group(2))
            entry["wait_interval"] = int(m.group(3))
            entry["retransmit_interval"] = int(m.group(4))
            continue

        m = _OOB_RE.match(line)
        if m:
            entry["oob_resync_timeout"] = int(m.group(1))
            continue

        m = _HELLO_DUE_RE.match(line)
        if m:
            entry["hello_due_in"] = m.group(1)
            continue

        if _PASSIVE_RE.match(line):
            entry["passive"] = True


def _parse_topology(lines: list[str], entry: dict) -> None:
    """Parse topology table rows."""
    topology: dict[str, TopologyEntry] = {}
    in_topology = False
    for line in lines:
        if _TOPOLOGY_HEADER_RE.match(line):
            in_topology = True
            continue
        if in_topology:
            m = _TOPOLOGY_ROW_RE.match(line)
            if m:
                mtid = m.group(1)
                topology[mtid] = {
                    "cost": int(m.group(2)),
                    "disabled": m.group(3) == "yes",
                    "shutdown": m.group(4) == "yes",
                    "name": m.group(5),
                }
            else:
                in_topology = False
    if topology:
        entry["topology"] = topology


def _parse_ipfrr(lines: list[str], entry: dict) -> None:
    """Parse IPFRR and TI-LFA protection flags."""
    for line in lines:
        if _IPFRR_PROTECTED_RE.match(line):
            entry["ipfrr_protected"] = True
        elif _IPFRR_NOT_PROTECTED_RE.match(line):
            entry["ipfrr_protected"] = False
        elif _IPFRR_CANDIDATE_RE.match(line):
            entry["ipfrr_candidate"] = True
        elif _IPFRR_NOT_CANDIDATE_RE.match(line):
            entry["ipfrr_candidate"] = False
        elif _TILFA_PROTECTED_RE.match(line):
            entry["ti_lfa_protected"] = True
        elif _TILFA_NOT_PROTECTED_RE.match(line):
            entry["ti_lfa_protected"] = False


def _parse_auth(lines: list[str], entry: dict) -> None:
    """Parse authentication configuration."""
    auth_type: str | None = None
    auth_key_id: int | None = None

    for line in lines:
        if _SIMPLE_AUTH_RE.match(line):
            auth_type = "simple"
        elif _CRYPTO_AUTH_RE.match(line):
            auth_type = "md5"
        else:
            m = _KEY_ID_RE.match(line)
            if m:
                auth_key_id = int(m.group(1))

    if auth_type is not None:
        auth: AuthenticationEntry = {"type": auth_type}
        if auth_key_id is not None:
            auth["key_id"] = auth_key_id
        entry["authentication"] = auth


_BOOL_FLAG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_LLS_RE, "lls"),
    (_PREFIX_SUPP_RE, "prefix_suppression"),
    (_DEMAND_CIRCUIT_RE, "demand_circuit"),
    (_STUB_HOST_RE, "stub_host"),
    (_BFD_RE, "bfd_enabled"),
)


def _parse_lsa_info(lines: list[str], entry: dict) -> None:
    """Parse DCbitless LSA and DoNotAge LSA fields."""
    for line in lines:
        m = _DCBITLESS_RE.match(line)
        if m:
            entry["total_dcbitless_lsa"] = int(m.group(1))
            entry["donotage_lsa_allowed"] = False
        elif _DONOTAGE_ALLOWED_RE.match(line):
            entry["donotage_lsa_allowed"] = True


def _parse_features(lines: list[str], entry: dict) -> None:
    """Parse feature flags: LLS, NSF, TTL, etc."""
    cisco_nsf = False
    ietf_nsf = False

    for line in lines:
        if _CISCO_NSF_RE.match(line):
            cisco_nsf = True
        elif _IETF_NSF_RE.match(line):
            ietf_nsf = True
        else:
            for pattern, key in _BOOL_FLAG_PATTERNS:
                if pattern.match(line):
                    entry[key] = True
                    break
            else:
                m = _TTL_RE.match(line)
                if m:
                    entry["ttl_security"] = {
                        "enabled": True,
                        "hops": int(m.group(1)),
                    }

    if cisco_nsf or ietf_nsf:
        entry["graceful_restart"] = {
            "cisco_nsf": cisco_nsf,
            "ietf_nsf": ietf_nsf,
        }


def _parse_neighbors(lines: list[str], entry: dict) -> None:
    """Parse neighbor count and adjacent neighbor list."""
    for line in lines:
        m = _NEIGHBOR_COUNT_RE.match(line)
        if m:
            entry["neighbor_count"] = int(m.group(1))
            entry["adjacent_neighbor_count"] = int(m.group(2))
            continue

        m = _ADJACENT_RE.match(line)
        if m:
            neighbors = entry.setdefault("neighbors", {})
            neighbor_id = m.group(1)
            neighbor_entry: NeighborEntry = {}
            if m.group(2):
                neighbor_entry["role"] = m.group(2)
            neighbors[neighbor_id] = neighbor_entry
            continue

        m = _SUPPRESS_RE.match(line)
        if m:
            entry["suppress_hello_count"] = int(m.group(1))


def _parse_flood_stats(lines: list[str], entry: dict) -> None:
    """Parse flood scan statistics."""
    flood: dict = {}

    for line in lines:
        m = _INDEX_RE.match(line)
        if m:
            flood["index"] = m.group(1)
            flood["queue_length"] = int(m.group(2))
            continue

        m = _FLOOD_SCAN_LEN_RE.match(line)
        if m:
            flood["last_scan_length"] = int(m.group(1))
            flood["max_scan_length"] = int(m.group(2))
            continue

        m = _FLOOD_SCAN_TIME_RE.match(line)
        if m:
            flood["last_scan_time_msec"] = int(m.group(1))
            flood["max_scan_time_msec"] = int(m.group(2))

    if flood:
        entry["flood_stats"] = flood


def _parse_block(lines: list[str]) -> OspfInterfaceEntry | None:
    """Parse a single interface block."""
    if not lines:
        return None

    entry: dict = _parse_status_line(lines[0])
    if not entry:
        return None

    body = lines[1:]
    _parse_address_area(body, entry)
    _parse_process_info(body, entry)
    _parse_state_dr(body, entry)
    _parse_timers(body, entry)
    _parse_topology(body, entry)
    _parse_features(body, entry)
    _parse_auth(body, entry)
    _parse_ipfrr(body, entry)
    _parse_lsa_info(body, entry)
    _parse_neighbors(body, entry)
    _parse_flood_stats(body, entry)

    return entry  # type: ignore[return-value]


@register(OS.CISCO_IOS, "show ip ospf interface")
@register(OS.CISCO_IOSXE, "show ip ospf interface")
class ShowIpOspfInterfaceParser(BaseParser[ShowIpOspfInterfaceResult]):
    """Parser for 'show ip ospf interface' on IOS/IOS-XE."""

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfInterfaceResult:
        """Parse 'show ip ospf interface' output."""
        blocks = _split_blocks(output)
        interfaces: dict[str, OspfInterfaceEntry] = {}

        for raw_name, block_lines in blocks:
            parsed = _parse_block(block_lines)
            if parsed is None:
                continue
            name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)
            interfaces[name] = parsed

        return {"interfaces": interfaces}
