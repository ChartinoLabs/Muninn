"""Parser for 'show interfaces' command on IOS/IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InputQueueEntry(TypedDict):
    """Schema for interface input queue info."""

    size: int
    max: int
    drops: int
    flushes: int


class OutputQueueEntry(TypedDict):
    """Schema for interface output queue info."""

    size: int
    max: int


class CountersEntry(TypedDict):
    """Schema for interface traffic counters."""

    packets_input: NotRequired[int]
    bytes_input: NotRequired[int]
    no_buffer: NotRequired[int]
    broadcasts_received: NotRequired[int]
    ip_multicasts_received: NotRequired[int]
    runts: NotRequired[int]
    giants: NotRequired[int]
    throttles: NotRequired[int]
    input_errors: NotRequired[int]
    crc: NotRequired[int]
    frame: NotRequired[int]
    overrun: NotRequired[int]
    ignored: NotRequired[int]
    abort: NotRequired[int]
    watchdog: NotRequired[int]
    multicast: NotRequired[int]
    pause_input: NotRequired[int]
    dribble_condition: NotRequired[int]
    packets_output: NotRequired[int]
    bytes_output: NotRequired[int]
    underruns: NotRequired[int]
    output_broadcasts: NotRequired[int]
    output_ip_multicasts: NotRequired[int]
    output_errors: NotRequired[int]
    collisions: NotRequired[int]
    interface_resets: NotRequired[int]
    unknown_protocol_drops: NotRequired[int]
    babbles: NotRequired[int]
    late_collision: NotRequired[int]
    deferred: NotRequired[int]
    lost_carrier: NotRequired[int]
    no_carrier: NotRequired[int]
    pause_output: NotRequired[int]
    output_buffer_failures: NotRequired[int]
    output_buffers_swapped_out: NotRequired[int]
    carrier_transitions: NotRequired[int]


class PortChannelMemberEntry(TypedDict):
    """Per-member duplex and speed (see ``PortChannelInfo.members`` keys)."""

    duplex: str
    speed: str


class PortChannelInfo(TypedDict):
    """Schema for port-channel information."""

    active_members: int
    members: dict[str, PortChannelMemberEntry]
    pf_jumbo_members: NotRequired[int]


class TunnelInfo(TypedDict):
    """Schema for tunnel interface information."""

    source: NotRequired[str]
    source_interface: NotRequired[str]
    destination: NotRequired[str]
    protocol: NotRequired[str]
    ttl: NotRequired[int]
    transport_mtu: NotRequired[int]
    transmit_bandwidth_kbps: NotRequired[int]
    receive_bandwidth_kbps: NotRequired[int]
    linestate_evaluation: NotRequired[str]
    fast_tunneling: NotRequired[bool]
    key_disabled: NotRequired[bool]
    sequencing_disabled: NotRequired[bool]
    checksumming_disabled: NotRequired[bool]
    ipsec_profile: NotRequired[str]


class InterfaceEntry(TypedDict):
    """Schema for a single interface entry."""

    status: str
    line_protocol: str
    hardware: str
    mtu: int
    bandwidth_kbps: int
    delay_usec: int
    encapsulation: str
    line_protocol_reason: NotRequired[str]
    description: NotRequired[str]
    address: NotRequired[str]
    bia: NotRequired[str]
    ip_address: NotRequired[str]
    ip_prefix_length: NotRequired[int]
    unnumbered_interface: NotRequired[str]
    reliability: NotRequired[str]
    txload: NotRequired[str]
    rxload: NotRequired[str]
    loopback_set: NotRequired[bool]
    keepalive: NotRequired[int]
    duplex: NotRequired[str]
    speed: NotRequired[str]
    link_type: NotRequired[str]
    media_type: NotRequired[str]
    output_flow_control: NotRequired[str]
    input_flow_control: NotRequired[str]
    fec: NotRequired[str]
    arp_type: NotRequired[str]
    arp_timeout: NotRequired[str]
    vlan_id: NotRequired[int]
    outer_vlan_id: NotRequired[int]
    inner_vlan_id: NotRequired[int]
    autostate_enabled: NotRequired[bool]
    last_input: NotRequired[str]
    last_output: NotRequired[str]
    output_hang: NotRequired[str]
    last_clearing: NotRequired[str]
    input_queue: NotRequired[InputQueueEntry]
    output_queue: NotRequired[OutputQueueEntry]
    total_output_drops: NotRequired[int]
    queueing_strategy: NotRequired[str]
    rate_interval_seconds: NotRequired[int]
    input_rate_bps: NotRequired[int]
    input_rate_pps: NotRequired[int]
    output_rate_bps: NotRequired[int]
    output_rate_pps: NotRequired[int]
    counters: NotRequired[CountersEntry]
    port_channel: NotRequired[PortChannelInfo]
    tunnel: NotRequired[TunnelInfo]
    serial_rts: NotRequired[str]
    serial_cts: NotRequired[str]
    serial_dtr: NotRequired[str]
    serial_dcd: NotRequired[str]
    serial_dsr: NotRequired[str]


class ShowInterfacesResult(TypedDict):
    """Schema for 'show interfaces' parsed output."""

    interfaces: dict[str, InterfaceEntry]


# --- Status line ---
_STATUS_RE = re.compile(
    r"^(\S+) is (.+?),\s*line protocol is (\S+)\s*(?:\((\S+)\))?\s*$"
)

# --- Common field patterns ---
_HW_RE = re.compile(
    r"^\s*Hardware is (.+?)(?:,\s*address is ([0-9a-f.]+)"
    r"\s*\(bia ([0-9a-f.]+)\))?\s*$"
)
_DESC_RE = re.compile(r"^\s*Description:\s*(.+?)\s*$")
_IP_RE = re.compile(r"^\s*Internet address is (\S+)/(\d+)\s*$")
_UNNUMBERED_RE = re.compile(
    r"^\s*Interface is unnumbered\.\s*Using address of (\S+)\s*\((\S+)\)\s*$"
)
_MTU_RE = re.compile(r"^\s*MTU (\d+) bytes,\s*BW (\d+) Kbit(?:/sec)?,\s*DLY (\d+) usec")
_RELIABILITY_RE = re.compile(
    r"^\s*reliability (\d+/\d+),\s*txload (\d+/\d+),\s*rxload (\d+/\d+)"
)
_ENCAP_RE = re.compile(r"^\s*Encapsulation (.+?)(?:,\s*loopback (.+))?\s*$")
_ENCAP_VLAN_RE = re.compile(
    r"^\s*Encapsulation 802\.1Q Virtual LAN,\s*Vlan ID\s+(\d+)\."
    r"(?:,\s*loopback (.+))?\s*$"
)
_ENCAP_QINQ_RE = re.compile(
    r"^\s*Encapsulation QinQ Virtual LAN,\s*outer ID\s+(\d+),\s*inner ID\s*(\d+)"
)
_KEEPALIVE_RE = re.compile(r"^\s*Keepalive\s+(.+?)\s*$")
_DUPLEX_SPEED_KEYWORDS = frozenset(
    {
        "full",
        "half",
        "auto",
        "auto-duplex",
        "full-duplex",
        "half-duplex",
        "unknown",
    }
)
_FLOW_RE = re.compile(
    r"^\s*(?:output flow-control is (\S+),\s*)?input flow-control is (\S+)"
    r"(?:,\s*output flow-control is (\S+))?\s*$"
)
_FEC_RE = re.compile(r"^\s*[Ff]ec is (\S+)\s*$")
_ARP_RE = re.compile(r"^\s*ARP type:\s*(\S+),\s*ARP Timeout\s*(\S+)\s*$")
_LAST_IO_RE = re.compile(
    r"^\s*Last input (.+?),\s*output (.+?),\s*output hang (.+?)\s*$"
)
_LAST_CLEAR_RE = re.compile(r'^\s*Last clearing of "show interface" counters (.+?)\s*$')
_INPUT_QUEUE_RE = re.compile(
    r"^\s*Input queue:\s*(\d+)/(\d+)/(\d+)/(\d+)\s*"
    r"\(size/max/drops/flushes\);\s*Total output drops:\s*(\d+)\s*$"
)
_OUTPUT_QUEUE_RE = re.compile(r"^\s*Output queue\s*:\s*(\d+)/(\d+)\s*\(size/max\)\s*$")
_QUEUEING_RE = re.compile(r"^\s*Queueing strategy:\s*(.+?)\s*$")
_RATE_INTERVAL_RE = re.compile(
    r"^\s*(\d+) (?:second|minute) (?:input|output) rate\s+(\d+) bits/sec,"
    r"\s*(\d+) packets/sec\s*$"
)
_AUTOSTATE_RE = re.compile(r"^\s*Autostate (enabled|disabled)\s*$")

# --- Port-channel patterns ---
_PC_ACTIVE_RE = re.compile(r"^\s*No\. of active members in this channel:\s*(\d+)\s*$")
_PC_MEMBER_RE = re.compile(r"^\s*Member \d+\s*:\s*(\S+)\s*,\s*(.+?),\s*(\S+)\s*$")
_PC_JUMBO_RE = re.compile(
    r"^\s*No\. of PF_JUMBO supported members in this channel\s*:\s*(\d+)\s*$"
)
_PC_MEMBERS_IN_RE = re.compile(r"^\s*Members in this channel:\s*(.+?)\s*$")

# --- Tunnel patterns ---
_TUNNEL_LINESTATE_RE = re.compile(r"^\s*Tunnel linestate evaluation (.+?)\s*$")
_TUNNEL_SOURCE_RE = re.compile(
    r"^\s*Tunnel source\s+(\S+?)(?:\s+\((\S+)\))?"
    r"(?:,\s*destination\s+(\S+))?\s*$"
)
_TUNNEL_PROTO_RE = re.compile(r"^\s*Tunnel protocol/transport\s+(.+?)\s*$")
_TUNNEL_TTL_RE = re.compile(
    r"^\s*Tunnel TTL\s+(\d+)(?:,\s*Fast tunneling (enabled))?\s*$"
)
_TUNNEL_MTU_RE = re.compile(r"^\s*Tunnel transport MTU\s+(\d+) bytes\s*$")
_TUNNEL_TX_BW_RE = re.compile(r"^\s*Tunnel transmit bandwidth\s+(\d+)\s*\(kbps\)\s*$")
_TUNNEL_RX_BW_RE = re.compile(r"^\s*Tunnel receive bandwidth\s+(\d+)\s*\(kbps\)\s*$")
_TUNNEL_KEY_SEQ_RE = re.compile(
    r"^\s*Key (disabled|enabled),\s*sequencing (disabled|enabled)\s*$"
)
_TUNNEL_CKSUM_RE = re.compile(r"^\s*Checksumming of packets (disabled|enabled)\s*$")
_TUNNEL_IPSEC_RE = re.compile(r"^\s*Tunnel IPSec profile:\s*(\S+)\s*$")

# --- Counter patterns ---
_COUNTER_PATTERNS: list[tuple[re.Pattern[str], list[tuple[int, str]]]] = [
    (
        re.compile(
            r"^\s*(\d+) packets input,\s*(\d+) bytes(?:,\s*(\d+) no buffer)?\s*$"
        ),
        [(1, "packets_input"), (2, "bytes_input"), (3, "no_buffer")],
    ),
    (
        re.compile(r"^\s*Received (\d+) broadcasts\s*\((\d+) (?:IP )?multicasts\)\s*$"),
        [(1, "broadcasts_received"), (2, "ip_multicasts_received")],
    ),
    (
        re.compile(r"^\s*(\d+) runts,\s*(\d+) giants,\s*(\d+) throttles\s*$"),
        [(1, "runts"), (2, "giants"), (3, "throttles")],
    ),
    (
        re.compile(
            r"^\s*(\d+) input errors,\s*(\d+) CRC,\s*(\d+) frame,"
            r"\s*(\d+) overrun,\s*(\d+) ignored(?:,\s*(\d+) abort)?\s*$"
        ),
        [
            (1, "input_errors"),
            (2, "crc"),
            (3, "frame"),
            (4, "overrun"),
            (5, "ignored"),
            (6, "abort"),
        ],
    ),
    (
        re.compile(r"^\s*(\d+) watchdog,\s*(\d+) multicast,\s*(\d+) pause input\s*$"),
        [(1, "watchdog"), (2, "multicast"), (3, "pause_input")],
    ),
    (
        re.compile(r"^\s*(\d+) input packets with dribble condition detected\s*$"),
        [(1, "dribble_condition")],
    ),
    (
        re.compile(r"^\s*(\d+) packets output,\s*(\d+) bytes,\s*(\d+) underruns\s*$"),
        [(1, "packets_output"), (2, "bytes_output"), (3, "underruns")],
    ),
    (
        re.compile(r"^\s*Output (\d+) broadcasts\s*\((\d+) (?:IP )?multicasts\)\s*$"),
        [(1, "output_broadcasts"), (2, "output_ip_multicasts")],
    ),
    (
        re.compile(
            r"^\s*(\d+) output errors,\s*(\d+) collisions,"
            r"\s*(\d+) interface resets\s*$"
        ),
        [
            (1, "output_errors"),
            (2, "collisions"),
            (3, "interface_resets"),
        ],
    ),
    (
        re.compile(r"^\s*(\d+) output errors,\s*(\d+) interface resets\s*$"),
        [(1, "output_errors"), (2, "interface_resets")],
    ),
    (
        re.compile(r"^\s*(\d+) unknown protocol drops\s*$"),
        [(1, "unknown_protocol_drops")],
    ),
    (
        re.compile(r"^\s*(\d+) babbles,\s*(\d+) late collision,\s*(\d+) deferred\s*$"),
        [(1, "babbles"), (2, "late_collision"), (3, "deferred")],
    ),
    (
        re.compile(
            r"^\s*(\d+) lost carrier,\s*(\d+) no carrier,\s*(\d+) pause output\s*$"
        ),
        [(1, "lost_carrier"), (2, "no_carrier"), (3, "pause_output")],
    ),
    (
        re.compile(r"^\s*(\d+) lost carrier,\s*(\d+) no carrier\s*$"),
        [(1, "lost_carrier"), (2, "no_carrier")],
    ),
    (
        re.compile(
            r"^\s*(\d+) output buffer failures,"
            r"\s*(\d+) output buffers swapped out\s*$"
        ),
        [(1, "output_buffer_failures"), (2, "output_buffers_swapped_out")],
    ),
    (
        re.compile(r"^\s*(\d+) carrier transitions\s*$"),
        [(1, "carrier_transitions")],
    ),
]

# --- Serial signal line ---
_SERIAL_SIGNALS_RE = re.compile(
    r"^\s*RTS (\w+),\s*CTS (\w+),\s*DTR (\w+),\s*DCD (\w+),\s*DSR (\w+)\s*$"
)


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
    """Parse the status line."""
    m = _STATUS_RE.match(line)
    if not m:
        return {}
    result: dict = {
        "status": m.group(2).strip(),
        "line_protocol": m.group(3),
    }
    if m.group(4):
        result["line_protocol_reason"] = m.group(4)
    return result


def _parse_encapsulation(line: str, entry: dict) -> bool:
    """Parse encapsulation line. Returns True if matched."""
    m = _ENCAP_QINQ_RE.match(line)
    if m:
        entry["encapsulation"] = "QinQ Virtual LAN"
        entry["outer_vlan_id"] = int(m.group(1))
        entry["inner_vlan_id"] = int(m.group(2))
        return True

    m = _ENCAP_VLAN_RE.match(line)
    if m:
        entry["encapsulation"] = "802.1Q Virtual LAN"
        entry["vlan_id"] = int(m.group(1))
        if m.group(2):
            entry["loopback_set"] = m.group(2).strip() != "not set"
        return True

    m = _ENCAP_RE.match(line)
    if m:
        entry["encapsulation"] = m.group(1)
        if m.group(2):
            entry["loopback_set"] = m.group(2).strip() != "not set"
        return True

    return False


def _extract_kv_parts(parts: list[str]) -> dict[str, str]:
    """Extract 'key is value' pairs from comma-separated parts."""
    kv: dict[str, str] = {}
    for part in parts:
        if " is " in part:
            k, _, v = part.partition(" is ")
            kv[k.strip().lower()] = v.strip()
    return kv


def _apply_link_media(kv: dict[str, str], entry: dict) -> None:
    """Apply link_type and media_type from parsed key-value pairs."""
    if "link type" in kv:
        entry["link_type"] = kv["link type"]
    if "media type" in kv and kv["media type"]:
        entry["media_type"] = kv["media type"]


def _parse_duplex_speed(line: str, entry: dict) -> bool:
    """Parse duplex/speed/link_type/media_type line. Returns True if matched."""
    stripped = line.strip()
    first_token = stripped.split(",")[0].strip().lower().replace(" ", "-")
    if first_token not in _DUPLEX_SPEED_KEYWORDS:
        return False

    parts = [p.strip() for p in stripped.split(",")]
    if len(parts) < 2:
        return False

    duplex_val = parts[0]
    speed_val = parts[1]
    kv = _extract_kv_parts(parts[2:])

    if duplex_val == "Unknown" and speed_val == "Unknown":
        _apply_link_media(kv, entry)
        return True

    entry["duplex"] = duplex_val
    entry["speed"] = speed_val
    _apply_link_media(kv, entry)
    return True


def _parse_flow_control(line: str, entry: dict) -> bool:
    """Parse flow control line. Returns True if matched."""
    m = _FLOW_RE.match(line)
    if not m:
        return False
    if m.group(1):
        entry["output_flow_control"] = m.group(1)
    if m.group(2):
        entry["input_flow_control"] = m.group(2)
    if m.group(3):
        entry["output_flow_control"] = m.group(3)
    return True


def _parse_keepalive(line: str, entry: dict) -> bool:
    """Parse keepalive line. Returns True if matched."""
    m = _KEEPALIVE_RE.match(line)
    if not m:
        return False
    val = m.group(1)
    if val.startswith("set"):
        sec_m = re.search(r"\((\d+) sec\)", val)
        if sec_m:
            entry["keepalive"] = int(sec_m.group(1))
    # "not set" / "not supported" → omit
    return True


def _parse_queues(line: str, entry: dict) -> bool:
    """Parse queue lines. Returns True if matched."""
    m = _INPUT_QUEUE_RE.match(line)
    if m:
        entry["input_queue"] = {
            "size": int(m.group(1)),
            "max": int(m.group(2)),
            "drops": int(m.group(3)),
            "flushes": int(m.group(4)),
        }
        entry["total_output_drops"] = int(m.group(5))
        return True

    m = _OUTPUT_QUEUE_RE.match(line)
    if m:
        entry["output_queue"] = {
            "size": int(m.group(1)),
            "max": int(m.group(2)),
        }
        return True
    return False


def _parse_rates(line: str, entry: dict) -> bool:
    """Parse rate lines. Returns True if matched."""
    m = _RATE_INTERVAL_RE.match(line)
    if not m:
        return False
    interval = int(m.group(1))
    # Convert "5 minute" → 300, "30 second" → 30
    if "minute" in line:
        entry["rate_interval_seconds"] = interval * 60
    else:
        entry["rate_interval_seconds"] = interval
    rate = int(m.group(2))
    pps = int(m.group(3))
    if "input rate" in line:
        entry["input_rate_bps"] = rate
        entry["input_rate_pps"] = pps
    else:
        entry["output_rate_bps"] = rate
        entry["output_rate_pps"] = pps
    return True


def _parse_counters(lines: list[str]) -> CountersEntry:
    """Parse counter lines from a block."""
    counters: CountersEntry = {}
    for line in lines:
        for pattern, fields in _COUNTER_PATTERNS:
            m = pattern.match(line)
            if m:
                for group_idx, field_name in fields:
                    val = m.group(group_idx)
                    if val is not None:
                        counters[field_name] = int(val)  # type: ignore[literal-required]
                break
    return counters


def _apply_tunnel_source(m: re.Match[str], tunnel: TunnelInfo) -> None:
    """Apply tunnel source/destination fields from a match."""
    tunnel["source"] = m.group(1)
    if m.group(2):
        tunnel["source_interface"] = canonical_interface_name(
            m.group(2), os=OS.CISCO_IOS
        )
    if m.group(3):
        tunnel["destination"] = m.group(3)


_TUNNEL_STR_FIELDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_TUNNEL_LINESTATE_RE, "linestate_evaluation"),
    (_TUNNEL_PROTO_RE, "protocol"),
    (_TUNNEL_IPSEC_RE, "ipsec_profile"),
)

_TUNNEL_INT_FIELDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_TUNNEL_MTU_RE, "transport_mtu"),
    (_TUNNEL_TX_BW_RE, "transmit_bandwidth_kbps"),
    (_TUNNEL_RX_BW_RE, "receive_bandwidth_kbps"),
)


def _apply_tunnel_line(line: str, tunnel: TunnelInfo) -> None:
    """Try to match a single line against tunnel patterns."""
    for pattern, key in _TUNNEL_STR_FIELDS:
        m = pattern.match(line)
        if m:
            tunnel[key] = m.group(1)  # type: ignore[literal-required]
            return

    m = _TUNNEL_SOURCE_RE.match(line)
    if m:
        _apply_tunnel_source(m, tunnel)
        return

    m = _TUNNEL_TTL_RE.match(line)
    if m:
        tunnel["ttl"] = int(m.group(1))
        if m.group(2):
            tunnel["fast_tunneling"] = True
        return

    for pattern, key in _TUNNEL_INT_FIELDS:
        m = pattern.match(line)
        if m:
            tunnel[key] = int(m.group(1))  # type: ignore[literal-required]
            return

    m = _TUNNEL_KEY_SEQ_RE.match(line)
    if m:
        tunnel["key_disabled"] = m.group(1) == "disabled"
        tunnel["sequencing_disabled"] = m.group(2) == "disabled"
        return

    m = _TUNNEL_CKSUM_RE.match(line)
    if m:
        tunnel["checksumming_disabled"] = m.group(1) == "disabled"


def _parse_tunnel(lines: list[str]) -> TunnelInfo:
    """Parse tunnel-specific lines."""
    tunnel: TunnelInfo = {}
    for line in lines:
        _apply_tunnel_line(line, tunnel)
    return tunnel


def _parse_port_channel(lines: list[str]) -> PortChannelInfo:
    """Parse port-channel specific lines."""
    members: dict[str, PortChannelMemberEntry] = {}
    pc: PortChannelInfo = {"active_members": 0, "members": members}
    for line in lines:
        m = _PC_ACTIVE_RE.match(line)
        if m:
            pc["active_members"] = int(m.group(1))
            continue

        m = _PC_MEMBER_RE.match(line)
        if m:
            if_name = canonical_interface_name(m.group(1), os=OS.CISCO_IOS)
            members[if_name] = {
                "duplex": m.group(2).strip(),
                "speed": m.group(3),
            }
            continue

        m = _PC_JUMBO_RE.match(line)
        if m:
            pc["pf_jumbo_members"] = int(m.group(1))
            continue

        m = _PC_MEMBERS_IN_RE.match(line)
        if m:
            # "Members in this channel: Gi1/0/2" — short form without duplex/speed
            member_str = m.group(1).strip()
            for name in member_str.split():
                canon = canonical_interface_name(name, os=OS.CISCO_IOS)
                members[canon] = {"duplex": "", "speed": ""}
            pc["active_members"] = len(members)
            continue

    return pc


_TUNNEL_PATTERNS = (
    _TUNNEL_LINESTATE_RE,
    _TUNNEL_SOURCE_RE,
    _TUNNEL_PROTO_RE,
    _TUNNEL_TTL_RE,
    _TUNNEL_MTU_RE,
    _TUNNEL_TX_BW_RE,
    _TUNNEL_RX_BW_RE,
    _TUNNEL_KEY_SEQ_RE,
    _TUNNEL_CKSUM_RE,
    _TUNNEL_IPSEC_RE,
)

_PC_PATTERNS = (_PC_ACTIVE_RE, _PC_MEMBER_RE, _PC_JUMBO_RE, _PC_MEMBERS_IN_RE)

_COUNTER_START_RE = re.compile(r"^\s+\d+\s+")
_COUNTER_CONT_RE = re.compile(r"^\s+(Received|Output)\s+")


def _parse_header_fields(line: str, entry: dict) -> bool:
    """Parse header fields (hardware, description, IP, MTU, etc.)."""
    m = _HW_RE.match(line)
    if m:
        entry["hardware"] = m.group(1)
        if m.group(2):
            entry["address"] = m.group(2)
        if m.group(3):
            entry["bia"] = m.group(3)
        return True

    m = _DESC_RE.match(line)
    if m:
        entry["description"] = m.group(1)
        return True

    m = _IP_RE.match(line)
    if m:
        entry["ip_address"] = m.group(1)
        entry["ip_prefix_length"] = int(m.group(2))
        return True

    m = _UNNUMBERED_RE.match(line)
    if m:
        entry["unnumbered_interface"] = canonical_interface_name(
            m.group(1), os=OS.CISCO_IOS
        )
        entry["ip_address"] = m.group(2)
        return True

    m = _MTU_RE.match(line)
    if m:
        entry["mtu"] = int(m.group(1))
        entry["bandwidth_kbps"] = int(m.group(2))
        entry["delay_usec"] = int(m.group(3))
        return True

    m = _RELIABILITY_RE.match(line)
    if m:
        entry["reliability"] = m.group(1)
        entry["txload"] = m.group(2)
        entry["rxload"] = m.group(3)
        return True

    return False


def _parse_config_fields(line: str, stripped: str, entry: dict) -> bool:
    """Parse config fields (encap, keepalive, ARP, timestamps, etc.)."""
    if stripped.startswith("Encapsulation"):
        _parse_encapsulation(line, entry)
        return True

    if stripped.startswith("Keepalive"):
        _parse_keepalive(line, entry)
        return True

    m = _ARP_RE.match(line)
    if m:
        entry["arp_type"] = m.group(1)
        entry["arp_timeout"] = m.group(2)
        return True

    m = _AUTOSTATE_RE.match(line)
    if m:
        entry["autostate_enabled"] = m.group(1) == "enabled"
        return True

    m = _LAST_IO_RE.match(line)
    if m:
        entry["last_input"] = m.group(1)
        entry["last_output"] = m.group(2)
        entry["output_hang"] = m.group(3)
        return True

    m = _LAST_CLEAR_RE.match(line)
    if m:
        entry["last_clearing"] = m.group(1)
        return True

    return False


def _parse_stats_fields(line: str, entry: dict) -> bool:
    """Parse queue, rate, and media fields. Returns True if matched."""
    if _parse_queues(line, entry):
        return True

    m = _QUEUEING_RE.match(line)
    if m:
        entry["queueing_strategy"] = m.group(1)
        return True

    if _parse_rates(line, entry):
        return True

    m = _FEC_RE.match(line)
    if m:
        entry["fec"] = m.group(1)
        return True

    if _parse_flow_control(line, entry):
        return True

    if _parse_duplex_speed(line, entry):
        return True

    m = _SERIAL_SIGNALS_RE.match(line)
    if m:
        entry["serial_rts"] = m.group(1)
        entry["serial_cts"] = m.group(2)
        entry["serial_dtr"] = m.group(3)
        entry["serial_dcd"] = m.group(4)
        entry["serial_dsr"] = m.group(5)
        return True

    return False


def _try_parse_line(line: str, entry: dict) -> bool:
    """Try to parse a line as a known field. Returns True if matched."""
    if _parse_header_fields(line, entry):
        return True
    if _parse_config_fields(line, line.strip(), entry):
        return True
    return _parse_stats_fields(line, entry)


def _collect_counter_line(
    line: str, counter_lines: list[str], in_counters: bool
) -> bool:
    """Check if line is a counter line and collect it. Returns new in_counters."""
    if _COUNTER_START_RE.match(line):
        counter_lines.append(line)
        return True
    if in_counters and _COUNTER_CONT_RE.match(line):
        counter_lines.append(line)
        return True
    return in_counters


def _detect_type_specific(
    lines: list[str],
) -> tuple[bool, bool]:
    """Detect tunnel and port-channel lines in block. Returns (has_tunnel, has_pc)."""
    has_tunnel = False
    has_pc = False
    for line in lines:
        if not has_pc and any(p.match(line) for p in _PC_PATTERNS):
            has_pc = True
        if not has_tunnel and any(p.match(line) for p in _TUNNEL_PATTERNS):
            has_tunnel = True
        if has_tunnel and has_pc:
            break
    return has_tunnel, has_pc


def _finalize_block(entry: dict, body: list[str], counter_lines: list[str]) -> None:
    """Finalize a block by parsing counters, tunnel, and port-channel."""
    if counter_lines:
        counters = _parse_counters(counter_lines)
        if counters:
            entry["counters"] = counters

    has_tunnel, has_pc = _detect_type_specific(body)
    if has_tunnel:
        tunnel = _parse_tunnel(body)
        if tunnel:
            entry["tunnel"] = tunnel
    if has_pc:
        pc = _parse_port_channel(body)
        if pc:
            entry["port_channel"] = pc


def _parse_block(lines: list[str]) -> InterfaceEntry | None:
    """Parse a single interface block into an InterfaceEntry."""
    if not lines:
        return None

    entry: dict = _parse_status_line(lines[0])
    if not entry:
        return None

    counter_lines: list[str] = []
    in_counters = False

    for line in lines[1:]:
        if not line.strip():
            continue
        if _try_parse_line(line, entry):
            continue
        in_counters = _collect_counter_line(line, counter_lines, in_counters)

    _finalize_block(entry, lines[1:], counter_lines)
    return entry  # type: ignore[return-value]


@register(OS.CISCO_IOS, "show interfaces")
@register(OS.CISCO_IOSXE, "show interfaces")
class ShowInterfacesParser(BaseParser[ShowInterfacesResult]):
    """Parser for 'show interfaces' on IOS/IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesResult:
        """Parse 'show interfaces' output."""
        blocks = _split_blocks(output)
        interfaces: dict[str, InterfaceEntry] = {}

        for raw_name, block_lines in blocks:
            parsed = _parse_block(block_lines)
            if parsed is None:
                continue
            name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)
            interfaces[name] = parsed

        return {"interfaces": interfaces}
