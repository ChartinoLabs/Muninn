"""Parser for 'show ip ospf traffic' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class GlobalCounters(TypedDict):
    """Global OSPF traffic counters."""

    last_clearing: str
    received_total: int
    received_checksum_errors: int
    received_hello: int
    received_database_desc: int
    received_link_state_req: int
    received_link_state_updates: int
    received_link_state_acks: int
    sent_total: int
    sent_hello: int
    sent_database_desc: int
    sent_link_state_req: int
    sent_link_state_updates: int
    sent_link_state_acks: int


class QueueStats(TypedDict):
    """Per-queue statistics (InputQ, UpdateQ, OutputQ)."""

    limit: int
    drops: int
    max_delay: int
    max_size: int
    max_size_invalid: int
    max_size_hello: int
    max_size_db_des: int
    max_size_ls_req: int
    max_size_ls_upd: int
    max_size_ls_ack: int
    current_size: int
    current_size_invalid: int
    current_size_hello: int
    current_size_db_des: int
    current_size_ls_req: int
    current_size_ls_upd: int
    current_size_ls_ack: int


class ProcessQueueStats(TypedDict):
    """Queue statistics for an OSPF process."""

    router_id: str
    input_queue: QueueStats
    update_queue: QueueStats
    output_queue: QueueStats


class InterfacePacketCounters(TypedDict):
    """Packet type counters (packets and bytes)."""

    packets: int
    bytes: int


class InterfaceHeaderErrors(TypedDict):
    """OSPF header error counters for an interface."""

    length: NotRequired[int]
    instance_id: NotRequired[int]
    checksum: NotRequired[int]
    auth_type: NotRequired[int]
    version: NotRequired[int]
    no_virtual_link: NotRequired[int]
    area_mismatch: NotRequired[int]
    no_sham_link: NotRequired[int]
    self: NotRequired[int]
    duplicate_id: NotRequired[int]
    hello: NotRequired[int]
    mtu_mismatch: NotRequired[int]
    nbr_ignored: NotRequired[int]
    lls: NotRequired[int]
    unknown_neighbor: NotRequired[int]
    auth_failure: NotRequired[int]
    deleted: NotRequired[int]
    length_mismatch: NotRequired[int]


class InterfaceLsaErrors(TypedDict):
    """OSPF LSA error counters for an interface."""

    type: NotRequired[int]
    length: NotRequired[int]
    data: NotRequired[int]
    checksum: NotRequired[int]


class InterfaceStats(TypedDict):
    """Per-interface OSPF traffic statistics."""

    last_clearing: str
    rx_invalid: InterfacePacketCounters
    rx_hello: InterfacePacketCounters
    rx_db_des: InterfacePacketCounters
    rx_ls_req: InterfacePacketCounters
    rx_ls_upd: InterfacePacketCounters
    rx_ls_ack: InterfacePacketCounters
    tx_failed: InterfacePacketCounters
    tx_hello: InterfacePacketCounters
    tx_db_des: InterfacePacketCounters
    tx_ls_req: InterfacePacketCounters
    tx_ls_upd: InterfacePacketCounters
    tx_ls_ack: InterfacePacketCounters
    header_errors: NotRequired[InterfaceHeaderErrors]
    lsa_errors: NotRequired[InterfaceLsaErrors]


class ShowIpOspfTrafficResult(TypedDict):
    """Schema for 'show ip ospf traffic' parsed output."""

    global_counters: GlobalCounters
    processes: dict[str, ProcessQueueStats]
    interfaces: dict[str, InterfaceStats]


# Module-level compiled regexes
_GLOBAL_CLEARING_RE = re.compile(r"Last clearing of OSPF traffic counters (.+)")
_GLOBAL_RCVD_TOTAL_RE = re.compile(r"Rcvd:\s+(\d+)\s+total,\s+(\d+)\s+checksum errors")
_GLOBAL_RCVD_DETAIL_RE = re.compile(
    r"(\d+)\s+hello,\s+(\d+)\s+database desc,\s+(\d+)\s+link state req"
)
_GLOBAL_RCVD_DETAIL2_RE = re.compile(
    r"(\d+)\s+link state updates,\s+(\d+)\s+link state acks"
)
_GLOBAL_SENT_TOTAL_RE = re.compile(r"Sent:\s+(\d+)\s+total")
_PROCESS_HEADER_RE = re.compile(
    rf"OSPF Router with ID \(({IPV4_ADDRESS})\) \(Process ID (\d+)\)"
)
_QUEUE_HEADER_RE = re.compile(r"OSPF queue statistics for process ID (\d+):")
_INTERFACE_RE = re.compile(r"^\s*Interface\s+([A-Z]\S+)")
_INTF_CLEARING_RE = re.compile(r"Last clearing of interface traffic counters (.+)")
_PACKET_LINE_RE = re.compile(r"((?:RX|TX)\s+\S+(?:\s+\S+)?)\s+(\d+)\s+(\d+)")
_HEADER_ERROR_RE = re.compile(r"([A-Za-z][A-Za-z /]+?)\s+(\d+)")
_QUEUE_LINE_RE = re.compile(r"^\s+([\w ]+?)\s{2,}(\d+)\s+(\d+)\s+(\d+)")


def _try_global_line(
    line: str, result: dict[str, object], in_sent: bool
) -> bool | None:
    """Try to match a global counter line.

    Returns True if matched a rcvd total, None if matched sent total,
    False if matched detail line, or raises StopIteration to signal
    end of section. Returns None-like False for no match.
    """
    m = _GLOBAL_CLEARING_RE.search(line)
    if m:
        result["last_clearing"] = m.group(1).strip()
        return in_sent  # type: ignore[return-value]

    m = _GLOBAL_RCVD_TOTAL_RE.search(line)
    if m:
        result["received_total"] = int(m.group(1))
        result["received_checksum_errors"] = int(m.group(2))
        return False

    m = _GLOBAL_SENT_TOTAL_RE.search(line)
    if m:
        result["sent_total"] = int(m.group(1))
        return True

    prefix = "sent_" if in_sent else "received_"
    m = _GLOBAL_RCVD_DETAIL_RE.search(line)
    if m:
        result[f"{prefix}hello"] = int(m.group(1))
        result[f"{prefix}database_desc"] = int(m.group(2))
        result[f"{prefix}link_state_req"] = int(m.group(3))
        return in_sent  # type: ignore[return-value]

    m = _GLOBAL_RCVD_DETAIL2_RE.search(line)
    if m:
        result[f"{prefix}link_state_updates"] = int(m.group(1))
        result[f"{prefix}link_state_acks"] = int(m.group(2))
        return in_sent  # type: ignore[return-value]

    return None


def _parse_global_counters(lines: list[str]) -> tuple[GlobalCounters, int]:
    """Parse the global OSPF statistics section.

    Returns the counters and the index of the last consumed line.
    """
    result: dict[str, object] = {}
    idx = 0
    in_sent = False

    while idx < len(lines):
        line = lines[idx]

        if _PROCESS_HEADER_RE.search(line) or _QUEUE_HEADER_RE.search(line):
            break

        matched = _try_global_line(line, result, in_sent)
        if matched is not None:
            in_sent = bool(matched)

        idx += 1

    return cast(GlobalCounters, result), idx


_SECTION_LABELS: dict[str, str] = {
    "max size": "max_size_",
    "current size": "current_size_",
}


def _apply_queue_line(
    m: re.Match[str],
    queues: dict[str, dict[str, int]],
    queue_section: str,
) -> str:
    """Apply a single queue line match to the queues dict.

    Returns the updated queue_section prefix.
    """
    label = m.group(1).strip().lower()
    values = (int(m.group(2)), int(m.group(3)), int(m.group(4)))

    key = _queue_label_to_key(label, queue_section)
    if key:
        queues["input_queue"][key] = values[0]
        queues["update_queue"][key] = values[1]
        queues["output_queue"][key] = values[2]

    return _SECTION_LABELS.get(label, queue_section)


def _parse_queue_stats(
    lines: list[str], start: int
) -> tuple[dict[str, ProcessQueueStats], int]:
    """Parse OSPF queue statistics for all processes."""
    processes: dict[str, ProcessQueueStats] = {}
    idx = start
    current_process_id: str | None = None
    current_router_id: str = ""
    queues: dict[str, dict[str, int]] = {}
    queue_section: str = ""

    while idx < len(lines):
        line = lines[idx]

        m = _PROCESS_HEADER_RE.search(line)
        if m:
            current_router_id = m.group(1)
            current_process_id = m.group(2)
            idx += 1
            continue

        m = _QUEUE_HEADER_RE.search(line)
        if m:
            if current_process_id is None:
                current_process_id = m.group(1)
            queues = {
                "input_queue": {},
                "update_queue": {},
                "output_queue": {},
            }
            idx += 1
            continue

        if "Interface statistics:" in line:
            break

        m = _QUEUE_LINE_RE.match(line)
        if m and current_process_id is not None:
            queue_section = _apply_queue_line(m, queues, queue_section)
            idx += 1
            continue

        idx += 1

    # Store process if collected
    if current_process_id is not None and current_process_id not in processes:
        processes[current_process_id] = cast(
            ProcessQueueStats,
            {
                "router_id": current_router_id,
                **queues,
            },
        )

    return processes, idx


def _queue_label_to_key(label: str, section: str) -> str:
    """Map a queue row label to its dict key."""
    mapping: dict[str, str] = {
        "limit": "limit",
        "drops": "drops",
        "max delay": "max_delay",
        "max size": "max_size",
        "current size": "current_size",
        "invalid": "invalid",
        "hello": "hello",
        "db des": "db_des",
        "ls req": "ls_req",
        "ls upd": "ls_upd",
        "ls ack": "ls_ack",
    }
    base = mapping.get(label, "")
    if not base:
        return ""
    if section and base not in (
        "limit",
        "drops",
        "max_delay",
        "max_size",
        "current_size",
    ):
        return f"{section}{base}"
    return base


def _try_interface_packet_line(line: str, stats: dict[str, object]) -> bool:
    """Try to parse a packet counter line, return True if matched."""
    m = _PACKET_LINE_RE.search(line)
    if not m:
        return False
    pkt_type = m.group(1).strip().lower().replace(" ", "_")
    stats[pkt_type] = InterfacePacketCounters(
        packets=int(m.group(2)), bytes=int(m.group(3))
    )
    return True


def _parse_interface_stats(lines: list[str], start: int) -> dict[str, InterfaceStats]:
    """Parse per-interface OSPF traffic statistics."""
    interfaces: dict[str, InterfaceStats] = {}
    idx = start
    current_intf: str | None = None
    current_stats: dict[str, object] = {}
    error_section: str = ""
    header_errors: dict[str, int] = {}
    lsa_errors: dict[str, int] = {}

    while idx < len(lines):
        line = lines[idx]

        m = _INTERFACE_RE.match(line)
        if m:
            if current_intf is not None:
                _finalize_interface(
                    interfaces,
                    current_intf,
                    current_stats,
                    header_errors,
                    lsa_errors,
                )
            current_intf = canonical_interface_name(m.group(1), os=OS.CISCO_IOSXE)
            current_stats = {}
            header_errors = {}
            lsa_errors = {}
            error_section = ""
            idx += 1
            continue

        m = _INTF_CLEARING_RE.search(line)
        if m:
            current_stats["last_clearing"] = m.group(1).strip()
            error_section = ""
            idx += 1
            continue

        if "OSPF header errors" in line:
            error_section = "header"
            idx += 1
            continue

        if "OSPF LSA errors" in line:
            error_section = "lsa"
            idx += 1
            continue

        if error_section == "header":
            _parse_error_line(line, header_errors, _HEADER_ERROR_KEYS)
        elif error_section == "lsa":
            _parse_error_line(line, lsa_errors, _LSA_ERROR_KEYS)
        else:
            _try_interface_packet_line(line, current_stats)

        idx += 1

    if current_intf is not None:
        _finalize_interface(
            interfaces, current_intf, current_stats, header_errors, lsa_errors
        )

    return interfaces


# Header error field name mapping
_HEADER_ERROR_KEYS: dict[str, str] = {
    "length": "length",
    "instance id": "instance_id",
    "checksum": "checksum",
    "auth type": "auth_type",
    "version": "version",
    "no virtual link": "no_virtual_link",
    "area mismatch": "area_mismatch",
    "no sham link": "no_sham_link",
    "self": "self",
    "duplicate id": "duplicate_id",
    "hello": "hello",
    "mtu mismatch": "mtu_mismatch",
    "nbr ignored": "nbr_ignored",
    "lls": "lls",
    "unknown neighbor": "unknown_neighbor",
    "auth failure": "auth_failure",
    "deleted": "deleted",
    "length mismatch": "length_mismatch",
}

# LSA error field name mapping
_LSA_ERROR_KEYS: dict[str, str] = {
    "type": "type",
    "length": "length",
    "data": "data",
    "checksum": "checksum",
}


def _parse_error_line(
    line: str, errors: dict[str, int], key_map: dict[str, str]
) -> None:
    """Parse a comma-separated error counter line."""
    for m in _HEADER_ERROR_RE.finditer(line):
        label = m.group(1).strip().lower()
        value = int(m.group(2))
        key = key_map.get(label)
        if key and value != 0:
            errors[key] = value


def _finalize_interface(
    interfaces: dict[str, InterfaceStats],
    name: str,
    stats: dict[str, object],
    header_errors: dict[str, int],
    lsa_errors: dict[str, int],
) -> None:
    """Store completed interface stats into the result dict."""
    if header_errors:
        stats["header_errors"] = header_errors
    if lsa_errors:
        stats["lsa_errors"] = lsa_errors
    interfaces[name] = cast(InterfaceStats, stats)


@register(OS.CISCO_IOSXE, "show ip ospf traffic")
class ShowIpOspfTrafficParser(BaseParser[ShowIpOspfTrafficResult]):
    """Parser for 'show ip ospf traffic' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfTrafficResult:
        """Parse 'show ip ospf traffic' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed traffic statistics including global counters,
            per-process queue stats, and per-interface counters.

        Raises:
            ValueError: If required sections are missing.
        """
        lines = output.splitlines()

        global_counters, idx = _parse_global_counters(lines)
        processes, idx = _parse_queue_stats(lines, idx)
        interfaces = _parse_interface_stats(lines, idx)

        if not global_counters.get("last_clearing"):
            msg = "Missing required field: global_counters.last_clearing"
            raise ValueError(msg)

        return ShowIpOspfTrafficResult(
            global_counters=global_counters,
            processes=processes,
            interfaces=interfaces,
        )
