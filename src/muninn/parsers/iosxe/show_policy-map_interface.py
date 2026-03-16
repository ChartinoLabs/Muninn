"""Parser for 'show policy-map interface' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class PoliceEntry(TypedDict):
    """Schema for police configuration and statistics."""

    rate_bps: NotRequired[int]
    burst_bytes: NotRequired[int]
    cir_bps: NotRequired[int]
    bc_bytes: NotRequired[int]
    pir_bps: NotRequired[int]
    be_bytes: NotRequired[int]
    conformed_packets: NotRequired[int]
    conformed_bytes: int
    conformed_action: str
    conformed_bps: int
    exceeded_packets: NotRequired[int]
    exceeded_bytes: int
    exceeded_action: str
    exceeded_bps: int
    violated_packets: NotRequired[int]
    violated_bytes: NotRequired[int]
    violated_action: NotRequired[str]
    violated_bps: NotRequired[int]


class QueueingEntry(TypedDict):
    """Schema for queueing statistics."""

    queue_limit_packets: NotRequired[int]
    queue_limit_bytes: NotRequired[int]
    queue_depth: int
    total_drops: int
    no_buffer_drops: int
    pkts_output: NotRequired[int]
    bytes_output: NotRequired[int]
    bandwidth_kbps: NotRequired[int]
    bandwidth_percent: NotRequired[int]
    bandwidth_remaining_percent: NotRequired[int]
    bandwidth_remaining_ratio: NotRequired[int]


class ShapeEntry(TypedDict):
    """Schema for traffic shaping configuration."""

    type: str
    cir: int
    bc: int
    be: NotRequired[int]
    target_rate: NotRequired[int]


class QosSetEntry(TypedDict):
    """Schema for QoS set action."""

    type: str
    value: str
    packets_marked: NotRequired[int]
    table: NotRequired[str]


class PriorityEntry(TypedDict):
    """Schema for priority configuration."""

    kbps: NotRequired[int]
    burst_bytes: NotRequired[int]
    exceed_drops: NotRequired[int]
    level: NotRequired[int]


class ClassMapEntry(TypedDict):
    """Schema for a class-map entry within a service-policy."""

    match_type: str
    packets: int
    bytes: int
    offered_rate_bps: NotRequired[int]
    drop_rate_bps: NotRequired[int]
    match: NotRequired[list[str]]
    police: NotRequired[PoliceEntry]
    queueing: NotRequired[QueueingEntry]
    shape: NotRequired[ShapeEntry]
    qos_set: NotRequired[list[QosSetEntry]]
    priority: NotRequired[PriorityEntry]
    child_policy: NotRequired[str]
    child_classes: NotRequired[dict[str, "ClassMapEntry"]]


class ServicePolicyEntry(TypedDict):
    """Schema for a service-policy attached to an interface."""

    direction: str
    classes: dict[str, ClassMapEntry]


class InterfaceEntry(TypedDict):
    """Schema for an interface with service-policies."""

    service_policies: dict[str, ServicePolicyEntry]


# Top-level result: interface name -> InterfaceEntry
ShowPolicyMapInterfaceResult = dict[str, InterfaceEntry]


# -- Compiled regex patterns --

_INTERFACE_RE = re.compile(r"^\s*(\S+\d\S*)\s*$")

_SERVICE_POLICY_RE = re.compile(r"^\s*Service-policy\s+(input|output):\s+(\S+)")

_CHILD_SERVICE_POLICY_RE = re.compile(r"^\s*Service-policy\s*:\s+(\S+)")

_CLASS_MAP_RE = re.compile(r"^\s*Class-map:\s+(\S+)\s+\((match-(?:any|all))\)")

_PACKETS_BYTES_RE = re.compile(r"^\s*(\d+)\s+packets(?:,\s*(\d+)\s+bytes)?")

_OFFERED_DROP_RATE_RE = re.compile(
    r"^\s*(?:\d+\s+(?:second|minute)\s+)?offered\s+rate\s+(\d+)\s+bps"
    r"(?:,\s+drop\s+rate\s+(\d+)\s+bps)?"
)

_MATCH_RE = re.compile(r"^\s*Match:\s+(.*\S)")

_POLICE_RATE_RE = re.compile(r"^\s*rate\s+(\d+)\s+bps,\s+burst\s+(\d+)\s+bytes")

_POLICE_CIR_RE = re.compile(r"^\s*cir\s+(\d+)\s+bps,\s+bc\s+(\d+)\s+bytes")

_POLICE_PIR_RE = re.compile(r"^\s*pir\s+(\d+)\s+bps,\s+be\s+(\d+)\s+bytes")

_CONFORMED_RE = re.compile(
    r"^\s*conformed\s+(?:(\d+)\s+packets,\s+)?(\d+)\s+bytes;\s+actions:"
)

_EXCEEDED_RE = re.compile(
    r"^\s*exceeded\s+(?:(\d+)\s+packets,\s+)?(\d+)\s+bytes;\s+actions:"
)

_VIOLATED_RE = re.compile(
    r"^\s*violated\s+(?:(\d+)\s+packets,\s+)?(\d+)\s+bytes;\s+actions:"
)

_CONFORMED_BPS_RE = re.compile(
    r"^\s*conformed\s+(\d+)\s+bps,\s+exceeded\s+(\d+)\s+bps"
    r"(?:,\s+violated\s+(\d+)\s+bps)?"
)

_ACTION_RE = re.compile(r"^\s*(transmit|drop|set-\S+)")

_QUEUE_LIMIT_PACKETS_RE = re.compile(r"^\s*queue\s+limit\s+(\d+)\s+packets")

_QUEUE_LIMIT_BYTES_RE = re.compile(r"^\s*queue\s+limit\s+(\d+)\s+bytes")

_QUEUE_DEPTH_RE = re.compile(
    r"^\s*\(?queue\s+depth/total\s+drops/no-buffer\s+drops\)?\s+(\d+)/(\d+)/(\d+)"
)

_PKTS_OUTPUT_RE = re.compile(r"^\s*\(?pkts\s+output/bytes\s+output\)?\s+(\d+)/(\d+)")

_BANDWIDTH_KBS_RE = re.compile(r"^\s*bandwidth\s+(\d+)\s+(?:\(?\s*kbps\s*\)?|kbps)")

_BANDWIDTH_PCT_RE = re.compile(r"^\s*bandwidth\s+(\d+)\s*(?:\(?\s*%\s*\)?|%)")

_BANDWIDTH_REMAINING_PCT_RE = re.compile(r"^\s*bandwidth\s+remaining\s+(\d+)%")

_BANDWIDTH_REMAINING_RATIO_RE = re.compile(r"^\s*bandwidth\s+remaining\s+ratio\s+(\d+)")

_SHAPE_RE = re.compile(
    r"^\s*shape\s+\((\w+)\)\s+cir\s+(\d+),\s+bc\s+(\d+)"
    r"(?:,\s+be\s+(\d+))?"
)

_TARGET_SHAPE_RE = re.compile(r"^\s*target\s+shape\s+rate\s+(\d+)")

_QOS_SET_RE = re.compile(
    r"^\s*(dscp|ip\s+precedence|qos-group|traffic-class"
    r"|cos|discard-class)\s+(\S+)"
)

_QOS_SET_TABLE_RE = re.compile(r"^\s*(dscp|traffic-class)\s+(\S+)\s+table\s+(\S+)")

_PACKETS_MARKED_RE = re.compile(r"^\s*Packets\s+marked\s+(\d+)")

_PRIORITY_RE = re.compile(
    r"^\s*Priority:\s+(\d+)\s+kbps,\s+burst\s+bytes\s+(\d+)"
    r"(?:,\s+b/w\s+exceed\s+drops:\s+(\d+))?"
)

_PRIORITY_LEVEL_RE = re.compile(r"^\s*priority\s+level\s+(\d+)")


def _get_indent(line: str) -> int:
    """Return the number of leading spaces in a line."""
    return len(line) - len(line.lstrip())


def _find_next_action(lines: list[str], idx: int) -> tuple[str | None, int]:
    """Find the next police action line (transmit/drop/set-*).

    Returns the action string and updated index.
    """
    total = len(lines)
    while idx < total:
        action_line = lines[idx].strip()
        action_m = _ACTION_RE.match(action_line)
        if action_m:
            return action_m.group(1), idx + 1
        idx += 1
    return None, idx


def _parse_police_counters(
    lines: list[str],
    idx: int,
    stripped: str,
    police: dict[str, object],
) -> tuple[bool, int]:
    """Parse conformed/exceeded/violated counter lines.

    Returns (matched, updated_idx).
    """
    conf_m = _CONFORMED_RE.match(stripped)
    if conf_m:
        if conf_m.group(1) is not None:
            police["conformed_packets"] = int(conf_m.group(1))
        police["conformed_bytes"] = int(conf_m.group(2))
        action, idx = _find_next_action(lines, idx + 1)
        if action is not None:
            police["conformed_action"] = action
        return True, idx

    exc_m = _EXCEEDED_RE.match(stripped)
    if exc_m:
        if exc_m.group(1) is not None:
            police["exceeded_packets"] = int(exc_m.group(1))
        police["exceeded_bytes"] = int(exc_m.group(2))
        action, idx = _find_next_action(lines, idx + 1)
        if action is not None:
            police["exceeded_action"] = action
        return True, idx

    viol_m = _VIOLATED_RE.match(stripped)
    if viol_m:
        if viol_m.group(1) is not None:
            police["violated_packets"] = int(viol_m.group(1))
        police["violated_bytes"] = int(viol_m.group(2))
        action, idx = _find_next_action(lines, idx + 1)
        if action is not None:
            police["violated_action"] = action
        return True, idx

    return False, idx


def _parse_police_rates(
    stripped: str,
    police: dict[str, object],
) -> bool:
    """Parse police rate/cir/pir configuration lines.

    Returns True if a match was found.
    """
    rate_m = _POLICE_RATE_RE.match(stripped)
    if rate_m:
        police["rate_bps"] = int(rate_m.group(1))
        police["burst_bytes"] = int(rate_m.group(2))
        return True

    cir_m = _POLICE_CIR_RE.match(stripped)
    if cir_m:
        police["cir_bps"] = int(cir_m.group(1))
        police["bc_bytes"] = int(cir_m.group(2))
        return True

    pir_m = _POLICE_PIR_RE.match(stripped)
    if pir_m:
        police["pir_bps"] = int(pir_m.group(1))
        police["be_bytes"] = int(pir_m.group(2))
        return True

    return False


def _parse_police_block(lines: list[str], start: int) -> tuple[PoliceEntry | None, int]:
    """Parse a police block starting after the 'police:' line.

    Returns the PoliceEntry and the index of the last consumed line.
    """
    idx = start
    total = len(lines)
    police: dict[str, object] = {}

    while idx < total:
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue

        if _parse_police_rates(stripped, police):
            idx += 1
            continue

        matched, idx = _parse_police_counters(lines, idx, stripped, police)
        if matched:
            continue

        bps_m = _CONFORMED_BPS_RE.match(stripped)
        if bps_m:
            police["conformed_bps"] = int(bps_m.group(1))
            police["exceeded_bps"] = int(bps_m.group(2))
            if bps_m.group(3) is not None:
                police["violated_bps"] = int(bps_m.group(3))
            idx += 1
            break

        # Unrecognized line ends the police block
        break

    if "conformed_bytes" not in police or "conformed_action" not in police:
        return None, idx

    return PoliceEntry(**police), idx  # type: ignore[arg-type]


def _try_match_queue_stats(
    stripped: str,
    queueing: dict[str, object],
) -> bool:
    """Try to match a single queueing statistics line.

    Returns True if matched.
    """
    ql_pkt_m = _QUEUE_LIMIT_PACKETS_RE.match(stripped)
    if ql_pkt_m:
        queueing["queue_limit_packets"] = int(ql_pkt_m.group(1))
        return True

    ql_byte_m = _QUEUE_LIMIT_BYTES_RE.match(stripped)
    if ql_byte_m:
        queueing["queue_limit_bytes"] = int(ql_byte_m.group(1))
        return True

    qd_m = _QUEUE_DEPTH_RE.match(stripped)
    if qd_m:
        queueing["queue_depth"] = int(qd_m.group(1))
        queueing["total_drops"] = int(qd_m.group(2))
        queueing["no_buffer_drops"] = int(qd_m.group(3))
        return True

    po_m = _PKTS_OUTPUT_RE.match(stripped)
    if po_m:
        queueing["pkts_output"] = int(po_m.group(1))
        queueing["bytes_output"] = int(po_m.group(2))
        return True

    return False


def _try_match_bandwidth(
    stripped: str,
    queueing: dict[str, object],
) -> bool:
    """Try to match a bandwidth line for queueing.

    Returns True if matched.
    """
    bw_rem_ratio_m = _BANDWIDTH_REMAINING_RATIO_RE.match(stripped)
    if bw_rem_ratio_m:
        queueing["bandwidth_remaining_ratio"] = int(bw_rem_ratio_m.group(1))
        return True

    bw_rem_pct_m = _BANDWIDTH_REMAINING_PCT_RE.match(stripped)
    if bw_rem_pct_m:
        queueing["bandwidth_remaining_percent"] = int(bw_rem_pct_m.group(1))
        return True

    bw_kbps_m = _BANDWIDTH_KBS_RE.match(stripped)
    if bw_kbps_m:
        queueing["bandwidth_kbps"] = int(bw_kbps_m.group(1))
        return True

    bw_pct_m = _BANDWIDTH_PCT_RE.match(stripped)
    if bw_pct_m:
        queueing["bandwidth_percent"] = int(bw_pct_m.group(1))
        return True

    return False


def _parse_queueing(class_entry: ClassMapEntry, lines: list[str], idx: int) -> int:
    """Parse queueing-related lines into the class entry.

    Returns the index after the last consumed queueing line.
    """
    total = len(lines)
    queueing: dict[str, object] = {}

    while idx < total:
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue

        if _try_match_queue_stats(stripped, queueing):
            idx += 1
            continue

        if _try_match_bandwidth(stripped, queueing):
            idx += 1
            continue

        break

    if "queue_depth" in queueing:
        class_entry["queueing"] = QueueingEntry(**queueing)  # type: ignore[arg-type]

    return idx


def _parse_shape(class_entry: ClassMapEntry, lines: list[str], idx: int) -> int:
    """Parse shape and target shape rate lines.

    Returns updated index.
    """
    stripped = lines[idx].strip()
    shape_m = _SHAPE_RE.match(stripped)
    if not shape_m:
        return idx

    shape: dict[str, object] = {
        "type": shape_m.group(1),
        "cir": int(shape_m.group(2)),
        "bc": int(shape_m.group(3)),
    }
    if shape_m.group(4) is not None:
        shape["be"] = int(shape_m.group(4))

    idx += 1
    total = len(lines)

    while idx < total:
        next_stripped = lines[idx].strip()
        if not next_stripped:
            idx += 1
            continue
        target_m = _TARGET_SHAPE_RE.match(next_stripped)
        if target_m:
            shape["target_rate"] = int(target_m.group(1))
            idx += 1
        break

    class_entry["shape"] = ShapeEntry(**shape)  # type: ignore[arg-type]
    return idx


def _parse_qos_set_block(class_entry: ClassMapEntry, lines: list[str], idx: int) -> int:
    """Parse QoS Set block lines.

    Returns updated index.
    """
    total = len(lines)
    qos_set_list: list[QosSetEntry] = list(class_entry.get("qos_set", []))

    while idx < total:
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue

        table_m = _QOS_SET_TABLE_RE.match(stripped)
        if table_m:
            entry = QosSetEntry(
                type=table_m.group(1),
                value=table_m.group(2),
                table=table_m.group(3),
            )
            qos_set_list.append(entry)
            idx += 1
            continue

        qos_m = _QOS_SET_RE.match(stripped)
        if qos_m:
            entry = QosSetEntry(
                type=qos_m.group(1).strip(),
                value=qos_m.group(2),
            )
            idx += 1
            # Check for Packets marked on next line
            while idx < total:
                next_s = lines[idx].strip()
                if not next_s:
                    idx += 1
                    continue
                marked_m = _PACKETS_MARKED_RE.match(next_s)
                if marked_m:
                    entry["packets_marked"] = int(marked_m.group(1))
                    idx += 1
                break
            qos_set_list.append(entry)
            continue

        break

    if qos_set_list:
        class_entry["qos_set"] = qos_set_list

    return idx


def _parse_child_policy(
    class_entry: ClassMapEntry,
    lines: list[str],
    idx: int,
    child_indent: int,
) -> int:
    """Parse child service-policy classes.

    Returns updated index.
    """
    total = len(lines)
    child_classes: dict[str, ClassMapEntry] = {}

    while idx < total:
        child_line = lines[idx]
        child_stripped = child_line.strip()
        if not child_stripped:
            idx += 1
            continue
        child_line_indent = _get_indent(child_line)
        if child_line_indent <= child_indent:
            break
        child_cm_m = _CLASS_MAP_RE.match(child_stripped)
        if child_cm_m:
            child_name = child_cm_m.group(1)
            child_entry, idx = _parse_class_block(lines, idx, child_line_indent - 2)
            child_classes[child_name] = child_entry
        else:
            idx += 1

    if child_classes:
        class_entry["child_classes"] = child_classes

    return idx


def _handle_stats_line(
    class_entry: ClassMapEntry,
    matches: list[str],
    stripped: str,
) -> bool:
    """Handle packet/byte count, rate, and match lines.

    Returns True if matched.
    """
    pb_m = _PACKETS_BYTES_RE.match(stripped)
    if pb_m:
        class_entry["packets"] = int(pb_m.group(1))
        if pb_m.group(2) is not None:
            class_entry["bytes"] = int(pb_m.group(2))
        return True

    rate_m = _OFFERED_DROP_RATE_RE.match(stripped)
    if rate_m:
        class_entry["offered_rate_bps"] = int(rate_m.group(1))
        if rate_m.group(2) is not None:
            class_entry["drop_rate_bps"] = int(rate_m.group(2))
        return True

    match_m = _MATCH_RE.match(stripped)
    if match_m:
        matches.append(match_m.group(1).strip())
        return True

    return False


def _handle_policy_block(
    class_entry: ClassMapEntry,
    lines: list[str],
    idx: int,
    stripped: str,
) -> tuple[bool, int]:
    """Handle police, queueing, shape, and QoS set block headers.

    Returns (handled, updated_idx).
    """
    if stripped == "police:":
        police_entry, new_idx = _parse_police_block(lines, idx + 1)
        if police_entry is not None:
            class_entry["police"] = police_entry
        return True, new_idx

    if stripped == "Queueing":
        return True, _parse_queueing(class_entry, lines, idx + 1)

    if _SHAPE_RE.match(stripped):
        return True, _parse_shape(class_entry, lines, idx)

    target_m = _TARGET_SHAPE_RE.match(stripped)
    if target_m:
        if "shape" in class_entry:
            class_entry["shape"]["target_rate"] = int(target_m.group(1))
        return True, idx + 1

    if stripped == "QoS Set":
        return True, _parse_qos_set_block(class_entry, lines, idx + 1)

    return False, idx


def _handle_priority_line(
    class_entry: ClassMapEntry,
    stripped: str,
) -> bool:
    """Handle priority-related lines.

    Returns True if matched.
    """
    prio_m = _PRIORITY_RE.match(stripped)
    if prio_m:
        prio: dict[str, object] = {
            "kbps": int(prio_m.group(1)),
            "burst_bytes": int(prio_m.group(2)),
        }
        if prio_m.group(3) is not None:
            prio["exceed_drops"] = int(prio_m.group(3))
        class_entry["priority"] = PriorityEntry(**prio)  # type: ignore[arg-type]
        return True

    prio_lvl_m = _PRIORITY_LEVEL_RE.match(stripped)
    if prio_lvl_m:
        prio_entry: PriorityEntry = class_entry.get("priority", {})  # type: ignore[assignment]
        prio_entry["level"] = int(prio_lvl_m.group(1))
        class_entry["priority"] = prio_entry
        return True

    return False


def _handle_bandwidth_line(
    class_entry: ClassMapEntry,
    stripped: str,
) -> bool:
    """Handle bandwidth lines that appear outside a Queueing block.

    Returns True if matched.
    """
    if "queueing" not in class_entry:
        return False

    bw_rem_ratio_m = _BANDWIDTH_REMAINING_RATIO_RE.match(stripped)
    if bw_rem_ratio_m:
        class_entry["queueing"]["bandwidth_remaining_ratio"] = int(
            bw_rem_ratio_m.group(1)
        )
        return True

    bw_rem_pct_m = _BANDWIDTH_REMAINING_PCT_RE.match(stripped)
    if bw_rem_pct_m:
        class_entry["queueing"]["bandwidth_remaining_percent"] = int(
            bw_rem_pct_m.group(1)
        )
        return True

    bw_kbps_m = _BANDWIDTH_KBS_RE.match(stripped)
    if bw_kbps_m:
        class_entry["queueing"]["bandwidth_kbps"] = int(bw_kbps_m.group(1))
        return True

    if not stripped.startswith("bandwidth remaining"):
        bw_pct_m = _BANDWIDTH_PCT_RE.match(stripped)
        if bw_pct_m:
            class_entry["queueing"]["bandwidth_percent"] = int(bw_pct_m.group(1))
            return True

    return False


def _dispatch_class_line(
    class_entry: ClassMapEntry,
    matches: list[str],
    lines: list[str],
    idx: int,
    stripped: str,
    indent: int,
) -> int:
    """Dispatch a single line inside a class-map block.

    Returns updated index.
    """
    child_sp_m = _CHILD_SERVICE_POLICY_RE.match(stripped)
    if child_sp_m:
        class_entry["child_policy"] = child_sp_m.group(1)
        return _parse_child_policy(class_entry, lines, idx + 1, indent)

    if _handle_stats_line(class_entry, matches, stripped):
        return idx + 1

    handled, new_idx = _handle_policy_block(class_entry, lines, idx, stripped)
    if handled:
        return new_idx

    if _handle_priority_line(class_entry, stripped):
        return idx + 1

    if _handle_bandwidth_line(class_entry, stripped):
        return idx + 1

    return idx + 1


def _parse_class_block(
    lines: list[str],
    start: int,
    class_indent: int,
) -> tuple[ClassMapEntry, int]:
    """Parse a class-map block starting at the Class-map line.

    Returns the ClassMapEntry and the index after the last consumed line.
    """
    cm_m = _CLASS_MAP_RE.match(lines[start].strip())
    if cm_m is None:
        msg = f"Expected Class-map line at index {start}"
        raise ValueError(msg)

    class_entry = ClassMapEntry(
        match_type=cm_m.group(2),
        packets=0,
        bytes=0,
    )

    idx = start + 1
    total = len(lines)
    matches: list[str] = []

    while idx < total:
        line = lines[idx]
        stripped = line.strip()

        if not stripped:
            idx += 1
            continue

        indent = _get_indent(line)
        if indent <= class_indent:
            break

        if _CLASS_MAP_RE.match(stripped) and indent == class_indent + 2:
            break

        idx = _dispatch_class_line(class_entry, matches, lines, idx, stripped, indent)

    if matches:
        class_entry["match"] = matches

    return class_entry, idx


def _parse_service_policy(
    lines: list[str],
    idx: int,
    sp_indent: int,
) -> tuple[dict[str, ClassMapEntry], int]:
    """Parse class-maps within a service-policy block.

    Returns the classes dict and updated index.
    """
    total = len(lines)
    classes: dict[str, ClassMapEntry] = {}

    while idx < total:
        inner_line = lines[idx]
        inner_stripped = inner_line.strip()

        if not inner_stripped:
            idx += 1
            continue

        inner_indent = _get_indent(inner_line)

        if inner_indent <= sp_indent:
            break

        cm_m = _CLASS_MAP_RE.match(inner_stripped)
        if cm_m:
            class_name = cm_m.group(1)
            class_entry, idx = _parse_class_block(lines, idx, inner_indent - 2)
            classes[class_name] = class_entry
        else:
            idx += 1

    return classes, idx


def _save_interface(
    result: ShowPolicyMapInterfaceResult,
    interface: str | None,
    policies: dict[str, ServicePolicyEntry],
) -> None:
    """Save accumulated policies for an interface into the result dict."""
    if interface is not None and policies:
        result[interface] = InterfaceEntry(service_policies=policies)


def _build_result(output: str) -> ShowPolicyMapInterfaceResult:
    """Build the full result dict from raw CLI output."""
    result: ShowPolicyMapInterfaceResult = {}
    lines = output.splitlines()
    total = len(lines)
    idx = 0

    current_interface: str | None = None
    current_policies: dict[str, ServicePolicyEntry] = {}

    while idx < total:
        line = lines[idx]
        stripped = line.strip()

        if not stripped:
            idx += 1
            continue

        sp_m = _SERVICE_POLICY_RE.match(stripped)
        if sp_m:
            sp_indent = _get_indent(line)
            classes, idx = _parse_service_policy(lines, idx + 1, sp_indent)
            policy_name = sp_m.group(2)
            current_policies[policy_name] = ServicePolicyEntry(
                direction=sp_m.group(1),
                classes=classes,
            )
            continue

        iface_m = _INTERFACE_RE.match(stripped)
        if iface_m:
            _save_interface(result, current_interface, current_policies)
            current_interface = canonical_interface_name(
                iface_m.group(1), os=OS.CISCO_IOSXE
            )
            current_policies = {}
            idx += 1
            continue

        idx += 1

    _save_interface(result, current_interface, current_policies)
    return result


@register(OS.CISCO_IOSXE, "show policy-map interface")
class ShowPolicyMapInterfaceParser(
    BaseParser[ShowPolicyMapInterfaceResult],
):
    """Parser for 'show policy-map interface' command.

    Example output::

        GigabitEthernet0/0/0
          Service-policy output: my-policy
            Class-map: class-default (match-any)
              100 packets, 5000 bytes
              Match: any
    """

    tags: ClassVar[frozenset[str]] = frozenset({"qos"})

    @classmethod
    def parse(cls, output: str) -> ShowPolicyMapInterfaceResult:
        """Parse 'show policy-map interface' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed policy-map interface data keyed by interface name.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result = _build_result(output)

        if not result:
            msg = "No policy-map interface data found in output"
            raise ValueError(msg)

        return result
