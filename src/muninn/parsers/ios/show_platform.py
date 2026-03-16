"""Parser for 'show platform' command on IOS/IOS-XE.

Handles two fundamentally different output formats:
- Chassis-based (ASR/ISR/C8300/C9500): slot tables with CPLD/firmware versions
- Stack-based (Catalyst 3850/9300): switch inventory and stack role tables
"""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# --- TypedDict schema ---


class SubslotEntry(TypedDict):
    """Schema for a subslot within a chassis slot."""

    type: str
    state: str
    insert_time: str


class SlotEntry(TypedDict):
    """Schema for a chassis slot entry."""

    state: str
    type: NotRequired[str]
    insert_time: NotRequired[str]
    cpld_version: NotRequired[str]
    firmware_version: NotRequired[str]
    subslots: NotRequired[dict[str, SubslotEntry]]


class SwitchEntry(TypedDict):
    """Schema for a switch in a stack."""

    ports: int
    model: str
    serial_no: str
    mac_address: str
    hw_version: str
    sw_version: str


class StackMemberEntry(TypedDict):
    """Schema for a stack member role entry."""

    role: str
    priority: int
    state: str


class StackInfo(TypedDict):
    """Schema for stack metadata."""

    mac_address: NotRequired[str]
    mac_persistency_wait_time: NotRequired[str]
    members: dict[str, StackMemberEntry]


class ShowPlatformResult(TypedDict):
    """Schema for 'show platform' parsed output."""

    chassis_type: NotRequired[str]
    slots: NotRequired[dict[str, SlotEntry]]
    switches: NotRequired[dict[str, SwitchEntry]]
    stack: NotRequired[StackInfo]


# --- Regex patterns ---

_CHASSIS_TYPE_RE = re.compile(r"^Chassis\s+type:\s*(\S+)\s*$")

# Subslot identifier pattern (e.g., " 0/1")
_SUBSLOT_ID_RE = re.compile(r"^\s+(\d+)/(\d+)")

# CPLD/firmware version table row
_CPLD_FW_RE = re.compile(r"^(\S+)\s{2,}(\S+)\s{2,}(\S+)\s*$")

# Switch inventory table row
_SWITCH_RE = re.compile(
    r"^\s*\*?(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+"
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)\s*$",
    re.IGNORECASE,
)

# Stack role table row
_STACK_ROLE_RE = re.compile(
    r"^\s*\*?(\d+)\s+(Active|Standby|Member)\s+(\d+)\s+(\S+)\s*$"
)

# Stack MAC address line
_STACK_MAC_RE = re.compile(
    r"^Switch/Stack\s+Mac\s+Address\s*:\s*"
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
    re.IGNORECASE,
)

# Mac persistency wait time
_MAC_PERSIST_RE = re.compile(
    r"^Mac\s+persistency\s+wait\s+time:\s*(.+?)\s*$", re.IGNORECASE
)

# Table separator / header lines to skip
_SEPARATOR_RE = re.compile(r"^[-\s]+$")
_SLOT_HEADER_RE = re.compile(r"^\s*Slot\s+", re.IGNORECASE)
_SWITCH_HEADER_RE = re.compile(r"^\s*Switch\s+Ports\s+", re.IGNORECASE)
_ROLE_HEADER_RE = re.compile(r"^\s*Switch#?\s+Role\s+", re.IGNORECASE)
_CURRENT_HEADER_RE = re.compile(r"^\s*Current\s*$")

_NA_VALUE = "N/A"


def _parse_chassis_type(lines: list[str]) -> str | None:
    """Extract chassis type from output lines."""
    for line in lines:
        m = _CHASSIS_TYPE_RE.match(line)
        if m:
            return m.group(1)
    return None


class _SlotColumns:
    """Column positions extracted from the slot table header."""

    def __init__(self, type_col: int, state_col: int, insert_col: int) -> None:
        self.type_col = type_col
        self.state_col = state_col
        self.insert_col = insert_col


def _parse_slot_row(line: str, cols: _SlotColumns) -> tuple[str, str, str, str]:
    """Extract slot name, type, state, and insert_time from a row."""
    slot_name = line[: cols.type_col].strip()
    slot_type = line[cols.type_col : cols.state_col].strip()
    state = line[cols.state_col : cols.insert_col].strip()
    insert_time = line[cols.insert_col :].strip()
    return slot_name, slot_type, state, insert_time


def _add_subslot(
    m: re.Match[str],
    line: str,
    cols: _SlotColumns,
    slots: dict[str, SlotEntry],
    current_parent: str | None,
) -> str | None:
    """Add a subslot entry to the parent slot. Returns updated parent."""
    parent_num = m.group(1)
    sub_num = m.group(2)
    _, sub_type, sub_state, sub_insert = _parse_slot_row(line, cols)
    subslot_entry: SubslotEntry = {
        "type": sub_type,
        "state": sub_state,
        "insert_time": sub_insert,
    }
    if parent_num in slots:
        current_parent = parent_num
    if current_parent and current_parent in slots:
        if "subslots" not in slots[current_parent]:
            slots[current_parent]["subslots"] = {}
        slots[current_parent]["subslots"][sub_num] = subslot_entry
    return current_parent


def _parse_slot_table(lines: list[str], cols: _SlotColumns) -> dict[str, SlotEntry]:
    """Parse the slot/subslot table into a dict keyed by slot name."""
    slots: dict[str, SlotEntry] = {}
    current_parent: str | None = None

    for line in lines:
        if not line.strip():
            continue

        m = _SUBSLOT_ID_RE.match(line)
        if m:
            current_parent = _add_subslot(m, line, cols, slots, current_parent)
            continue

        slot_name, slot_type, state, insert_time = _parse_slot_row(line, cols)
        if not slot_name or not state:
            continue

        entry: SlotEntry = {"state": state}
        if slot_type:
            entry["type"] = slot_type
        if insert_time:
            entry["insert_time"] = insert_time

        slots[slot_name] = entry
        current_parent = slot_name if slot_name.isdigit() else None

    return slots


def _find_slot_section(
    lines: list[str],
) -> tuple[list[str], _SlotColumns | None]:
    """Extract lines and column positions from the slot table section."""
    section: list[str] = []
    cols: _SlotColumns | None = None
    in_section = False

    for line in lines:
        if _SLOT_HEADER_RE.match(line) and "Type" in line:
            in_section = True
            type_col = line.index("Type")
            state_col = line.index("State")
            insert_col = line.index("Insert")
            cols = _SlotColumns(type_col, state_col, insert_col)
            continue
        if in_section:
            if _SEPARATOR_RE.match(line):
                continue
            if _SLOT_HEADER_RE.match(line) and "CPLD" in line:
                break
            if not line.strip():
                continue
            if line.strip():
                section.append(line)

    return section, cols


def _merge_cpld_firmware(lines: list[str], slots: dict[str, SlotEntry]) -> None:
    """Merge CPLD/firmware version data into existing slot entries."""
    cpld_lines = _extract_cpld_lines(lines)
    for line in cpld_lines:
        m = _CPLD_FW_RE.match(line)
        if not m or m.group(1) not in slots:
            continue
        slot = slots[m.group(1)]
        if m.group(2) != _NA_VALUE:
            slot["cpld_version"] = m.group(2)
        if m.group(3) != _NA_VALUE:
            slot["firmware_version"] = m.group(3)


def _extract_cpld_lines(lines: list[str]) -> list[str]:
    """Extract data lines from the CPLD/firmware section."""
    in_cpld = False
    result: list[str] = []
    for line in lines:
        if _SLOT_HEADER_RE.match(line) and "CPLD" in line:
            in_cpld = True
            continue
        if not in_cpld or _SEPARATOR_RE.match(line) or not line.strip():
            continue
        result.append(line)
    return result


def _parse_switch_table(lines: list[str]) -> dict[str, SwitchEntry]:
    """Parse the switch inventory table."""
    switches: dict[str, SwitchEntry] = {}

    for line in lines:
        m = _SWITCH_RE.match(line)
        if m:
            switch_num = m.group(1)
            switches[switch_num] = {
                "ports": int(m.group(2)),
                "model": m.group(3),
                "serial_no": m.group(4),
                "mac_address": m.group(5),
                "hw_version": m.group(6),
                "sw_version": m.group(7),
            }

    return switches


def _parse_stack_info(lines: list[str]) -> StackInfo | None:
    """Parse stack role table and metadata."""
    members: dict[str, StackMemberEntry] = {}
    mac_address: str | None = None
    mac_persistency: str | None = None

    for line in lines:
        m = _STACK_ROLE_RE.match(line)
        if m:
            members[m.group(1)] = {
                "role": m.group(2),
                "priority": int(m.group(3)),
                "state": m.group(4),
            }
            continue

        m = _STACK_MAC_RE.match(line)
        if m:
            mac_address = m.group(1)
            continue

        m = _MAC_PERSIST_RE.match(line)
        if m:
            mac_persistency = m.group(1)

    if not members:
        return None

    stack: StackInfo = {"members": members}
    if mac_address:
        stack["mac_address"] = mac_address
    if mac_persistency:
        stack["mac_persistency_wait_time"] = mac_persistency

    return stack


def _is_chassis_format(lines: list[str]) -> bool:
    """Detect whether output is chassis-based (vs stack-based)."""
    for line in lines:
        if _CHASSIS_TYPE_RE.match(line):
            return True
        if _SLOT_HEADER_RE.match(line) and "Type" in line:
            return True
    return False


def _parse_chassis(lines: list[str]) -> ShowPlatformResult:
    """Parse chassis-format output (ASR/ISR/C8300/C9500)."""
    result: ShowPlatformResult = {}

    chassis_type = _parse_chassis_type(lines)
    if chassis_type:
        result["chassis_type"] = chassis_type

    slot_lines, cols = _find_slot_section(lines)
    if slot_lines and cols:
        slots = _parse_slot_table(slot_lines, cols)
        _merge_cpld_firmware(lines, slots)
        if slots:
            result["slots"] = slots

    return result


def _parse_stack(lines: list[str]) -> ShowPlatformResult:
    """Parse stack-format output (Catalyst 3850/9300)."""
    result: ShowPlatformResult = {}

    switches = _parse_switch_table(lines)
    if switches:
        result["switches"] = switches

    stack = _parse_stack_info(lines)
    if stack:
        result["stack"] = stack

    return result


@register(OS.CISCO_IOS, "show platform")
@register(OS.CISCO_IOSXE, "show platform")
class ShowPlatformParser(BaseParser[ShowPlatformResult]):
    """Parser for 'show platform' on IOS/IOS-XE."""

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowPlatformResult:
        """Parse 'show platform' output."""
        lines = output.splitlines()

        if _is_chassis_format(lines):
            return _parse_chassis(lines)
        return _parse_stack(lines)
