"""Parser for 'show platform diag' command on IOS.

Parses per-slot diagnostic output including chassis type, slot/sub-slot
details with running state, CPLD/firmware versions, and timing information.
"""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# --- TypedDict schema ---


class SubslotEntry(TypedDict):
    """Schema for a sub-slot within a slot."""

    operational_status: str
    internal_state: str
    physical_insert_detect_time: NotRequired[str]
    logical_insert_detect_time: NotRequired[str]


class SlotEntry(TypedDict):
    """Schema for a slot entry."""

    type: str
    running_state: NotRequired[str]
    state: NotRequired[str]
    internal_state: NotRequired[str]
    internal_operational_state: NotRequired[str]
    physical_insert_detect_time: NotRequired[str]
    software_declared_up_time: NotRequired[str]
    hardware_ready_signal_time: NotRequired[str]
    packet_ready_signal_time: NotRequired[str]
    cpld_version: NotRequired[str]
    firmware_version: NotRequired[str]
    subslots: NotRequired[dict[str, SubslotEntry]]


class ShowPlatformDiagResult(TypedDict):
    """Schema for 'show platform diag' parsed output."""

    chassis_type: NotRequired[str]
    slots: dict[str, SlotEntry]


# --- Regex patterns ---

_CHASSIS_TYPE_RE = re.compile(r"^Chassis\s+type:\s*(\S+)\s*$")

# Slot header: "Slot: 0, ISR4451/K9" or "Slot: R0, ISR4451/K9"
_SLOT_HEADER_RE = re.compile(r"^Slot:\s*(\S+),\s*(.+?)\s*$")

# Sub-slot header: "  Sub-slot: 0/0, ISR4451-X-4x1GE" (may be indented)
_SUBSLOT_HEADER_RE = re.compile(r"^\s*Sub-slot:\s*(\S+),\s*(.+?)\s*$")

# Key-value pair: "Running state : ok" or "Running state : ok, active"
_KV_RE = re.compile(r"^\s+(\S[\w\s]+?)\s*:\s*(.+?)\s*$")

# Map of display labels to dict keys for slot entries
_SLOT_KEY_MAP: dict[str, str] = {
    "Running state": "running_state",
    "State": "state",
    "Internal state": "internal_state",
    "Internal operational state": "internal_operational_state",
    "Physical insert detect time": "physical_insert_detect_time",
    "Software declared up time": "software_declared_up_time",
    "Hardware ready signal time": "hardware_ready_signal_time",
    "Packet ready signal time": "packet_ready_signal_time",
    "CPLD version": "cpld_version",
    "Firmware version": "firmware_version",
}

# Map of display labels to dict keys for sub-slot entries
_SUBSLOT_KEY_MAP: dict[str, str] = {
    "Operational status": "operational_status",
    "Internal state": "internal_state",
    "Physical insert detect time": "physical_insert_detect_time",
    "Logical insert detect time": "logical_insert_detect_time",
}


def _init_subslot(
    slots: dict[str, SlotEntry],
    slot_id: str,
    subslot_num: str,
) -> None:
    """Initialize an empty sub-slot entry under the given slot."""
    if "subslots" not in slots[slot_id]:
        slots[slot_id]["subslots"] = {}
    slots[slot_id]["subslots"][subslot_num] = {
        "operational_status": "",
        "internal_state": "",
    }


def _assign_kv_to_subslot(
    slots: dict[str, SlotEntry],
    slot_id: str,
    subslot_id: str,
    label: str,
    value: str,
) -> None:
    """Assign a key-value pair to a sub-slot entry."""
    key = _SUBSLOT_KEY_MAP.get(label)
    if not key or "subslots" not in slots[slot_id]:
        return
    subslots = slots[slot_id]["subslots"]
    if subslot_id in subslots:
        subslots[subslot_id][key] = value  # type: ignore[literal-required]


def _assign_kv_to_slot(
    slots: dict[str, SlotEntry],
    slot_id: str,
    label: str,
    value: str,
) -> None:
    """Assign a key-value pair to a slot entry."""
    key = _SLOT_KEY_MAP.get(label)
    if key:
        slots[slot_id][key] = value  # type: ignore[literal-required]


def _handle_subslot_header(
    match: re.Match[str],
    slots: dict[str, SlotEntry],
    slot_id: str | None,
) -> tuple[str | None, str]:
    """Process a sub-slot header line. Returns (slot_id, subslot_id)."""
    parts = match.group(1).split("/", 1)
    parent = parts[0]
    subslot_num = parts[1] if len(parts) > 1 else parts[0]
    if parent in slots:
        slot_id = parent
    if slot_id and slot_id in slots:
        _init_subslot(slots, slot_id, subslot_num)
    return slot_id, subslot_num


def _process_line(
    line: str,
    slots: dict[str, SlotEntry],
    slot_id: str | None,
    subslot_id: str | None,
) -> tuple[str | None, str | None]:
    """Process a single non-blank line. Returns updated (slot_id, subslot_id)."""
    slot_match = _SLOT_HEADER_RE.match(line)
    if slot_match:
        sid = slot_match.group(1)
        slots[sid] = {"type": slot_match.group(2)}
        return sid, None

    subslot_match = _SUBSLOT_HEADER_RE.match(line)
    if subslot_match:
        return _handle_subslot_header(subslot_match, slots, slot_id)

    kv_match = _KV_RE.match(line)
    if kv_match and slot_id and slot_id in slots:
        label = kv_match.group(1).strip()
        value = kv_match.group(2).strip()
        if subslot_id:
            _assign_kv_to_subslot(slots, slot_id, subslot_id, label, value)
        else:
            _assign_kv_to_slot(slots, slot_id, label, value)

    return slot_id, subslot_id


def _parse_slots(lines: list[str]) -> dict[str, SlotEntry]:
    """Parse all slot and sub-slot sections from output lines."""
    slots: dict[str, SlotEntry] = {}
    slot_id: str | None = None
    subslot_id: str | None = None

    for line in lines:
        if not line.strip():
            subslot_id = None
            continue
        slot_id, subslot_id = _process_line(line, slots, slot_id, subslot_id)

    return slots


def _clean_subslots(slots: dict[str, SlotEntry]) -> None:
    """Remove sub-slot entries with empty required fields."""
    for slot in slots.values():
        if "subslots" not in slot:
            continue
        to_remove = []
        for sub_id, sub in slot["subslots"].items():
            if not sub["operational_status"] or not sub["internal_state"]:
                to_remove.append(sub_id)
        for sub_id in to_remove:
            del slot["subslots"][sub_id]
        if not slot["subslots"]:
            del slot["subslots"]


@register(OS.CISCO_IOS, "show platform diag")
class ShowPlatformDiagParser(BaseParser[ShowPlatformDiagResult]):
    """Parser for 'show platform diag' on IOS.

    Example output::

        Chassis type: ISR4451/K9

        Slot: 0, ISR4451/K9
          Running state               : ok
          Internal state              : online
          Internal operational state  : ok
          Physical insert detect time : 00:01:04 (3d10h ago)
          Software declared up time   : 00:01:43 (3d10h ago)
          CPLD version                : 12121625
          Firmware version            : 15.3(1r)S

        Sub-slot: 0/0, ISR4451-X-4x1GE
          Operational status : ok
          Internal state     : inserted
          Physical insert detect time : 00:03:03 (3d10h ago)
          Logical insert detect time  : 00:03:03 (3d10h ago)
    """

    @classmethod
    def parse(cls, output: str) -> ShowPlatformDiagResult:
        """Parse 'show platform diag' output.

        Args:
            output: Raw CLI output from 'show platform diag' command.

        Returns:
            Parsed data with chassis type and per-slot diagnostics.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()

        result: ShowPlatformDiagResult = {"slots": {}}

        # Extract chassis type
        for line in lines:
            chassis_match = _CHASSIS_TYPE_RE.match(line)
            if chassis_match:
                result["chassis_type"] = chassis_match.group(1)
                break

        # Parse slot and sub-slot sections
        slots = _parse_slots(lines)
        _clean_subslots(slots)

        if not slots:
            msg = "No slot entries found in output"
            raise ValueError(msg)

        result["slots"] = slots

        return result
