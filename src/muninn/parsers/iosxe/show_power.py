"""Parser for 'show power' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply entry."""

    model_no: str
    type: str
    capacity: NotRequired[str]
    status: str
    fan_state_0: str
    fan_state_1: str


class FanTrayEntry(TypedDict):
    """Schema for a single fan tray entry."""

    status: str
    fan_state_0: str
    fan_state_1: str


class SwitchEntry(TypedDict):
    """Schema for a single switch in a stack."""

    power_supplies: dict[str, PowerSupplyEntry]
    fan_trays: dict[str, FanTrayEntry]


class ShowPowerResult(TypedDict):
    """Schema for 'show power' parsed output."""

    switches: NotRequired[dict[str, SwitchEntry]]
    power_supplies: NotRequired[dict[str, PowerSupplyEntry]]
    fan_trays: NotRequired[dict[str, FanTrayEntry]]


_SWITCH_HEADER = re.compile(r"^Switch:(?P<switch>\S+)$")

_SEPARATOR = re.compile(r"^-{3,}")

# PS1     C9K-PWR-1500WAC-R     ac    n.a.      bad-input  n.a.  n.a.
# PS2     C9K-PWR-1500WAC-R     ac    1500 W    active     good  n.a.
# 1B  PWR-C5-1KWAC        DCI22031004  OK              Good     Good     1000
_POWER_SUPPLY_ROW = re.compile(
    r"^(?P<ps_id>\S+)\s+"
    r"(?P<model_no>\S+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<capacity>\S+)\s+W?\s*"
    r"(?P<status>\S+)\s+"
    r"(?P<fan0>\S+)\s+"
    r"(?P<fan1>\S+)\s*$"
)

# FT1     active      good  good
_FAN_TRAY_ROW = re.compile(
    r"^(?P<ft_id>\S+)\s+"
    r"(?P<status>\S+)\s+"
    r"(?P<fan0>\S+)\s+"
    r"(?P<fan1>\S+)\s*$"
)

# Header lines to skip
_HEADER_KEYWORDS = ("Power", "Supply", "Fan", "Tray", "------")


def _is_header_line(line: str) -> bool:
    """Check if a line is a header or separator line."""
    return any(line.startswith(kw) for kw in _HEADER_KEYWORDS)


def _normalize_capacity(value: str) -> str | None:
    """Normalize capacity values, returning None for sentinel values."""
    value = value.strip()
    if not value or value in ("n.a.", "N/A", "--"):
        return None
    return value


def _build_ps_entry(m: re.Match[str]) -> PowerSupplyEntry:
    """Build a PowerSupplyEntry from a regex match."""
    entry = PowerSupplyEntry(
        model_no=m.group("model_no"),
        type=m.group("type"),
        status=m.group("status"),
        fan_state_0=m.group("fan0"),
        fan_state_1=m.group("fan1"),
    )
    capacity = _normalize_capacity(m.group("capacity"))
    if capacity:
        entry["capacity"] = capacity
    return entry


def _build_ft_entry(m: re.Match[str]) -> FanTrayEntry:
    """Build a FanTrayEntry from a regex match."""
    return FanTrayEntry(
        status=m.group("status"),
        fan_state_0=m.group("fan0"),
        fan_state_1=m.group("fan1"),
    )


class _ParseState:
    """Mutable state container for the line-by-line parser."""

    __slots__ = ("current_switch", "found_data", "in_fan_section", "result")

    def __init__(self) -> None:
        self.result = ShowPowerResult()
        self.current_switch: str | None = None
        self.in_fan_section: bool = False
        self.found_data: bool = False


def _handle_data_line(line: str, state: _ParseState) -> None:
    """Process a data line (power supply or fan tray row)."""
    if state.in_fan_section:
        if m := _FAN_TRAY_ROW.match(line):
            ft_id = m.group("ft_id")
            if ft_id == "Tray":
                return
            state.found_data = True
            entry = _build_ft_entry(m)
            _store_fan_tray(state.result, state.current_switch, ft_id, entry)
    elif m := _POWER_SUPPLY_ROW.match(line):
        state.found_data = True
        _store_power_supply(
            state.result, state.current_switch, m.group("ps_id"), _build_ps_entry(m)
        )


def _process_line(line: str, state: _ParseState) -> None:
    """Process a single stripped, non-empty line."""
    if _SEPARATOR.match(line):
        return

    if m := _SWITCH_HEADER.match(line):
        state.current_switch = m.group("switch")
        state.in_fan_section = False
        return

    if _is_header_line(line):
        if line.startswith("Fan"):
            state.in_fan_section = True
        elif line.startswith("Power"):
            state.in_fan_section = False
        return

    _handle_data_line(line, state)


@register(OS.CISCO_IOSXE, "show power")
class ShowPowerParser(BaseParser[ShowPowerResult]):
    """Parser for 'show power' command.

    Example output::

        Switch:1

        Power                                                    Fan States
        Supply  Model No              Type  Capacity  Status     0     1
        ------  --------------------  ----  --------  ---------  -----------
        PS1     C9K-PWR-1500WAC-R     ac    n.a.      bad-input  n.a.  n.a.
        PS2     C9K-PWR-1500WAC-R     ac    1500 W    active     good  n.a.

        Fan                 Fan States
        Tray    Status      0     1
        ------  ----------  -----------
        FT1     active      good  good
    """

    @classmethod
    def parse(cls, output: str) -> ShowPowerResult:
        """Parse 'show power' output.

        Args:
            output: Raw CLI output from 'show power' command.

        Returns:
            Parsed power supply and fan tray data.

        Raises:
            ValueError: If no power supply or fan tray entries are found.
        """
        state = _ParseState()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            _process_line(line, state)

        if not state.found_data:
            msg = "No power supply or fan tray entries found in output"
            raise ValueError(msg)

        return state.result


def _store_power_supply(
    result: ShowPowerResult,
    switch: str | None,
    ps_id: str,
    entry: PowerSupplyEntry,
) -> None:
    """Store a power supply entry in the appropriate location."""
    if switch is not None:
        switches = result.setdefault("switches", {})
        sw = switches.setdefault(switch, SwitchEntry(power_supplies={}, fan_trays={}))
        sw["power_supplies"][ps_id] = entry
    else:
        ps_dict = result.setdefault("power_supplies", {})
        ps_dict[ps_id] = entry


def _store_fan_tray(
    result: ShowPowerResult,
    switch: str | None,
    ft_id: str,
    entry: FanTrayEntry,
) -> None:
    """Store a fan tray entry in the appropriate location."""
    if switch is not None:
        switches = result.setdefault("switches", {})
        sw = switches.setdefault(switch, SwitchEntry(power_supplies={}, fan_trays={}))
        sw["fan_trays"][ft_id] = entry
    else:
        ft_dict = result.setdefault("fan_trays", {})
        ft_dict[ft_id] = entry
