"""Parser for 'show power detail' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply entry."""

    model_no: str
    type: str
    status: str
    capacity_watts: NotRequired[int]
    fan_state_0: NotRequired[str]
    fan_state_1: NotRequired[str]


class FanTrayEntry(TypedDict):
    """Schema for a single fan tray entry."""

    status: str
    fan_state_0: NotRequired[str]
    fan_state_1: NotRequired[str]


class SwitchPowerDetail(TypedDict):
    """Schema for power detail of a single switch."""

    power_supplies: dict[str, PowerSupplyEntry]
    fan_trays: dict[str, FanTrayEntry]


class ShowPowerDetailResult(TypedDict):
    """Schema for 'show power detail' parsed output."""

    switches: dict[str, SwitchPowerDetail]


_SWITCH_HEADER = re.compile(r"^Switch:\s*(?P<switch_id>\d+)\s*$")

# PS1     C9K-PWR-1500WAC-R     ac    1500 W    active     good  n.a.
_PS_ROW = re.compile(
    r"^(?P<name>PS\d+)\s+"
    r"(?P<model>\S+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<capacity>\S+(?:\s+W)?)\s+"
    r"(?P<status>\S+)\s+"
    r"(?P<fan0>\S+)\s+"
    r"(?P<fan1>\S+)\s*$"
)

# FT1     active      good  good
_FT_ROW = re.compile(
    r"^(?P<name>FT\d+)\s+"
    r"(?P<status>\S+)\s+"
    r"(?P<fan0>\S+)\s+"
    r"(?P<fan1>\S+)\s*$"
)

_CAPACITY_PATTERN = re.compile(r"^(?P<watts>\d+)\s*W?$")


def _normalize_fan_state(value: str) -> str | None:
    """Return fan state or None if it is a sentinel value."""
    value = value.strip()
    if value in ("n.a.", "N/A", "--", ""):
        return None
    return value


def _parse_capacity(raw: str) -> int | None:
    """Parse capacity string, returning watts as int or None if unavailable."""
    raw = raw.strip()
    if raw in ("n.a.", "N/A", "--", ""):
        return None
    match = _CAPACITY_PATTERN.match(raw)
    if match:
        return int(match.group("watts"))
    return None


def _parse_ps_row(match: re.Match[str]) -> tuple[str, PowerSupplyEntry]:
    """Build a PowerSupplyEntry from a power supply regex match."""
    entry: PowerSupplyEntry = {
        "model_no": match.group("model"),
        "type": match.group("type"),
        "status": match.group("status"),
    }
    capacity = _parse_capacity(match.group("capacity"))
    if capacity is not None:
        entry["capacity_watts"] = capacity
    fan0 = _normalize_fan_state(match.group("fan0"))
    if fan0 is not None:
        entry["fan_state_0"] = fan0
    fan1 = _normalize_fan_state(match.group("fan1"))
    if fan1 is not None:
        entry["fan_state_1"] = fan1
    return match.group("name"), entry


def _parse_ft_row(match: re.Match[str]) -> tuple[str, FanTrayEntry]:
    """Build a FanTrayEntry from a fan tray regex match."""
    entry: FanTrayEntry = {
        "status": match.group("status"),
    }
    fan0 = _normalize_fan_state(match.group("fan0"))
    if fan0 is not None:
        entry["fan_state_0"] = fan0
    fan1 = _normalize_fan_state(match.group("fan1"))
    if fan1 is not None:
        entry["fan_state_1"] = fan1
    return match.group("name"), entry


@register(OS.CISCO_IOSXE, "show power detail")
class ShowPowerDetailParser(BaseParser[ShowPowerDetailResult]):
    """Parser for 'show power detail' command.

    Example output::

        Switch:1
        Power                                                    Fan States
        Supply  Model No              Type  Capacity  Status     0     1
        PS1     C9K-PWR-1500WAC-R     ac    1500 W    active     good  n.a.
        Fan                 Fan States
        Tray    Status      0     1
        FT1     active      good  good
    """

    @classmethod
    def parse(cls, output: str) -> ShowPowerDetailResult:
        """Parse 'show power detail' output.

        Args:
            output: Raw CLI output from 'show power detail' command.

        Returns:
            Parsed power detail data keyed by switch number.

        Raises:
            ValueError: If no switch sections are found in the output.
        """
        switches: dict[str, SwitchPowerDetail] = {}
        current_switch: str | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if m := _SWITCH_HEADER.match(line):
                current_switch = m.group("switch_id")
                switches[current_switch] = SwitchPowerDetail(
                    power_supplies={},
                    fan_trays={},
                )
                continue

            if current_switch is None:
                continue

            if m := _PS_ROW.match(line):
                name, entry = _parse_ps_row(m)
                switches[current_switch]["power_supplies"][name] = entry
            elif m := _FT_ROW.match(line):
                name, entry = _parse_ft_row(m)
                switches[current_switch]["fan_trays"][name] = entry

        if not switches:
            msg = "No switch sections found in output"
            raise ValueError(msg)

        return ShowPowerDetailResult(switches=switches)
