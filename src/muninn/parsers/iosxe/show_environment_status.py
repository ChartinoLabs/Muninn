"""Parser for 'show environment status' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PowerSupplyFanEntry(TypedDict):
    """Schema for a fan state within a power supply or fan tray."""

    status: str


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply entry."""

    model: str
    type: NotRequired[str]
    capacity_watts: NotRequired[int]
    status: str
    fans: NotRequired[dict[str, PowerSupplyFanEntry]]


class FanTrayEntry(TypedDict):
    """Schema for a single fan tray entry."""

    status: str
    fans: NotRequired[dict[str, PowerSupplyFanEntry]]


class SwitchEnvironment(TypedDict):
    """Schema for environment status of a single switch."""

    power_supplies: dict[str, PowerSupplyEntry]
    fan_trays: dict[str, FanTrayEntry]


class ShowEnvironmentStatusResult(TypedDict):
    """Schema for 'show environment status' parsed output."""

    switches: dict[str, SwitchEnvironment]


_SWITCH_HEADER = re.compile(r"^Switch:(?P<num>\d+)\s*$")

_SEPARATOR = re.compile(r"^-{3,}")

_POWER_HEADER = re.compile(r"^Power\s+Fan\s+States", re.IGNORECASE)

_FAN_HEADER = re.compile(r"^Fan\s+Fan\s+States", re.IGNORECASE)

# Power supply row:
# PS1     C9K-PWR-1500WAC-R     ac    1500 W    active     good  n.a.
# PS0     Not Present           N/A   N/A       N/A        N/A   N/A
_PS_ROW = re.compile(
    r"^(?P<name>PS\d+)\s+"
    r"(?P<model>.+?)\s{2,}"
    r"(?P<type>\S+)\s+"
    r"(?P<capacity>\S+(?:\s+W)?)\s+"
    r"(?P<status>\S[\w-]*)\s+"
    r"(?P<fans>.+)$"
)

# Fan tray row:
# FT1     active      good  good
# FM0     ok          good  good  good  good
_FAN_ROW = re.compile(r"^(?P<name>F[TM]\d+)\s+" r"(?P<status>\S+)\s+" r"(?P<fans>.+)$")


def _normalize(value: str | None) -> str | None:
    """Normalize sentinel values to None."""
    if value is None:
        return None
    value = value.strip()
    if not value or value.lower() in ("--", "n/a", "n.a.", "not present"):
        return None
    return value


def _parse_fan_states(raw: str) -> dict[str, PowerSupplyFanEntry] | None:
    """Parse space-separated fan state values into a dict keyed by index."""
    fans: dict[str, PowerSupplyFanEntry] = {}
    for idx, token in enumerate(raw.split()):
        normalized = _normalize(token)
        if normalized:
            fans[str(idx)] = PowerSupplyFanEntry(status=normalized)
    return fans if fans else None


def _parse_ps_row(
    match: re.Match[str],
    power_supplies: dict[str, PowerSupplyEntry],
) -> None:
    """Extract a power supply row into the power_supplies dict."""
    name = match.group("name")
    model_raw = match.group("model").strip()
    model = _normalize(model_raw)
    status_raw = match.group("status").strip()

    entry = PowerSupplyEntry(
        model=model if model else model_raw,
        status=status_raw,
    )

    type_val = _normalize(match.group("type"))
    if type_val:
        entry["type"] = type_val

    capacity_raw = match.group("capacity").strip()
    capacity_norm = _normalize(capacity_raw)
    if capacity_norm:
        # Extract numeric value from strings like "1500 W" or "1500"
        cap_match = re.match(r"(\d+)", capacity_norm)
        if cap_match:
            entry["capacity_watts"] = int(cap_match.group(1))

    fans = _parse_fan_states(match.group("fans"))
    if fans:
        entry["fans"] = fans

    power_supplies[name] = entry


def _parse_fan_row(
    match: re.Match[str],
    fan_trays: dict[str, FanTrayEntry],
) -> None:
    """Extract a fan tray row into the fan_trays dict."""
    name = match.group("name")
    entry = FanTrayEntry(status=match.group("status").strip())

    fans = _parse_fan_states(match.group("fans"))
    if fans:
        entry["fans"] = fans

    fan_trays[name] = entry


def _is_skip_line(line: str) -> bool:
    """Return True if line is a table header, separator, or noise."""
    if _SEPARATOR.match(line):
        return True
    if line.startswith("Supply") or line.startswith("Tray"):
        return True
    return bool("show environment" in line.lower() and "#" in line[:50])


def _ensure_switch(
    switches: dict[str, SwitchEnvironment], key: str
) -> SwitchEnvironment:
    """Ensure a switch entry exists and return it."""
    if key not in switches:
        switches[key] = SwitchEnvironment(power_supplies={}, fan_trays={})
    return switches[key]


def _detect_section(line: str) -> str | None:
    """Detect if a line is a section header. Returns section name or None."""
    if _POWER_HEADER.match(line):
        return "power"
    if _FAN_HEADER.match(line):
        return "fan"
    return None


def _process_data_line(line: str, section: str, switch_env: SwitchEnvironment) -> None:
    """Process a data line within the current section."""
    if section == "power":
        if m := _PS_ROW.match(line):
            _parse_ps_row(m, switch_env["power_supplies"])
    elif section == "fan":
        if m := _FAN_ROW.match(line):
            _parse_fan_row(m, switch_env["fan_trays"])


@register(OS.CISCO_IOSXE, "show environment status")
class ShowEnvironmentStatusParser(BaseParser[ShowEnvironmentStatusResult]):
    """Parser for 'show environment status' command.

    Example output::

        Power                                                    Fan States
        Supply  Model No              Type  Capacity  Status     0     1
        ------  --------------------  ----  --------  ---------  -----------
        PS1     C9K-PWR-1500WAC-R     ac    1500 W    active     good  n.a.
        PS2     C9K-PWR-1500WAC-R     ac    1500 W    active     good  n.a.

        Fan                 Fan States
        Tray    Status      0     1
        ------  ----------  -----------
        FT1     active      good  good
    """

    tags: ClassVar[frozenset[str]] = frozenset({"environment", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentStatusResult:
        """Parse 'show environment status' output.

        Args:
            output: Raw CLI output from 'show environment status' command.

        Returns:
            Parsed environment status data keyed by switch number.

        Raises:
            ValueError: If no environment data is found.
        """
        switches: dict[str, SwitchEnvironment] = {}
        current_switch = "1"
        section = "unknown"

        for line in output.splitlines():
            line = line.strip()
            if not line or _is_skip_line(line):
                continue

            if m := _SWITCH_HEADER.match(line):
                current_switch = m.group("num")
                continue

            detected = _detect_section(line)
            if detected:
                section = detected
                _ensure_switch(switches, current_switch)
                continue

            switch_env = _ensure_switch(switches, current_switch)
            _process_data_line(line, section, switch_env)

        if not switches:
            msg = "No environment status data found in output"
            raise ValueError(msg)

        return ShowEnvironmentStatusResult(switches=switches)
