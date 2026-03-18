"""Parser for 'show environment all' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class FanEntry(TypedDict):
    """Schema for a single fan entry."""

    speed: int
    state: str


class FanPsEntry(TypedDict):
    """Schema for a fan power supply entry."""

    state: str


class TemperatureEntry(TypedDict):
    """Schema for a temperature sensor reading."""

    value: int
    state: str
    yellow_threshold: int
    red_threshold: int


class PowerSupplyEntry(TypedDict):
    """Schema for a power supply entry."""

    status: str
    pid: NotRequired[str]
    serial_number: NotRequired[str]
    system_power: NotRequired[str]
    poe_power: NotRequired[str]
    watts: NotRequired[int]


class SwitchEntry(TypedDict):
    """Schema for a single switch entry."""

    system_temperature_state: NotRequired[str]
    fans: NotRequired[dict[str, FanEntry]]
    fan_power_supplies: NotRequired[dict[str, FanPsEntry]]
    inlet_temperature: NotRequired[TemperatureEntry]
    outlet_temperature: NotRequired[TemperatureEntry]
    hotspot_temperature: NotRequired[TemperatureEntry]
    power_supplies: NotRequired[dict[str, PowerSupplyEntry]]


class ShowEnvironmentAllResult(TypedDict):
    """Schema for 'show environment all' parsed output."""

    switches: dict[str, SwitchEntry]


# Fan table row: "  1     1 35840     OK"
_FAN_ROW = re.compile(
    r"^\s*(?P<switch>\d+)\s+(?P<fan>\d+)\s+(?P<speed>\d+)\s+(?P<state>\S+)\s*$"
)

# Fan PS status: "FAN PS-1 is OK" or "FAN PS-1 is NOT PRESENT"
_FAN_PS = re.compile(r"^FAN\s+PS-(?P<ps>\d+)\s+is\s+(?P<state>.+?)\s*$", re.IGNORECASE)

# System temperature header: "Switch 1: SYSTEM TEMPERATURE is OK"
_SYS_TEMP = re.compile(
    r"^Switch\s+(?P<switch>\d+):\s+SYSTEM\s+TEMPERATURE\s+is\s+(?P<state>.+?)\s*$",
    re.IGNORECASE,
)

# Temperature value: "Inlet Temperature Value: 29 Degree Celsius"
_TEMP_VALUE = re.compile(
    r"^(?P<sensor>Inlet|Outlet|Hotspot)\s+Temperature\s+Value:\s+"
    r"(?P<value>\d+)\s+Degree\s+Celsius\s*$",
    re.IGNORECASE,
)

# Temperature state: "Temperature State: GREEN"
_TEMP_STATE = re.compile(r"^Temperature\s+State:\s+(?P<state>\S+)\s*$", re.IGNORECASE)

# Temperature threshold: "Yellow Threshold : 46 Degree Celsius"
_TEMP_THRESHOLD = re.compile(
    r"^(?P<color>Yellow|Red)\s+Threshold\s*:\s+(?P<value>\d+)\s+Degree\s+Celsius\s*$",
    re.IGNORECASE,
)

# Power supply row: "1A  PWR-C4-950WAC-R  GEN222700VU  OK  Good  n/a  950"
_PS_ROW = re.compile(
    r"^(?P<sw>\d+)(?P<slot>[A-Z])\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<serial>\S+)\s+"
    r"(?P<status>.+?)\s{2,}"
    r"(?P<sys_pwr>\S+)\s+"
    r"(?P<poe_pwr>\S+)\s+"
    r"(?P<watts>\d+)\s*$"
)

# Power supply not present row: "3B  Not Present"
_PS_NOT_PRESENT = re.compile(
    r"^(?P<sw>\d+)(?P<slot>[A-Z])\s+Not\s+Present\s*$", re.IGNORECASE
)

# Fan table header and separator lines
_FAN_HEADER = re.compile(r"^Switch\s+FAN\s+Speed\s+State", re.IGNORECASE)
_SEPARATOR = SEPARATOR_DASH_RE
_PS_HEADER = re.compile(r"^SW\s+PID\s+", re.IGNORECASE)


def _is_skip_line(line: str) -> bool:
    """Check if line should be skipped (headers, separators, command echo)."""
    if not line:
        return True
    if _FAN_HEADER.match(line):
        return True
    if _SEPARATOR.match(line):
        return True
    if _PS_HEADER.match(line):
        return True
    if line.startswith("show environment"):
        return True
    return False


def _get_or_create_switch(
    switches: dict[str, SwitchEntry], switch_id: str
) -> SwitchEntry:
    """Get or create a switch entry."""
    if switch_id not in switches:
        switches[switch_id] = SwitchEntry()
    return switches[switch_id]


def _normalize_poe(value: str) -> str | None:
    """Normalize PoE power value, returning None for n/a."""
    val = value.strip().lower()
    if val in ("n/a", "--"):
        return None
    return val


def _build_temperature(
    value: int, state: str, yellow: int, red: int
) -> TemperatureEntry:
    """Build a TemperatureEntry from parsed components."""
    return TemperatureEntry(
        value=value,
        state=state.lower(),
        yellow_threshold=yellow,
        red_threshold=red,
    )


def _apply_fan_row(match: re.Match[str], switches: dict[str, SwitchEntry]) -> None:
    """Apply a fan table row match."""
    sw = _get_or_create_switch(switches, match.group("switch"))
    if "fans" not in sw:
        sw["fans"] = {}
    sw["fans"][match.group("fan")] = FanEntry(
        speed=int(match.group("speed")),
        state=match.group("state").lower(),
    )


def _apply_fan_ps(
    match: re.Match[str],
    switches: dict[str, SwitchEntry],
    current_switch: str,
) -> None:
    """Apply a fan power supply status line match."""
    sw = _get_or_create_switch(switches, current_switch)
    if "fan_power_supplies" not in sw:
        sw["fan_power_supplies"] = {}
    sw["fan_power_supplies"][match.group("ps")] = FanPsEntry(
        state=match.group("state").strip().lower(),
    )


def _apply_ps_row(match: re.Match[str], switches: dict[str, SwitchEntry]) -> None:
    """Apply a power supply table row match."""
    switch_id = match.group("sw")
    sw = _get_or_create_switch(switches, switch_id)
    if "power_supplies" not in sw:
        sw["power_supplies"] = {}
    slot = match.group("slot")
    entry = PowerSupplyEntry(
        status=match.group("status").strip().lower(),
        pid=match.group("pid"),
        serial_number=match.group("serial"),
        system_power=match.group("sys_pwr").lower(),
        watts=int(match.group("watts")),
    )
    poe = _normalize_poe(match.group("poe_pwr"))
    if poe is not None:
        entry["poe_power"] = poe
    sw["power_supplies"][slot] = entry


def _apply_ps_not_present(
    match: re.Match[str], switches: dict[str, SwitchEntry]
) -> None:
    """Apply a 'Not Present' power supply row match."""
    switch_id = match.group("sw")
    sw = _get_or_create_switch(switches, switch_id)
    if "power_supplies" not in sw:
        sw["power_supplies"] = {}
    slot = match.group("slot")
    sw["power_supplies"][slot] = PowerSupplyEntry(status="not present")


@register(OS.CISCO_IOSXE, "show environment all")
class ShowEnvironmentAllParser(BaseParser[ShowEnvironmentAllResult]):
    """Parser for 'show environment all' command.

    Example output::

        Switch   FAN   Speed   State
        ---------------------------------------------------
          1     1 35840     OK
        FAN PS-1 is OK
        Switch 1: SYSTEM TEMPERATURE is OK
        Inlet Temperature Value: 29 Degree Celsius
        SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
        1A  PWR-C4-950WAC-R     GEN222700VU  OK              Good     n/a      950
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ENVIRONMENT,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentAllResult:
        """Parse 'show environment all' output.

        Args:
            output: Raw CLI output from 'show environment all' command.

        Returns:
            Parsed environment data keyed by switch number.

        Raises:
            ValueError: If no environment data is found.
        """
        switches: dict[str, SwitchEntry] = {}
        current_switch = "1"
        current_sensor: str | None = None
        temp_parts: dict[str, int | str] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if _is_skip_line(stripped):
                continue

            current_switch, current_sensor, temp_parts = _process_line(
                stripped, switches, current_switch, current_sensor, temp_parts
            )

        if not switches:
            msg = "No environment data found in output"
            raise ValueError(msg)

        return ShowEnvironmentAllResult(switches=switches)


def _store_temperature(
    switches: dict[str, SwitchEntry],
    switch_id: str,
    sensor: str,
    parts: dict[str, int | str],
) -> None:
    """Store a completed temperature reading into the switch entry."""
    required = {"value", "state", "yellow", "red"}
    if not required.issubset(parts.keys()):
        return
    sw = _get_or_create_switch(switches, switch_id)
    temp = _build_temperature(
        value=int(parts["value"]),
        state=str(parts["state"]),
        yellow=int(parts["yellow"]),
        red=int(parts["red"]),
    )
    key = f"{sensor.lower()}_temperature"
    sw[key] = temp  # type: ignore[literal-required]


def _process_temperature_line(
    line: str,
    switches: dict[str, SwitchEntry],
    current_switch: str,
    current_sensor: str | None,
    temp_parts: dict[str, int | str],
) -> tuple[str | None, dict[str, int | str], bool]:
    """Process temperature-related lines. Returns (sensor, parts, matched)."""
    if match := _TEMP_VALUE.match(line):
        if current_sensor:
            _store_temperature(switches, current_switch, current_sensor, temp_parts)
        return match.group("sensor"), {"value": int(match.group("value"))}, True

    if match := _TEMP_STATE.match(line):
        if current_sensor:
            temp_parts["state"] = match.group("state")
        return current_sensor, temp_parts, True

    if match := _TEMP_THRESHOLD.match(line):
        if current_sensor:
            color = match.group("color").lower()
            temp_parts[color] = int(match.group("value"))
            if color == "red":
                _store_temperature(switches, current_switch, current_sensor, temp_parts)
                return None, {}, True
        return current_sensor, temp_parts, True

    return current_sensor, temp_parts, False


def _process_line(
    line: str,
    switches: dict[str, SwitchEntry],
    current_switch: str,
    current_sensor: str | None,
    temp_parts: dict[str, int | str],
) -> tuple[str, str | None, dict[str, int | str]]:
    """Process a single line, returning updated state."""
    if match := _FAN_ROW.match(line):
        _apply_fan_row(match, switches)
        return match.group("switch"), current_sensor, temp_parts

    if match := _FAN_PS.match(line):
        _apply_fan_ps(match, switches, current_switch)
        return current_switch, current_sensor, temp_parts

    if match := _SYS_TEMP.match(line):
        current_switch = match.group("switch")
        sw = _get_or_create_switch(switches, current_switch)
        sw["system_temperature_state"] = match.group("state").strip().lower()
        return current_switch, None, {}

    sensor, parts, matched = _process_temperature_line(
        line, switches, current_switch, current_sensor, temp_parts
    )
    if matched:
        return current_switch, sensor, parts

    if match := _PS_ROW.match(line):
        _apply_ps_row(match, switches)
    elif match := _PS_NOT_PRESENT.match(line):
        _apply_ps_not_present(match, switches)

    return current_switch, current_sensor, temp_parts
