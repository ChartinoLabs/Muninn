"""Parser for 'show environment' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ThresholdEntry(TypedDict):
    """Threshold values for a sensor."""

    minor: int | None
    major: int | None
    critical: int | None
    shutdown: int | None


class SensorEntry(TypedDict):
    """Schema for a single sensor reading."""

    state: str
    reading: int
    unit: str
    thresholds: NotRequired[ThresholdEntry]


class ShowEnvironmentResult(TypedDict):
    """Schema for 'show environment' parsed output."""

    critical_alarms: int
    major_alarms: int
    minor_alarms: int
    sensors: dict[str, dict[str, SensorEntry]]


_ALARM_PATTERN = re.compile(r"Number of (\w+) alarms:\s+(\d+)", re.IGNORECASE)

_THRESHOLD_PATTERN = re.compile(r"\(([^)]+)\)\s*\(([^)]+)\)")

_READING_PATTERN = re.compile(r"(\d+)\s+(.+)")

_COLUMN_SPLIT = re.compile(r"\s{4,}")


def _parse_thresholds(text: str) -> ThresholdEntry | None:
    """Parse threshold string into structured data.

    Format: ``(minor,major,critical,shutdown)(unit)``
    Values can be integers or ``na``.  A bare ``na`` means no thresholds.
    """
    text = text.strip()
    if not text or text.lower() == "na":
        return None

    m = _THRESHOLD_PATTERN.search(text)
    if not m:
        return None

    values = [v.strip() for v in m.group(1).split(",")]
    if len(values) != 4:
        return None

    def _to_int(v: str) -> int | None:
        return None if v.lower() == "na" else int(v)

    return {
        "minor": _to_int(values[0]),
        "major": _to_int(values[1]),
        "critical": _to_int(values[2]),
        "shutdown": _to_int(values[3]),
    }


def _parse_reading(text: str) -> tuple[int, str]:
    """Parse a reading string like ``'1796 mV'`` into (value, unit)."""
    m = _READING_PATTERN.match(text.strip())
    if not m:
        msg = f"Cannot parse reading: {text!r}"
        raise ValueError(msg)
    return int(m.group(1)), m.group(2).strip()


@register(OS.CISCO_IOS, "show environment")
@register(OS.CISCO_IOSXE, "show environment")
class ShowEnvironmentParser(BaseParser[ShowEnvironmentResult]):
    """Parser for 'show environment' on IOS/IOS-XE.

    Handles two table variants:

    * Without thresholds: columns separated by 4+ spaces, split by whitespace.
    * With thresholds: tab-delimited threshold column, fixed column positions
      from the header for slot/sensor/state/reading.
    """

    @classmethod
    def _find_header(cls, lines: list[str]) -> tuple[int, bool]:
        """Find the header line index and whether thresholds are present."""
        for i, line in enumerate(lines):
            lower = line.lower()
            if "slot" in lower and "sensor" in lower and "current state" in lower:
                return i, "threshold" in lower

        msg = "No sensor table header found in output"
        raise ValueError(msg)

    @classmethod
    def _get_column_positions(cls, header: str) -> tuple[int, int, int, int]:
        """Extract column start positions from the threshold-format header."""
        lower = header.lower()
        return (
            lower.index("slot"),
            lower.index("sensor"),
            lower.index("current state"),
            lower.index("reading"),
        )

    @classmethod
    def _parse_alarms(cls, lines: list[str]) -> dict[str, int]:
        """Extract alarm counts from lines before the table."""
        alarms: dict[str, int] = {}
        for line in lines:
            m = _ALARM_PATTERN.search(line)
            if m:
                alarms[m.group(1).lower()] = int(m.group(2))
        return alarms

    @classmethod
    def _parse_line_split(cls, line: str) -> tuple[str, str, str, str] | None:
        """Parse a no-threshold data line by splitting on 4+ whitespace."""
        parts = _COLUMN_SPLIT.split(line.strip())
        if len(parts) < 4:
            return None
        return parts[0], parts[1], parts[2], parts[3]

    @classmethod
    def _parse_line_columns(
        cls, line: str, cols: tuple[int, int, int, int]
    ) -> tuple[str, str, str, str, str | None] | None:
        """Parse a threshold-format data line using column positions.

        The threshold value is separated from the reading by a tab character.
        Column positions are used for slot, sensor, state, and reading.
        """
        slot_col, sensor_col, state_col, reading_col = cols

        # Split off threshold on tab
        threshold_str: str | None = None
        main = line
        if "\t" in line:
            tab_idx = line.index("\t")
            threshold_str = line[tab_idx + 1 :].strip()
            main = line[:tab_idx]

        padded = main.ljust(reading_col + 40)
        slot = padded[slot_col:sensor_col].strip()
        sensor = padded[sensor_col:state_col].strip()
        state = padded[state_col:reading_col].strip()
        reading_str = padded[reading_col:].strip()

        if not slot or not sensor or not reading_str:
            return None
        return slot, sensor, state, reading_str, threshold_str

    @classmethod
    def _find_data_start(cls, lines: list[str], header_idx: int) -> int:
        """Find the first data line after the header, skipping separators."""
        for j in range(header_idx + 1, len(lines)):
            stripped = lines[j].strip()
            if stripped and not all(c in "-= " for c in stripped):
                return j
        return header_idx + 1

    @classmethod
    def _build_entry(
        cls, state: str, reading_str: str, threshold_str: str | None
    ) -> SensorEntry | None:
        """Build a SensorEntry from parsed field strings."""
        try:
            reading_val, unit = _parse_reading(reading_str)
        except ValueError:
            return None

        entry: SensorEntry = {
            "state": state,
            "reading": reading_val,
            "unit": unit,
        }

        if threshold_str is not None:
            threshold = _parse_thresholds(threshold_str)
            if threshold is not None:
                entry["thresholds"] = threshold

        return entry

    @classmethod
    def _parse_sensor_line(
        cls,
        line: str,
        has_thresholds: bool,
        cols: tuple[int, int, int, int] | None,
    ) -> tuple[str, str, SensorEntry] | None:
        """Parse a single sensor data line.

        Returns (slot, sensor_name, entry) or None if the line is not valid.
        """
        threshold_str: str | None = None

        if has_thresholds and cols is not None:
            parsed = cls._parse_line_columns(line, cols)
            if parsed is None:
                return None
            slot, sensor_name, state, reading_str, threshold_str = parsed
        else:
            parsed_split = cls._parse_line_split(line)
            if parsed_split is None:
                return None
            slot, sensor_name, state, reading_str = parsed_split

        entry = cls._build_entry(state, reading_str, threshold_str)
        if entry is None:
            return None

        return slot, sensor_name, entry

    @classmethod
    def _parse_sensors(
        cls,
        lines: list[str],
        has_thresholds: bool,
        cols: tuple[int, int, int, int] | None,
    ) -> dict[str, dict[str, SensorEntry]]:
        """Parse sensor data lines into structured dict."""
        sensors: dict[str, dict[str, SensorEntry]] = {}

        for line in lines:
            if not line.strip():
                continue
            if line.strip().startswith("Power") and "Supply" in line:
                break

            result = cls._parse_sensor_line(line, has_thresholds, cols)
            if result is None:
                continue

            slot, sensor_name, entry = result
            if slot not in sensors:
                sensors[slot] = {}
            sensors[slot][sensor_name] = entry

        return sensors

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentResult:
        """Parse 'show environment' output."""
        lines = output.splitlines()

        header_idx, has_thresholds = cls._find_header(lines)
        alarms = cls._parse_alarms(lines[:header_idx])

        if "critical" not in alarms:
            msg = "No alarm counts found in output"
            raise ValueError(msg)

        data_start = cls._find_data_start(lines, header_idx)
        cols = cls._get_column_positions(lines[header_idx]) if has_thresholds else None

        sensors = cls._parse_sensors(lines[data_start:], has_thresholds, cols)

        if not sensors:
            msg = "No sensor data found in output"
            raise ValueError(msg)

        return {
            "critical_alarms": alarms.get("critical", 0),
            "major_alarms": alarms.get("major", 0),
            "minor_alarms": alarms.get("minor", 0),
            "sensors": sensors,
        }
