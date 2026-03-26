"""Parser for 'show power available' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PowerSummaryEntry(TypedDict):
    """Schema for a power summary row."""

    used: int
    available: int


class PowerMeasurementEntry(TypedDict):
    """Schema for a power measurement row."""

    watts: int


class ShowPowerAvailableResult(TypedDict):
    """Schema for 'show power available' parsed output."""

    system_power: PowerSummaryEntry
    inline_power: PowerSummaryEntry
    backplane_power: PowerSummaryEntry
    total_used: int
    total_maximum_available: int
    measurements: NotRequired[dict[str, PowerMeasurementEntry]]
    measurement_total: NotRequired[int]


# Power Summary rows: "System Power (12V)        971        1360"
_SUMMARY_ROW_RE = re.compile(
    r"^(System Power|Inline Power|Backplane Power)\s+\([^)]+\)\s+(\d+)\s+(\d+)\s*$"
)

# Total row with max: "Total  1694 (not to exceed Total Maximum Available = 4200)"
_TOTAL_WITH_MAX_RE = re.compile(
    r"^Total\s+(\d+)\s+\(not to exceed Total Maximum Available\s*=\s*(\d+)\)\s*$"
)

# Total row (simple): "Total                     575         750"
_TOTAL_SIMPLE_RE = re.compile(r"^Total\s+(\d+)\s+(\d+)\s*$")

# Measurement row: "PS1                         250"
_MEASUREMENT_ROW_RE = re.compile(r"^(PS\d+)\s+(\d+)\s*$")

# Measurement total: "Total                       350"
_MEASUREMENT_TOTAL_RE = re.compile(r"^Total\s+(\d+)\s*$")

# Section header for Power Measurement
_MEASUREMENT_HEADER_RE = re.compile(r"^Power Measurement", re.IGNORECASE)

_SUMMARY_KEY_MAP: dict[str, str] = {
    "System Power": "system_power",
    "Inline Power": "inline_power",
    "Backplane Power": "backplane_power",
}


def _is_skip_line(line: str) -> bool:
    """Return True if the line is a header, separator, or blank."""
    if not line:
        return True
    if line.startswith("---") or line.startswith("--"):
        return True
    if line.startswith("Power Summary") or line.startswith("(in Watts)"):
        return True
    return False


@register(OS.CISCO_IOS, "show power available")
class ShowPowerAvailableParser(BaseParser[ShowPowerAvailableResult]):
    """Parser for 'show power available' command.

    Example output:
        Power Summary                      Maximum
         (in Watts)              Used     Available
        ----------------------   ----     ---------
        System Power (12V)        971        1360
        Inline Power (-50V)       683        3189
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ENVIRONMENT,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowPowerAvailableResult:
        """Parse 'show power available' output.

        Args:
            output: Raw CLI output from 'show power available' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict = {}
        measurements: dict[str, PowerMeasurementEntry] = {}
        in_measurement_section = False

        for line in output.splitlines():
            line = line.strip()
            if _is_skip_line(line):
                continue

            if _MEASUREMENT_HEADER_RE.match(line):
                in_measurement_section = True
                continue

            if in_measurement_section:
                cls._parse_measurement_line(line, measurements, result)
            else:
                cls._parse_summary_line(line, result)

        missing = [
            f
            for f in ("system_power", "inline_power", "backplane_power", "total_used")
            if f not in result
        ]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        if measurements:
            result["measurements"] = measurements

        return cast(ShowPowerAvailableResult, result)

    @classmethod
    def _parse_summary_line(cls, line: str, result: dict) -> None:
        """Parse a line from the Power Summary section."""
        m = _SUMMARY_ROW_RE.match(line)
        if m:
            key = _SUMMARY_KEY_MAP[m.group(1)]
            result[key] = PowerSummaryEntry(
                used=int(m.group(2)), available=int(m.group(3))
            )
            return

        m = _TOTAL_WITH_MAX_RE.match(line)
        if m:
            result["total_used"] = int(m.group(1))
            result["total_maximum_available"] = int(m.group(2))
            return

        m = _TOTAL_SIMPLE_RE.match(line)
        if m:
            result["total_used"] = int(m.group(1))
            result["total_maximum_available"] = int(m.group(2))

    @classmethod
    def _parse_measurement_line(
        cls,
        line: str,
        measurements: dict[str, PowerMeasurementEntry],
        result: dict,
    ) -> None:
        """Parse a line from the Power Measurement section."""
        m = _MEASUREMENT_ROW_RE.match(line)
        if m:
            measurements[m.group(1)] = PowerMeasurementEntry(watts=int(m.group(2)))
            return

        m = _MEASUREMENT_TOTAL_RE.match(line)
        if m:
            result["measurement_total"] = int(m.group(1))
