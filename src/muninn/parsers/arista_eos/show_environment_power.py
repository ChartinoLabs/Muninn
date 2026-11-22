"""Parser for 'show environment power' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply entry."""

    model: str
    capacity_watts: int
    input_current_amps: float
    output_current_amps: float
    output_power_watts: float
    status: str
    uptime: NotRequired[str]


@register(OS.ARISTA_EOS, "show environment power")
class ShowEnvironmentPowerParser(BaseParser[dict[str, PowerSupplyEntry]]):
    """Parser for 'show environment power' command on Arista EOS.

    Returns a dict-of-dicts keyed by power supply name (e.g. "1", "2").
    The summary "Total" row is excluded from the output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ENVIRONMENT})

    # Matches a power supply data row. The uptime field is optional.
    # Example: "1   PWR-1011-AC-RED  1000W  0.70A 11.58A 139.0W Ok   68 days, 0:11:28"
    _PSU_LINE = re.compile(
        r"^\s*(?P<supply>\d+)"
        r"\s+(?P<model>\S+)"
        r"\s+(?P<capacity>\d+)W"
        r"\s+(?P<input_current>[\d.]+)A"
        r"\s+(?P<output_current>[\d.]+)A"
        r"\s+(?P<output_power>[\d.]+)W"
        r"\s+(?P<status>\S+(?:\s+\S+)*?)"
        r"(?:\s{2,}(?P<uptime>\d+\s+days?,\s*\d+:\d+:\d+))?"
        r"\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> dict[str, PowerSupplyEntry]:
        """Parse 'show environment power' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of power supply entries keyed by supply number.

        Raises:
            ValueError: If no power supply entries are found.
        """
        result: dict[str, PowerSupplyEntry] = {}

        for line in output.splitlines():
            match = cls._PSU_LINE.match(line)
            if not match:
                continue

            supply = match.group("supply")
            entry = PowerSupplyEntry(
                model=match.group("model"),
                capacity_watts=int(match.group("capacity")),
                input_current_amps=float(match.group("input_current")),
                output_current_amps=float(match.group("output_current")),
                output_power_watts=float(match.group("output_power")),
                status=match.group("status"),
            )

            uptime = match.group("uptime")
            if uptime:
                entry["uptime"] = uptime

            result[supply] = entry

        if not result:
            msg = "No power supply entries found in output"
            raise ValueError(msg)

        return result
