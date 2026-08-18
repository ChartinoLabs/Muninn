"""Parser for 'show environment cooling' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FanEntry(TypedDict):
    """Schema for an individual fan entry."""

    status: str
    configured_speed_pct: NotRequired[int]
    actual_speed_pct: NotRequired[int]


class ShowEnvironmentCoolingResult(TypedDict):
    """Schema for 'show environment cooling' parsed output on Arista EOS.

    Note: keys in `fans` mirror the device output. Inserted PSU fans appear
    as ``PowerSupply{N}/{slot}`` (e.g. ``PowerSupply1/1``) while not-inserted
    PSU bays appear as just ``PowerSupply{N}`` with no trailing slot.
    """

    system_status: str
    ambient_temperature_celsius: int
    airflow: str
    fans: dict[str, FanEntry]


_PERCENT_OR_NA = r"\d+%|N/A"
_FAN_STATUS = r"Ok|Not Inserted|Failed|Unknown"


@register(OS.ARISTA_EOS, "show environment cooling")
class ShowEnvironmentCoolingParser(BaseParser[ShowEnvironmentCoolingResult]):
    """Parser for 'show environment cooling' command on Arista EOS.

    Parses system cooling status, ambient temperature, airflow direction,
    and per-fan status/speed information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ENVIRONMENT})

    _SYSTEM_STATUS = re.compile(r"^System cooling status is:\s*(?P<status>.+)$")
    _AMBIENT_TEMP = re.compile(r"^Ambient temperature:\s*(?P<temp>\d+)C$")
    _AIRFLOW = re.compile(r"^Airflow:\s*(?P<airflow>.+)$")
    _FAN_LINE = re.compile(
        r"^(?P<fan>\S+)\s+"
        rf"(?P<status>{_FAN_STATUS})\s+"
        rf"(?P<configured>{_PERCENT_OR_NA})\s+"
        rf"(?P<actual>{_PERCENT_OR_NA})$"
    )

    @classmethod
    def _parse_speed(cls, value: str) -> int | None:
        """Parse a speed percentage string, returning None for N/A."""
        if value == "N/A":
            return None
        return int(value.rstrip("%"))

    @classmethod
    def _parse_fan_line(cls, line: str) -> tuple[str, FanEntry] | None:
        """Parse a single fan table row into a (name, entry) pair."""
        match = cls._FAN_LINE.match(line)
        if not match:
            return None

        entry = FanEntry(status=match.group("status").strip())

        configured = cls._parse_speed(match.group("configured"))
        if configured is not None:
            entry["configured_speed_pct"] = configured

        actual = cls._parse_speed(match.group("actual"))
        if actual is not None:
            entry["actual_speed_pct"] = actual

        return match.group("fan"), entry

    @classmethod
    def _parse_header(cls, line: str, result: dict[str, object]) -> bool:
        """Parse system status, ambient temp, or airflow from a header line."""
        if match := cls._SYSTEM_STATUS.match(line):
            result["system_status"] = match.group("status").strip()
            return True

        if match := cls._AMBIENT_TEMP.match(line):
            result["ambient_temperature_celsius"] = int(match.group("temp"))
            return True

        if match := cls._AIRFLOW.match(line):
            result["airflow"] = match.group("airflow").strip()
            return True

        return False

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentCoolingResult:
        """Parse 'show environment cooling' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed cooling environment information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result: dict[str, object] = {}
        fans: dict[str, FanEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if cls._parse_header(stripped, result):
                continue

            fan_pair = cls._parse_fan_line(stripped)
            if fan_pair:
                fans[fan_pair[0]] = fan_pair[1]

        result["fans"] = fans

        required = ["system_status", "ambient_temperature_celsius", "airflow", "fans"]
        missing = [f for f in required if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowEnvironmentCoolingResult, result)
