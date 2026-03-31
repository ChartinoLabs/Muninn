"""Parser for 'show system uptime' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowSystemUptimeResult(TypedDict):
    """Schema for 'show system uptime' parsed output.

    Captures current time, time source, boot time, protocol start time,
    last configuration change, and uptime string from Juniper Junos devices.
    """

    current_time: str
    time_source: NotRequired[str]
    system_booted_at: str
    system_booted_ago: str
    protocols_started_at: str
    protocols_started_ago: str
    last_configured_at: str
    last_configured_ago: str
    last_configured_by: NotRequired[str]
    uptime: str


_TS = r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+"
_TS_AGO = rf"(?P<time>{_TS})\s+\((?P<ago>[^)]+)\)"


@register(OS.JUNIPER_JUNOS, "show system uptime")
class ShowSystemUptimeParser(BaseParser[ShowSystemUptimeResult]):
    """Parser for 'show system uptime' command on Juniper Junos.

    Parses current time, boot time, protocol start time, last configuration
    change, and the uptime summary line.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _CURRENT_TIME = re.compile(rf"^Current time:\s+(?P<time>{_TS})")
    _TIME_SOURCE = re.compile(r"^Time Source:\s+(?P<source>.+?)\s*$")
    _SYSTEM_BOOTED = re.compile(rf"^System booted:\s+{_TS_AGO}")
    _PROTOCOLS_STARTED = re.compile(rf"^Protocols started:\s+{_TS_AGO}")
    _LAST_CONFIGURED = re.compile(
        rf"^Last configured:\s+{_TS_AGO}" r"(?:\s+by\s+(?P<user>\S+))?"
    )
    _UPTIME = re.compile(r"^\s*\d+:\d{2}[AP]M\s+up\s+(?P<uptime>.+?),\s+\d+\s+users?,")

    _REQUIRED_FIELDS = (
        "current_time",
        "system_booted_at",
        "system_booted_ago",
        "protocols_started_at",
        "protocols_started_ago",
        "last_configured_at",
        "last_configured_ago",
        "uptime",
    )

    @classmethod
    def _parse_timestamp_line(cls, line: str, result: dict[str, str]) -> bool:
        """Try to match a timestamp+ago line and store its fields."""
        patterns = (
            (cls._SYSTEM_BOOTED, "system_booted"),
            (cls._PROTOCOLS_STARTED, "protocols_started"),
            (cls._LAST_CONFIGURED, "last_configured"),
        )
        for pattern, prefix in patterns:
            match = pattern.match(line)
            if not match:
                continue
            result[f"{prefix}_at"] = match.group("time")
            result[f"{prefix}_ago"] = match.group("ago")
            if "user" in match.groupdict() and match.group("user"):
                result[f"{prefix}_by"] = match.group("user")
            return True
        return False

    @classmethod
    def _parse_line(cls, line: str, result: dict[str, str]) -> None:
        """Parse a single line, updating result in place."""
        if match := cls._CURRENT_TIME.match(line):
            result["current_time"] = match.group("time")
        elif match := cls._TIME_SOURCE.match(line):
            result["time_source"] = match.group("source")
        elif cls._parse_timestamp_line(line, result):
            pass
        elif match := cls._UPTIME.match(line):
            result["uptime"] = match.group("uptime")

    @classmethod
    def parse(cls, output: str) -> ShowSystemUptimeResult:
        """Parse 'show system uptime' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed uptime information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result: dict[str, str] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if stripped:
                cls._parse_line(stripped, result)

        missing = [f for f in cls._REQUIRED_FIELDS if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowSystemUptimeResult, result)
