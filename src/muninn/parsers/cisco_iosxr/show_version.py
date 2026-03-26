"""Parser for 'show version' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class UptimeInfo(TypedDict):
    """Schema for uptime information."""

    years: NotRequired[int]
    weeks: NotRequired[int]
    days: NotRequired[int]
    hours: NotRequired[int]
    minutes: NotRequired[int]


class BuildInfo(TypedDict):
    """Schema for build information (IOS-XR 6.x+ format)."""

    built_by: NotRequired[str]
    built_on: NotRequired[str]
    built_host: NotRequired[str]
    workspace: NotRequired[str]
    version: NotRequired[str]
    location: NotRequired[str]
    label: NotRequired[str]


class ShowVersionResult(TypedDict):
    """Schema for 'show version' parsed output on IOS-XR."""

    # Software info (always present)
    software_version: str

    # Copyright year(s) (e.g. "2017" or "2013-2017")
    copyright_years: NotRequired[str]

    # ROM/bootstrap info
    rom: NotRequired[str]

    # Build info block (newer IOS-XR format)
    build_info: NotRequired[BuildInfo]

    # Device identification
    device_name: NotRequired[str]
    chassis: str
    chassis_detail: NotRequired[str]
    processor: NotRequired[str]
    processor_speed: NotRequired[str]
    memory: NotRequired[str]

    # System image
    image_file: NotRequired[str]

    # Uptime
    uptime: NotRequired[UptimeInfo]

    # Configuration register
    config_register: NotRequired[str]


@register(OS.CISCO_IOSXR, "show version")
class ShowVersionParser(BaseParser[ShowVersionResult]):
    """Parser for 'show version' command on Cisco IOS-XR.

    Parses system version, hardware, and uptime information.
    Supports both classic (ASR9K/CRS) and modern (NCS/XRv9000) output formats.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INVENTORY,
            ParserTag.SYSTEM,
        }
    )

    # Software version line — strip optional [Default] suffix
    _SOFTWARE_VERSION = re.compile(
        r"^Cisco IOS XR Software,\s+Version\s+"
        r"(?P<version>[^\s\[]+)(?:\[Default\])?"
        r"(?:\s+(?P<extra>\S+))?$",
        re.I,
    )

    # Copyright line
    _COPYRIGHT = re.compile(
        r"^Copyright \(c\)\s+(?P<years>\d+(?:-\d+)?)\s+by Cisco Systems",
        re.I,
    )

    # ROM line
    _ROM = re.compile(
        r"^ROM:\s+(?P<rom>.+?),?\s*$",
        re.I,
    )

    # Build info fields
    _BUILD_BUILT_BY = re.compile(r"^\s+Built By\s+:\s+(?P<value>\S+)", re.I)
    _BUILD_BUILT_ON = re.compile(r"^\s+Built On\s+:\s+(?P<value>.+?)\s*$", re.I)
    _BUILD_BUILT_HOST = re.compile(
        r"^\s+(?:Build|Built) Host\s+:\s+(?P<value>\S+)", re.I
    )
    _BUILD_WORKSPACE = re.compile(r"^\s+Workspace\s+:\s+(?P<value>\S+)", re.I)
    _BUILD_VERSION = re.compile(r"^\s+Version\s+:\s+(?P<value>\S+)", re.I)
    _BUILD_LOCATION = re.compile(r"^\s+Location\s+:\s+(?P<value>\S+)", re.I)
    _BUILD_LABEL = re.compile(r"^\s+Label\s+:\s+(?P<value>\S+)", re.I)

    # Device name and uptime in format: "<hostname> uptime is ..."
    _DEVICE_UPTIME = re.compile(
        r"^(?P<hostname>\S+)\s+uptime\s+is\s+(?P<uptime>.+)$",
        re.I,
    )

    # System uptime (no hostname prefix)
    _SYSTEM_UPTIME = re.compile(
        r"^System uptime is\s+(?P<uptime>.+)$",
        re.I,
    )

    # System image file
    _IMAGE_FILE = re.compile(
        r'^System image file is\s+"(?P<file>[^"]+)"',
        re.I,
    )

    # Chassis line: "cisco <model> (<processor>) processor with <memory>"
    _CHASSIS_WITH_MEMORY = re.compile(
        r"^cisco\s+(?P<chassis>.+?)\s+\((?P<processor>[^)]+)\)\s+processor"
        r"\s+with\s+(?P<memory>\S+\s+\S+)\s+of\s+memory",
        re.I,
    )

    # Chassis line without memory: "cisco <model> (<processor>) processor"
    _CHASSIS_PROCESSOR = re.compile(
        r"^cisco\s+(?P<chassis>.+?)\s+\((?P<processor>[^)]*)\)\s+processor",
        re.I,
    )

    # Processor speed line: "<processor> at <speed>, Revision ..."
    _PROCESSOR_SPEED = re.compile(
        r"^(?P<processor>.+?)\s+(?:at|@)\s+(?P<speed>\d+\S*Hz)",
        re.I,
    )

    # Chassis detail line (standalone, e.g. "ASR 9006 4 Line Card Slot Chassis ...")
    # or "IOS XRv Chassis" or "CRS 16 Slots ..."
    _CHASSIS_DETAIL = re.compile(
        r"^(?P<detail>(?:ASR|CRS|NCS|IOS XRv|Cisco)\s+.*(?:Chassis|Slot).*)$",
        re.I,
    )

    # Configuration register
    _CONFIG_REGISTER = re.compile(
        r"^Configuration register on node \S+ is (?P<value>\S+)",
        re.I,
    )

    # Uptime duration components
    _UPTIME_YEARS = re.compile(r"(\d+)\s+year", re.I)
    _UPTIME_WEEKS = re.compile(r"(\d+)\s+week", re.I)
    _UPTIME_DAYS = re.compile(r"(\d+)\s+day", re.I)
    _UPTIME_HOURS = re.compile(r"(\d+)\s+hour", re.I)
    _UPTIME_MINUTES = re.compile(r"(\d+)\s+minute", re.I)

    @classmethod
    def _parse_uptime_string(cls, uptime_str: str) -> UptimeInfo:
        """Parse an uptime string into an UptimeInfo dict.

        Handles formats like:
            "5 hours, 14 minutes"
            "5 days, 25 minutes"
            "1 week, 1 day, 5 hours, 47 minutes"
            "1 minute"
            "23 hours 3 minutes"
        """
        info: UptimeInfo = {}

        if match := cls._UPTIME_YEARS.search(uptime_str):
            info["years"] = int(match.group(1))
        if match := cls._UPTIME_WEEKS.search(uptime_str):
            info["weeks"] = int(match.group(1))
        if match := cls._UPTIME_DAYS.search(uptime_str):
            info["days"] = int(match.group(1))
        if match := cls._UPTIME_HOURS.search(uptime_str):
            info["hours"] = int(match.group(1))
        if match := cls._UPTIME_MINUTES.search(uptime_str):
            info["minutes"] = int(match.group(1))

        return info

    @classmethod
    def _parse_software(cls, line: str, result: dict[str, object]) -> bool:
        """Parse software version, copyright, and ROM lines."""
        if match := cls._SOFTWARE_VERSION.match(line):
            version = match.group("version")
            extra = match.group("extra")
            if extra:
                version = f"{version} {extra}"
            result["software_version"] = version
            return True

        if match := cls._COPYRIGHT.match(line):
            result["copyright_years"] = match.group("years")
            return True

        if match := cls._ROM.match(line):
            result["rom"] = match.group("rom").rstrip(",").strip()
            return True

        return False

    @classmethod
    def _parse_build_info(cls, line: str, build_info: BuildInfo) -> bool:
        """Parse build information block fields."""
        if match := cls._BUILD_BUILT_BY.match(line):
            build_info["built_by"] = match.group("value")
            return True
        if match := cls._BUILD_BUILT_ON.match(line):
            build_info["built_on"] = match.group("value")
            return True
        if match := cls._BUILD_BUILT_HOST.match(line):
            build_info["built_host"] = match.group("value")
            return True
        if match := cls._BUILD_WORKSPACE.match(line):
            build_info["workspace"] = match.group("value")
            return True
        if match := cls._BUILD_VERSION.match(line):
            build_info["version"] = match.group("value")
            return True
        if match := cls._BUILD_LOCATION.match(line):
            build_info["location"] = match.group("value")
            return True
        if match := cls._BUILD_LABEL.match(line):
            build_info["label"] = match.group("value")
            return True
        return False

    @classmethod
    def _parse_uptime(cls, line: str, result: dict[str, object]) -> bool:
        """Parse uptime lines (system uptime or device-name uptime)."""
        # System uptime (no hostname) — check before device uptime
        if match := cls._SYSTEM_UPTIME.match(line):
            result["uptime"] = cls._parse_uptime_string(match.group("uptime"))
            return True

        # Device name + uptime (e.g. "PE1 uptime is 5 hours, 14 minutes")
        if match := cls._DEVICE_UPTIME.match(line):
            result["device_name"] = match.group("hostname")
            result["uptime"] = cls._parse_uptime_string(match.group("uptime"))
            return True

        return False

    @classmethod
    def _parse_hardware(cls, line: str, result: dict[str, object]) -> bool:
        """Parse chassis, processor, memory, and config register lines."""
        if match := cls._IMAGE_FILE.match(line):
            result["image_file"] = match.group("file")
            return True

        if match := cls._CHASSIS_WITH_MEMORY.match(line):
            result["chassis"] = f"cisco {match.group('chassis')}"
            processor = match.group("processor").strip()
            if processor:
                result["processor"] = processor
            result["memory"] = match.group("memory")
            return True

        if match := cls._CHASSIS_PROCESSOR.match(line):
            if "chassis" not in result:
                result["chassis"] = f"cisco {match.group('chassis')}"
                processor = match.group("processor").strip()
                if processor:
                    result["processor"] = processor
            return True

        if match := cls._PROCESSOR_SPEED.match(line):
            result["processor_speed"] = match.group("speed")
            return True

        if match := cls._CHASSIS_DETAIL.match(line):
            result["chassis_detail"] = match.group("detail").strip()
            return True

        if match := cls._CONFIG_REGISTER.match(line):
            result["config_register"] = match.group("value")
            return True

        return False

    @classmethod
    def _parse_line(
        cls,
        line: str,
        result: dict[str, object],
        build_info: BuildInfo,
    ) -> bool:
        """Dispatch a single line to the appropriate sub-parser."""
        return (
            cls._parse_software(line, result)
            or cls._parse_build_info(line, build_info)
            or cls._parse_uptime(line, result)
            or cls._parse_hardware(line, result)
        )

    @classmethod
    def parse(cls, output: str) -> ShowVersionResult:
        """Parse 'show version' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed version information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result: dict[str, object] = {}
        build_info: BuildInfo = {}

        for line in output.splitlines():
            stripped = line.rstrip()
            if stripped:
                cls._parse_line(stripped, result, build_info)

        # Add build_info if any fields were parsed
        if build_info:
            result["build_info"] = build_info

        # Validate required fields
        required = ["software_version", "chassis"]
        missing = [f for f in required if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowVersionResult, result)
