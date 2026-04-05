"""Parser for 'show version brief' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

from .show_version import UptimeInfo


class StorageDevice(TypedDict):
    """Schema for a storage device entry."""

    size: str
    sector_size: NotRequired[int]


class ShowVersionBriefResult(TypedDict):
    """Schema for 'show version brief' parsed output on IOS-XR."""

    software_version: str
    rom: NotRequired[str]
    device_name: NotRequired[str]
    uptime: NotRequired[UptimeInfo]
    image_file: NotRequired[str]
    chassis: str
    chassis_detail: NotRequired[str]
    processor: NotRequired[str]
    processor_speed: NotRequired[str]
    memory: NotRequired[str]
    nvram: NotRequired[str]
    interfaces: NotRequired[dict[str, int]]
    storage: NotRequired[dict[str, StorageDevice]]


@register(OS.CISCO_IOSXR, "show version brief")
class ShowVersionBriefParser(BaseParser[ShowVersionBriefResult]):
    """Parser for 'show version brief' command on Cisco IOS-XR.

    Parses the abbreviated version output containing software version,
    ROM, device name, uptime, image file, and chassis information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _SOFTWARE_VERSION = re.compile(
        r"^Cisco IOS XR Software,\s+Version\s+"
        r"(?P<version>[^\s\[]+)(?:\[Default\])?"
        r"(?:\s+(?P<extra>\S+))?$",
        re.I,
    )

    _ROM = re.compile(
        r"^ROM:\s+(?P<rom>.+?),?\s*$",
        re.I,
    )

    _DEVICE_UPTIME = re.compile(
        r"^(?P<hostname>\S+)\s+uptime\s+is\s+(?P<uptime>.+)$",
        re.I,
    )

    _SYSTEM_UPTIME = re.compile(
        r"^System uptime is\s+(?P<uptime>.+)$",
        re.I,
    )

    _IMAGE_FILE = re.compile(
        r'^System image file is\s+"(?P<file>[^"]+)"',
        re.I,
    )

    _CHASSIS_WITH_MEMORY = re.compile(
        r"^cisco\s+(?P<chassis>.+?)\s+\((?P<processor>[^)]+)\)\s+processor"
        r"\s+with\s+(?P<memory>\S+\s+\S+)\s+of\s+memory",
        re.I,
    )

    _PROCESSOR_SPEED = re.compile(
        r"^(?P<processor>.+?)\s+(?:at|@)\s+(?P<speed>\d+\S*Hz)",
        re.I,
    )

    _CHASSIS_DETAIL = re.compile(
        r"^(?P<detail>(?:ASR|CRS|NCS|IOS XRv|Cisco)\s+.*(?:Chassis|Slot).*)$",
        re.I,
    )

    _INTERFACE_COUNT = re.compile(
        r"^(?P<count>\d+)\s+(?P<type>.+?)(?:\s+interface\(s\))?\s*$",
        re.I,
    )

    _NVRAM = re.compile(
        r"^(?P<size>\S+)\s+bytes of non-volatile configuration memory",
        re.I,
    )

    _STORAGE = re.compile(
        r"^(?P<size>\S+)\s+bytes of\s+(?P<device>.+?)"
        r"(?:\s+\(Sector size\s+(?P<sector>\d+)\s+bytes\))?\s*\.\s*$",
        re.I,
    )

    _UPTIME_YEARS = re.compile(r"(\d+)\s+year", re.I)
    _UPTIME_WEEKS = re.compile(r"(\d+)\s+week", re.I)
    _UPTIME_DAYS = re.compile(r"(\d+)\s+day", re.I)
    _UPTIME_HOURS = re.compile(r"(\d+)\s+hour", re.I)
    _UPTIME_MINUTES = re.compile(r"(\d+)\s+minute", re.I)

    @classmethod
    def _parse_uptime_string(cls, uptime_str: str) -> UptimeInfo:
        """Parse an uptime string into an UptimeInfo dict."""
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
        """Parse software version and ROM lines."""
        if match := cls._SOFTWARE_VERSION.match(line):
            version = match.group("version")
            extra = match.group("extra")
            if extra:
                version = f"{version} {extra}"
            result["software_version"] = version
            return True

        if match := cls._ROM.match(line):
            result["rom"] = match.group("rom").rstrip(",").strip()
            return True

        return False

    @classmethod
    def _parse_uptime(cls, line: str, result: dict[str, object]) -> bool:
        """Parse uptime lines (system uptime or device-name uptime)."""
        if match := cls._SYSTEM_UPTIME.match(line):
            result["uptime"] = cls._parse_uptime_string(match.group("uptime"))
            return True

        if match := cls._DEVICE_UPTIME.match(line):
            result["device_name"] = match.group("hostname")
            result["uptime"] = cls._parse_uptime_string(match.group("uptime"))
            return True

        return False

    @classmethod
    def _parse_hardware(cls, line: str, result: dict[str, object]) -> bool:
        """Parse image file, chassis, interfaces, and storage lines."""
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

        if match := cls._PROCESSOR_SPEED.match(line):
            result["processor_speed"] = match.group("speed")
            return True

        if match := cls._CHASSIS_DETAIL.match(line):
            result["chassis_detail"] = match.group("detail").strip()
            return True

        if match := cls._NVRAM.match(line):
            result["nvram"] = match.group("size") + " bytes"
            return True

        if match := cls._STORAGE.match(line):
            storage = cast(dict[str, StorageDevice], result.setdefault("storage", {}))
            device: StorageDevice = {"size": match.group("size") + " bytes"}
            if match.group("sector"):
                device["sector_size"] = int(match.group("sector"))
            storage[match.group("device")] = device
            return True

        if match := cls._INTERFACE_COUNT.match(line):
            interfaces = cast(dict[str, int], result.setdefault("interfaces", {}))
            interfaces[match.group("type").strip()] = int(match.group("count"))
            return True

        return False

    @classmethod
    def parse(cls, output: str) -> ShowVersionBriefResult:
        """Parse 'show version brief' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed version brief information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result: dict[str, object] = {}

        for line in output.splitlines():
            stripped = line.rstrip()
            if stripped:
                (
                    cls._parse_software(stripped, result)
                    or cls._parse_uptime(stripped, result)
                    or cls._parse_hardware(stripped, result)
                )

        required = ["software_version", "chassis"]
        missing = [f for f in required if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowVersionBriefResult, result)
