"""Parser for 'show version' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class UptimeInfo(TypedDict):
    """Schema for uptime information."""

    weeks: NotRequired[int]
    days: int
    hours: int
    minutes: int


class ShowVersionResult(TypedDict):
    """Schema for 'show version' parsed output on Arista EOS."""

    # Model / hardware
    model: str
    hardware_version: NotRequired[str]
    serial_number: NotRequired[str]
    hardware_mac_address: NotRequired[str]
    system_mac_address: str

    # Software
    software_image_version: str
    architecture: str
    internal_build_version: str
    internal_build_id: str
    image_format_version: NotRequired[str]
    image_optimization: NotRequired[str]

    # cEOS-specific
    ceos_tools_version: NotRequired[str]
    kernel_version: NotRequired[str]

    # Uptime
    uptime: UptimeInfo

    # Memory
    total_memory_kb: int
    free_memory_kb: int


@register(OS.ARISTA_EOS, "show version")
class ShowVersionParser(BaseParser[ShowVersionResult]):
    """Parser for 'show version' command on Arista EOS.

    Parses system version, hardware, and uptime information.
    Supports physical hardware, vEOS, and cEOS variants.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INVENTORY,
            ParserTag.SYSTEM,
        }
    )

    # First line: model identifier
    _MODEL = re.compile(r"^Arista\s+(?P<model>.+)$")

    # Hardware info
    _HARDWARE_VERSION = re.compile(r"^Hardware version:\s*(?P<version>.+)$")
    _SERIAL_NUMBER = re.compile(r"^Serial number:\s*(?P<serial>.+)$")
    _HARDWARE_MAC = re.compile(r"^Hardware MAC address:\s*(?P<mac>\S+)", re.I)
    _SYSTEM_MAC = re.compile(r"^System MAC address:\s*(?P<mac>\S+)", re.I)

    # Software info
    _SOFTWARE_VERSION = re.compile(r"^Software image version:\s*(?P<version>.+)$")
    _ARCHITECTURE = re.compile(r"^Architecture:\s*(?P<arch>\S+)")
    _INTERNAL_BUILD_VERSION = re.compile(r"^Internal build version:\s*(?P<version>.+)$")
    _INTERNAL_BUILD_ID = re.compile(r"^Internal build ID:\s*(?P<id>\S+)")
    _IMAGE_FORMAT_VERSION = re.compile(r"^Image format version:\s*(?P<version>.+)$")
    _IMAGE_OPTIMIZATION = re.compile(r"^Image optimization:\s*(?P<opt>.+)$")

    # cEOS-specific
    _CEOS_TOOLS_VERSION = re.compile(r"^cEOS tools version:\s*(?P<version>.+)$")
    _KERNEL_VERSION = re.compile(r"^Kernel version:\s*(?P<version>.+)$")

    # Uptime
    _UPTIME = re.compile(r"^Uptime:\s*(?P<uptime>.+)$")
    _UPTIME_WEEKS = re.compile(r"(?P<weeks>\d+)\s+weeks?")
    _UPTIME_DAYS = re.compile(r"(?P<days>\d+)\s+days?")
    _UPTIME_HOURS = re.compile(r"(?P<hours>\d+)\s+hours?")
    _UPTIME_MINUTES = re.compile(r"(?P<minutes>\d+)\s+minutes?")

    # Memory
    _TOTAL_MEMORY = re.compile(r"^Total memory:\s*(?P<memory>\d+)\s+kB")
    _FREE_MEMORY = re.compile(r"^Free memory:\s*(?P<memory>\d+)\s+kB")

    @classmethod
    def _parse_uptime_string(cls, uptime_str: str) -> UptimeInfo:
        """Parse an Arista EOS uptime string.

        Args:
            uptime_str: Raw uptime string from CLI output.

        Returns:
            UptimeInfo dict with parsed components.
        """
        result: dict[str, int] = {}

        if match := cls._UPTIME_WEEKS.search(uptime_str):
            result["weeks"] = int(match.group("weeks"))

        days_match = cls._UPTIME_DAYS.search(uptime_str)
        result["days"] = int(days_match.group("days")) if days_match else 0

        hours_match = cls._UPTIME_HOURS.search(uptime_str)
        result["hours"] = int(hours_match.group("hours")) if hours_match else 0

        minutes_match = cls._UPTIME_MINUTES.search(uptime_str)
        result["minutes"] = int(minutes_match.group("minutes")) if minutes_match else 0

        return cast(UptimeInfo, result)

    @classmethod
    def _parse_hardware(cls, line: str, result: dict[str, object]) -> bool:
        """Parse hardware-related fields from a single line."""
        if match := cls._MODEL.match(line):
            result["model"] = match.group("model").strip()
            return True

        if match := cls._HARDWARE_VERSION.match(line):
            version = match.group("version").strip()
            if version:
                result["hardware_version"] = version
            return True

        if match := cls._SERIAL_NUMBER.match(line):
            serial = match.group("serial").strip()
            if serial:
                result["serial_number"] = serial
            return True

        if match := cls._HARDWARE_MAC.match(line):
            result["hardware_mac_address"] = match.group("mac")
            return True

        if match := cls._SYSTEM_MAC.match(line):
            result["system_mac_address"] = match.group("mac")
            return True

        return False

    @classmethod
    def _parse_software(cls, line: str, result: dict[str, object]) -> bool:
        """Parse software-related fields from a single line."""
        if match := cls._SOFTWARE_VERSION.match(line):
            result["software_image_version"] = match.group("version").strip()
            return True

        if match := cls._ARCHITECTURE.match(line):
            result["architecture"] = match.group("arch")
            return True

        if match := cls._INTERNAL_BUILD_VERSION.match(line):
            result["internal_build_version"] = match.group("version").strip()
            return True

        if match := cls._INTERNAL_BUILD_ID.match(line):
            result["internal_build_id"] = match.group("id")
            return True

        if match := cls._IMAGE_FORMAT_VERSION.match(line):
            result["image_format_version"] = match.group("version").strip()
            return True

        if match := cls._IMAGE_OPTIMIZATION.match(line):
            result["image_optimization"] = match.group("opt").strip()
            return True

        return False

    @classmethod
    def _parse_ceos(cls, line: str, result: dict[str, object]) -> bool:
        """Parse cEOS-specific fields from a single line."""
        if match := cls._CEOS_TOOLS_VERSION.match(line):
            result["ceos_tools_version"] = match.group("version").strip()
            return True

        if match := cls._KERNEL_VERSION.match(line):
            result["kernel_version"] = match.group("version").strip()
            return True

        return False

    @classmethod
    def _parse_system(cls, line: str, result: dict[str, object]) -> bool:
        """Parse uptime and memory fields from a single line."""
        if match := cls._UPTIME.match(line):
            result["uptime"] = cls._parse_uptime_string(match.group("uptime"))
            return True

        if match := cls._TOTAL_MEMORY.match(line):
            result["total_memory_kb"] = int(match.group("memory"))
            return True

        if match := cls._FREE_MEMORY.match(line):
            result["free_memory_kb"] = int(match.group("memory"))
            return True

        return False

    @classmethod
    def _parse_line(cls, line: str, result: dict[str, object]) -> bool:
        """Dispatch a single line to the appropriate sub-parser."""
        return (
            cls._parse_hardware(line, result)
            or cls._parse_software(line, result)
            or cls._parse_ceos(line, result)
            or cls._parse_system(line, result)
        )

    @classmethod
    def parse(cls, output: str) -> ShowVersionResult:
        """Parse 'show version' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed version information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result: dict[str, object] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if stripped:
                cls._parse_line(stripped, result)

        # Validate required fields
        required_fields = [
            "model",
            "system_mac_address",
            "software_image_version",
            "architecture",
            "internal_build_version",
            "internal_build_id",
            "uptime",
            "total_memory_kb",
            "free_memory_kb",
        ]
        missing = [f for f in required_fields if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowVersionResult, result)
