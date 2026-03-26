"""Parser for 'show version' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class UptimeInfo(TypedDict):
    """Schema for uptime information."""

    days: int
    hours: int
    minutes: int
    seconds: int


class LastResetInfo(TypedDict):
    """Schema for last reset information."""

    reason: str
    system_version: NotRequired[str]
    service: NotRequired[str]
    timestamp: NotRequired[str]


class ShowVersionResult(TypedDict):
    """Schema for 'show version' parsed output."""

    # BIOS info (always present)
    bios_version: str
    bios_compile_time: NotRequired[str]

    # Modern NX-OS format
    nxos_version: NotRequired[str]
    nxos_image_file: NotRequired[str]
    nxos_compile_time: NotRequired[str]

    # LXC boot mode fields
    host_nxos_version: NotRequired[str]
    nxos_boot_mode: NotRequired[str]

    # Legacy kickstart/system format
    kickstart_version: NotRequired[str]
    kickstart_image_file: NotRequired[str]
    kickstart_compile_time: NotRequired[str]
    system_version: NotRequired[str]
    system_image_file: NotRequired[str]
    system_compile_time: NotRequired[str]

    # ACI-specific
    pe_version: NotRequired[str]

    # Older devices
    loader_version: NotRequired[str]

    # Hardware info (always present)
    chassis: str
    cpu: str
    memory_kb: int
    processor_board_id: str
    device_name: str
    bootflash_kb: int

    # Uptime and reset info
    uptime: UptimeInfo
    last_reset: LastResetInfo

    # Plugins
    plugins: list[str]


@register(OS.CISCO_NXOS, "show version")
class ShowVersionParser(BaseParser[ShowVersionResult]):
    """Parser for 'show version' command on NX-OS.

    Parses system version, hardware, and uptime information.
    Supports both modern NX-OS format and legacy kickstart/system format.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INVENTORY,
            ParserTag.SYSTEM,
        }
    )

    # Software version patterns
    _BIOS_VERSION = re.compile(r"^\s*BIOS:\s*version\s+(?P<version>\S+)", re.I)
    _BIOS_COMPILE = re.compile(r"^\s*BIOS compile time:\s*(?P<time>.+)$", re.I)

    # Match NXOS version - strip trailing [build X.X.X] but keep [Feature Release]
    _NXOS_VERSION = re.compile(
        r"^\s*NXOS:\s*version\s+(?P<version>.+?)(?:\s+\[build\s+[^\]]+\])?$", re.I
    )
    _NXOS_IMAGE = re.compile(r"^\s*NXOS image file is:\s*(?P<file>.+)$", re.I)
    _NXOS_COMPILE = re.compile(r"^\s*NXOS compile time:\s*(?P<time>.+)$", re.I)

    _HOST_NXOS_VERSION = re.compile(
        r"^\s*Host NXOS:\s*version\s+(?P<version>\S+)", re.I
    )
    _NXOS_BOOT_MODE = re.compile(r"^\s*NXOS boot mode:\s*(?P<mode>\S+)", re.I)

    _KICKSTART_VERSION = re.compile(
        r"^\s*kickstart:\s*version\s+(?P<version>.+?)(?:\s+\[.+\])?$", re.I
    )
    _KICKSTART_IMAGE = re.compile(r"^\s*kickstart image file is:\s*(?P<file>.+)$", re.I)
    _KICKSTART_COMPILE = re.compile(
        r"^\s*kickstart compile time:\s*(?P<time>.+)$", re.I
    )

    _SYSTEM_VERSION = re.compile(
        r"^\s*system:\s*version\s+(?P<version>.+?)(?:\s+\[.+\])?$", re.I
    )
    _SYSTEM_IMAGE = re.compile(r"^\s*system image file is:\s*(?P<file>.+)$", re.I)
    _SYSTEM_COMPILE = re.compile(r"^\s*system compile time:\s*(?P<time>.+)$", re.I)

    _PE_VERSION = re.compile(r"^\s*PE:\s*version\s+(?P<version>\S+)", re.I)
    _LOADER_VERSION = re.compile(r"^\s*loader:\s*version\s+(?P<version>\S+)", re.I)

    # Hardware patterns
    _CHASSIS = re.compile(r"^\s*cisco\s+(?P<chassis>.+)$", re.I)
    _CPU_MEMORY = re.compile(
        r"^\s*(?P<cpu>.+?)\s+with\s+(?P<memory>\d+)\s+kB of memory", re.I
    )
    _PROCESSOR_BOARD = re.compile(r"^\s*Processor Board ID\s+(?P<id>\S+)", re.I)
    _DEVICE_NAME = re.compile(r"^\s*Device name:\s*(?P<name>\S+)", re.I)
    _BOOTFLASH = re.compile(r"^\s*bootflash:\s*(?P<size>\d+)\s+kB", re.I)

    # Uptime pattern
    _UPTIME = re.compile(
        r"Kernel uptime is\s+(?P<days>\d+)\s+day\(s\),\s+"
        r"(?P<hours>\d+)\s+hour\(s\),\s+"
        r"(?P<minutes>\d+)\s+minute\(s\),\s+"
        r"(?P<seconds>\d+)\s+second\(s\)",
        re.I,
    )

    # Last reset patterns
    _LAST_RESET_AT = re.compile(
        r"Last reset at\s+(?:\d+\s+usecs after\s+)?(?P<timestamp>.+)$", re.I
    )
    _RESET_REASON = re.compile(r"^\s*Reason:\s*(?P<reason>.+)$", re.I)
    _RESET_SYSTEM_VERSION = re.compile(r"^\s*System version:\s*(?P<version>.*)$", re.I)
    _RESET_SERVICE = re.compile(r"^\s*Service:\s*(?P<service>.*)$", re.I)

    # Plugin pattern
    _PLUGIN = re.compile(r"^\s*(?P<plugins>(?:\w+\s+Plugin)(?:,\s*\w+\s+Plugin)*)$")

    @classmethod
    def _normalize_value(cls, value: str | None) -> str | None:
        """Normalize a value, converting N/A and empty to None."""
        if value is None:
            return None
        value = value.strip()
        if not value or value.upper() == "N/A":
            return None
        return value

    @classmethod
    def _parse_bios(cls, line: str, result: dict[str, object]) -> bool:
        if match := cls._BIOS_VERSION.match(line):
            result["bios_version"] = match.group("version")
            return True

        if match := cls._BIOS_COMPILE.match(line):
            result["bios_compile_time"] = match.group("time").strip()
            return True

        return False

    @classmethod
    def _parse_nxos(cls, line: str, result: dict[str, object]) -> bool:
        if match := cls._NXOS_VERSION.match(line):
            result["nxos_version"] = match.group("version").strip()
            return True

        if match := cls._NXOS_IMAGE.match(line):
            result["nxos_image_file"] = match.group("file").strip()
            return True

        if match := cls._NXOS_COMPILE.match(line):
            result["nxos_compile_time"] = match.group("time").strip()
            return True

        if match := cls._HOST_NXOS_VERSION.match(line):
            result["host_nxos_version"] = match.group("version")
            return True

        if match := cls._NXOS_BOOT_MODE.match(line):
            result["nxos_boot_mode"] = match.group("mode")
            return True

        return False

    @classmethod
    def _parse_kickstart(cls, line: str, result: dict[str, object]) -> bool:
        if match := cls._KICKSTART_VERSION.match(line):
            result["kickstart_version"] = match.group("version").strip()
            return True

        if match := cls._KICKSTART_IMAGE.match(line):
            result["kickstart_image_file"] = match.group("file").strip()
            return True

        if match := cls._KICKSTART_COMPILE.match(line):
            result["kickstart_compile_time"] = match.group("time").strip()
            return True

        if match := cls._SYSTEM_VERSION.match(line):
            result["system_version"] = match.group("version").strip()
            return True

        if match := cls._SYSTEM_IMAGE.match(line):
            result["system_image_file"] = match.group("file").strip()
            return True

        if match := cls._SYSTEM_COMPILE.match(line):
            result["system_compile_time"] = match.group("time").strip()
            return True

        if match := cls._PE_VERSION.match(line):
            result["pe_version"] = match.group("version")
            return True

        if match := cls._LOADER_VERSION.match(line):
            loader = cls._normalize_value(match.group("version"))
            if loader:
                result["loader_version"] = loader
            return True

        return False

    @classmethod
    def _parse_hardware(cls, line: str, result: dict[str, object]) -> bool:
        if match := cls._CHASSIS.match(line):
            chassis = f"cisco {match.group('chassis').strip()}"
            result["chassis"] = chassis
            return True

        if match := cls._CPU_MEMORY.match(line):
            result["cpu"] = match.group("cpu").strip()
            result["memory_kb"] = int(match.group("memory"))
            return True

        if match := cls._PROCESSOR_BOARD.match(line):
            result["processor_board_id"] = match.group("id")
            return True

        if match := cls._DEVICE_NAME.match(line):
            result["device_name"] = match.group("name")
            return True

        if match := cls._BOOTFLASH.match(line):
            result["bootflash_kb"] = int(match.group("size"))
            return True

        return False

    @classmethod
    def _parse_uptime(cls, line: str, result: dict[str, object]) -> bool:
        if match := cls._UPTIME.search(line):
            result["uptime"] = UptimeInfo(
                days=int(match.group("days")),
                hours=int(match.group("hours")),
                minutes=int(match.group("minutes")),
                seconds=int(match.group("seconds")),
            )
            return True

        return False

    @classmethod
    def _parse_last_reset(cls, line: str, last_reset: dict[str, str]) -> bool:
        if match := cls._LAST_RESET_AT.match(line):
            timestamp = match.group("timestamp").strip()
            if timestamp:
                last_reset["timestamp"] = timestamp
            return True

        if match := cls._RESET_REASON.match(line):
            last_reset["reason"] = match.group("reason").strip()
            return True

        if match := cls._RESET_SYSTEM_VERSION.match(line):
            version = cls._normalize_value(match.group("version"))
            if version:
                last_reset["system_version"] = version
            return True

        if match := cls._RESET_SERVICE.match(line):
            service = cls._normalize_value(match.group("service"))
            if service:
                last_reset["service"] = service
            return True

        return False

    @classmethod
    def _parse_plugins(cls, line: str, result: dict[str, object]) -> bool:
        if match := cls._PLUGIN.match(line):
            plugins_str = match.group("plugins")
            result["plugins"] = [p.strip() for p in plugins_str.split(",")]
            return True

        return False

    @classmethod
    def _parse_line(
        cls,
        line: str,
        result: dict[str, object],
        last_reset: dict[str, str],
    ) -> bool:
        return (
            cls._parse_bios(line, result)
            or cls._parse_nxos(line, result)
            or cls._parse_kickstart(line, result)
            or cls._parse_hardware(line, result)
            or cls._parse_uptime(line, result)
            or cls._parse_last_reset(line, last_reset)
            or cls._parse_plugins(line, result)
        )

    @classmethod
    def parse(cls, output: str) -> ShowVersionResult:
        """Parse 'show version' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed version information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        # Initialize result with required fields
        result: dict[str, object] = {}
        last_reset: dict[str, str] = {}

        lines = output.splitlines()
        for line in lines:
            cls._parse_line(line, result, last_reset)

        # Validate required fields
        required = ["bios_version", "chassis", "cpu", "memory_kb", "device_name"]
        missing = [f for f in required if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        # Add last_reset if we have at least the reason
        if "reason" in last_reset:
            result["last_reset"] = last_reset

        # Default plugins if not found
        if "plugins" not in result:
            result["plugins"] = []

        return cast(ShowVersionResult, result)
