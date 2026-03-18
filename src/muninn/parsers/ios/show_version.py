"""Parser for 'show version' command on IOS/IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# --- Constants ---
BYTES_PER_KB = 1024


class MemoryEntry(TypedDict):
    """Schema for memory information."""

    total_bytes: int
    io_bytes: NotRequired[int]


class LicenseEntry(TypedDict):
    """Schema for license information."""

    level: str
    type: NotRequired[str]
    next_reload_level: NotRequired[str]


class SwitchStackEntry(TypedDict):
    """Schema for a single switch in a stack."""

    switch_number: int
    ports: int
    model: str
    sw_version: str
    sw_image: str
    active: bool
    mode: NotRequired[str]


class ShowVersionResult(TypedDict):
    """Schema for 'show version' parsed output."""

    hostname: str
    version: str
    system_image: str
    config_register: str
    platform: str
    serial_number: str
    compiled: str
    uptime: str
    memory: MemoryEntry
    image_type: NotRequired[str]
    rom_version: NotRequired[str]
    bootldr_version: NotRequired[str]
    restarted_at: NotRequired[str]
    last_reload_reason: NotRequired[str]
    system_returned_to_rom_by: NotRequired[str]
    nvram_bytes: NotRequired[int]
    license: NotRequired[LicenseEntry]
    mac_address: NotRequired[str]
    model_number: NotRequired[str]
    motherboard_serial: NotRequired[str]
    interfaces: NotRequired[dict[str, int]]
    switch_stack: NotRequired[list[SwitchStackEntry]]
    config_register_next: NotRequired[str]


# --- Regex patterns ---

# Version line: multiple formats
_VERSION_RE = re.compile(r"Version\s+(\S+?)(?:,|\s|$)")

# Image type from software line, e.g. "(C3750E-UNIVERSALK9-M)"
_IMAGE_TYPE_RE = re.compile(r"\(([A-Za-z0-9][A-Za-z0-9_-]+-[A-Za-z0-9]+)\)")

# Compiled line
_COMPILED_RE = re.compile(r"^Compiled\s+(.+)$")

# ROM version
_ROM_RE = re.compile(r"^ROM:\s+(.+?)\s*$")

# BOOTLDR version
_BOOTLDR_RE = re.compile(r"^BOOTLDR:\s+(.+?)\s*$")

# Uptime line: "{hostname} uptime is {uptime}"
_UPTIME_RE = re.compile(r"^(\S+)\s+uptime\s+is\s+(.+?)\s*$")

# System returned to ROM
_RETURNED_TO_ROM_RE = re.compile(r"^System returned to ROM by\s+(.+?)\s*$")

# System restarted at
_RESTARTED_RE = re.compile(r"^System restarted at\s+(.+?)\s*$")

# System image file
_IMAGE_FILE_RE = re.compile(r'^System image file is "(.+?)"')

# Last reload reason
_RELOAD_REASON_RE = re.compile(r"^Last reload reason:\s+(.+?)\s*$")

# Processor line with memory: "cisco <model> (<cpu>) processor ... with <mem>K bytes"
_PROCESSOR_RE = re.compile(
    r"^[Cc]isco\s+(\S+)\s+\(.+?\)\s+(?:processor\s+)?"
    r".*?with\s+(\d+)K(?:/(\d+)K)?\s+bytes\s+of\s+memory"
)

# Alternate processor line (IOSv style):
# "Cisco IOSv (revision ...) with  with <mem>K/<io>K bytes"
_PROCESSOR_ALT_RE = re.compile(
    r"^[Cc]isco\s+(\S+)\s+\(revision\s+.+?\)\s+"
    r"(?:with\s+)+(\d+)K(?:/(\d+)K)?\s+bytes\s+of\s+memory"
)

# Serial number
_SERIAL_RE = re.compile(r"^Processor board ID\s+(\S+)")

# Interface counts: "N <type> interface(s)" or "N <type> interfaces"
_INTERFACE_RE = re.compile(r"^(\d+)\s+(.+?)\s+interface(?:s|\(s\))?\s*$")

# NVRAM: "NNK bytes of ... non-volatile configuration memory"
_NVRAM_RE = re.compile(
    r"^(\d+)K\s+bytes\s+of\s+(?:flash-simulated\s+)?non-volatile\s+configuration\s+memory"
)

# License level
_LICENSE_LEVEL_RE = re.compile(r"^License Level:\s+(.+?)\s*$")

# License type
_LICENSE_TYPE_RE = re.compile(r"^License Type:\s+(.+?)\s*$")

# Next reload license level
_LICENSE_NEXT_RE = re.compile(r"^Next reload license Level:\s+(.+?)\s*$")

# Technology package license table row (C3850 style)
_TECH_PKG_RE = re.compile(r"^(\S+k9)\s+(Permanent|Evaluation|RightToUse)\s+(\S+k9)\s*$")

# Base ethernet MAC address
_MAC_RE = re.compile(r"^Base [Ee]thernet MAC [Aa]ddress\s*:\s*([0-9A-Fa-f:.-]+)")

# Model number
_MODEL_NUMBER_RE = re.compile(r"^Model [Nn]umber\s*:\s*(\S+)")

# Motherboard serial number
_MB_SERIAL_RE = re.compile(r"^Motherboard [Ss]erial [Nn]umber\s*:\s*(\S+)")

# Configuration register
_CONFIG_REG_RE = re.compile(
    r"^Configuration register is\s+(\S+)"
    r"(?:\s+\(will be\s+(\S+)\s+at next reload\))?\s*$"
)

# Switch stack table row
_SWITCH_STACK_RE = re.compile(
    r"^(\*?)\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)"
    r"(?:\s+(\S+))?\s*$"
)


# --- Interface name normalization map ---
_INTERFACE_TYPE_MAP = {
    "virtual ethernet": "virtual_ethernet",
    "virtual ethernet/ieee 802.3": "virtual_ethernet",
    "fastethernet": "fast_ethernet",
    "fast ethernet": "fast_ethernet",
    "gigabit ethernet": "gigabit_ethernet",
    "gigabit ethernet/ieee 802.3": "gigabit_ethernet",
    "ten gigabit ethernet": "ten_gigabit_ethernet",
    "twentyfive gigabit ethernet": "twentyfive_gigabit_ethernet",
    "forty gigabit ethernet": "forty_gigabit_ethernet",
    "hundred gigabit ethernet": "hundred_gigabit_ethernet",
    "serial": "serial",
    "terminal": "terminal",
}


def _normalize_interface_type(raw_type: str) -> str:
    """Normalize interface type string to a snake_case key."""
    normalized = raw_type.lower().strip()
    if normalized in _INTERFACE_TYPE_MAP:
        return _INTERFACE_TYPE_MAP[normalized]
    # Fallback: replace spaces with underscores
    return normalized.replace(" ", "_")


def _parse_version_and_image(lines: list[str], result: dict) -> None:
    """Extract version string and image type from the first few lines."""
    for line in lines:
        if "Version" in line and "version" not in result:
            m = _VERSION_RE.search(line)
            if m:
                result["version"] = m.group(1).rstrip(",")

        if "image_type" not in result:
            m = _IMAGE_TYPE_RE.search(line)
            if m:
                result["image_type"] = m.group(1)

        m = _COMPILED_RE.match(line)
        if m:
            result["compiled"] = m.group(1).strip()
            break


def _parse_rom_bootldr(line: str, result: dict) -> bool:
    """Parse ROM and BOOTLDR lines. Returns True if matched."""
    m = _ROM_RE.match(line)
    if m:
        result["rom_version"] = m.group(1)
        return True

    m = _BOOTLDR_RE.match(line)
    if m:
        result["bootldr_version"] = m.group(1)
        return True

    return False


def _parse_uptime_and_identity(line: str, result: dict) -> bool:
    """Parse uptime line to extract hostname and uptime. Returns True if matched."""
    m = _UPTIME_RE.match(line)
    if m:
        result["hostname"] = m.group(1)
        result["uptime"] = m.group(2)
        return True
    return False


def _parse_system_info(line: str, result: dict) -> bool:
    """Parse system image, reload, restart lines. Returns True if matched."""
    m = _IMAGE_FILE_RE.match(line)
    if m:
        result["system_image"] = m.group(1)
        return True

    m = _RELOAD_REASON_RE.match(line)
    if m:
        result["last_reload_reason"] = m.group(1)
        return True

    m = _RETURNED_TO_ROM_RE.match(line)
    if m:
        result["system_returned_to_rom_by"] = m.group(1)
        return True

    m = _RESTARTED_RE.match(line)
    if m:
        result["restarted_at"] = m.group(1)
        return True

    return False


def _parse_processor(line: str, result: dict) -> bool:
    """Parse processor/hardware line. Returns True if matched."""
    m = _PROCESSOR_RE.match(line)
    if not m:
        m = _PROCESSOR_ALT_RE.match(line)
    if m:
        result["platform"] = m.group(1)
        main_kb = int(m.group(2))
        result["memory"] = {"total_bytes": main_kb * BYTES_PER_KB}
        if m.group(3):
            io_kb = int(m.group(3))
            result["memory"]["io_bytes"] = io_kb * BYTES_PER_KB
        return True
    return False


def _parse_interfaces(line: str, result: dict) -> bool:
    """Parse interface count lines. Returns True if matched."""
    m = _INTERFACE_RE.match(line)
    if m:
        count = int(m.group(1))
        iface_type = _normalize_interface_type(m.group(2))
        if "interfaces" not in result:
            result["interfaces"] = {}
        result["interfaces"][iface_type] = count
        return True
    return False


def _parse_license_fields(line: str, result: dict) -> bool:
    """Parse license-related lines. Returns True if matched."""
    m = _LICENSE_LEVEL_RE.match(line)
    if m:
        if "license" not in result:
            result["license"] = {}
        result["license"]["level"] = m.group(1)
        return True

    m = _LICENSE_TYPE_RE.match(line)
    if m:
        if "license" not in result:
            result["license"] = {}
        result["license"]["type"] = m.group(1)
        return True

    m = _LICENSE_NEXT_RE.match(line)
    if m:
        if "license" not in result:
            result["license"] = {}
        result["license"]["next_reload_level"] = m.group(1)
        return True

    m = _TECH_PKG_RE.match(line)
    if m:
        if "license" not in result:
            result["license"] = {}
        result["license"]["level"] = m.group(1)
        result["license"]["type"] = m.group(2)
        result["license"]["next_reload_level"] = m.group(3)
        return True

    return False


def _parse_hardware_details(line: str, result: dict) -> bool:
    """Parse MAC, model number, motherboard serial. Returns True if matched."""
    m = _MAC_RE.match(line)
    if m:
        # Only capture the first MAC address (active switch in a stack)
        if "mac_address" not in result:
            result["mac_address"] = m.group(1)
        return True

    m = _MODEL_NUMBER_RE.match(line)
    if m:
        # Only capture the first Model number (switch 1 / active)
        if "model_number" not in result:
            result["model_number"] = m.group(1)
        return True

    m = _MB_SERIAL_RE.match(line)
    if m:
        if "motherboard_serial" not in result:
            result["motherboard_serial"] = m.group(1)
        return True

    return False


def _parse_config_register(line: str, result: dict) -> bool:
    """Parse configuration register line. Returns True if matched."""
    m = _CONFIG_REG_RE.match(line)
    if m:
        result["config_register"] = m.group(1)
        if m.group(2):
            result["config_register_next"] = m.group(2)
        return True
    return False


def _parse_switch_stack(lines: list[str], result: dict) -> None:
    """Parse switch stack table from output lines."""
    in_table = False
    for line in lines:
        stripped = line.strip()

        # Detect table header
        if stripped.startswith("Switch Ports Model"):
            in_table = True
            continue

        # Skip separator lines
        if in_table and stripped.startswith("------"):
            continue

        if in_table:
            m = _SWITCH_STACK_RE.match(stripped)
            if m:
                if "switch_stack" not in result:
                    result["switch_stack"] = []
                entry: SwitchStackEntry = {
                    "switch_number": int(m.group(2)),
                    "ports": int(m.group(3)),
                    "model": m.group(4),
                    "sw_version": m.group(5),
                    "sw_image": m.group(6),
                    "active": m.group(1) == "*",
                }
                if m.group(7):
                    entry["mode"] = m.group(7)
                result["switch_stack"].append(entry)
            else:
                in_table = False


def _parse_identity_line(stripped: str, result: dict) -> bool:
    """Parse core identity fields. Returns True if matched."""
    if _parse_rom_bootldr(stripped, result):
        return True
    if _parse_uptime_and_identity(stripped, result):
        return True
    if _parse_system_info(stripped, result):
        return True
    if _parse_processor(stripped, result):
        return True

    m = _SERIAL_RE.match(stripped)
    if m:
        result["serial_number"] = m.group(1)
        return True

    return False


def _parse_supplementary_line(stripped: str, result: dict) -> bool:
    """Parse supplementary fields. Returns True if matched."""
    if _parse_interfaces(stripped, result):
        return True

    m = _NVRAM_RE.match(stripped)
    if m:
        result["nvram_bytes"] = int(m.group(1)) * BYTES_PER_KB
        return True

    if _parse_license_fields(stripped, result):
        return True
    if _parse_hardware_details(stripped, result):
        return True
    if _parse_config_register(stripped, result):
        return True

    return False


def _parse_single_line(line: str, result: dict) -> None:
    """Try to parse a single line against all known patterns."""
    stripped = line.strip()
    if not stripped:
        return

    if _parse_identity_line(stripped, result):
        return
    _parse_supplementary_line(stripped, result)


@register(OS.CISCO_IOS, "show version")
@register(OS.CISCO_IOSXE, "show version")
class ShowVersionParser(BaseParser["ShowVersionResult"]):
    """Parser for 'show version' on IOS/IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INVENTORY,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowVersionResult:
        """Parse 'show version' output into structured data."""
        lines = output.splitlines()
        result: dict = {}

        _parse_version_and_image(lines, result)

        for line in lines:
            _parse_single_line(line, result)

        _parse_switch_stack(lines, result)

        return result  # type: ignore[return-value]
