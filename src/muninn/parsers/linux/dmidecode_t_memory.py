"""Parser for 'dmidecode -t memory' command on Linux."""

import re
from typing import Any, ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Sentinel values that should be omitted from output rather than carried through.
_OMIT_VALUES = frozenset(
    {
        "Not Specified",
        "Not Provided",
        "Unknown",
        "No Module Installed",
        "Reserved",
        "None",
    }
)

# Pattern matching the Handle header line preceding each section
_SECTION_HEADER_RE = re.compile(r"^Handle\s+\S+,\s+DMI\s+type\s+\d+,\s+\d+\s+bytes$")

# Pattern matching a key-value pair line with leading tab
_KV_RE = re.compile(r"^\t(?P<key>[^:]+):\s+(?P<value>.+)$")

# Pattern to extract numeric value and unit (e.g. "1111 MB", "1111 MHz")
_NUMERIC_UNIT_RE = re.compile(r"^(?P<number>\d+)\s+\S+$")

# Pattern to extract size value and unit (e.g. "16 GB", "1111 MB", "512 kB")
_SIZE_RE = re.compile(r"^(?P<number>\d+)\s+(?P<unit>bytes|kB|MB|GB|TB)$")

# Multipliers to convert a dmidecode Size unit to MB.
_SIZE_UNIT_TO_MB: dict[str, float] = {
    "bytes": 1 / (1024 * 1024),
    "kB": 1 / 1024,
    "MB": 1,
    "GB": 1024,
    "TB": 1024 * 1024,
}

# Pattern for width fields (e.g. "10 bits")
_WIDTH_RE = re.compile(r"^(?P<width>\d+)\s+bits$")

# Simple string fields to copy directly from dmidecode key to output key
_DEVICE_STRING_FIELDS: tuple[tuple[str, str], ...] = (
    ("Array Handle", "array_handle"),
    ("Error Information Handle", "error_information_handle"),
    ("Form Factor", "form_factor"),
    ("Set", "set"),
    ("Bank Locator", "bank_locator"),
    ("Type", "type"),
    ("Type Detail", "type_detail"),
    ("Manufacturer", "manufacturer"),
    ("Serial Number", "serial_number"),
    ("Asset Tag", "asset_tag"),
    ("Part Number", "part_number"),
)


class PhysicalMemoryArray(TypedDict):
    """Schema for a Physical Memory Array section."""

    location: str
    use: str
    error_correction_type: NotRequired[str]
    maximum_capacity: str
    number_of_devices: int


class MemoryDevice(TypedDict):
    """Schema for a Memory Device section."""

    array_handle: NotRequired[str]
    error_information_handle: NotRequired[str]
    total_width_bits: NotRequired[int]
    data_width_bits: NotRequired[int]
    size_mb: NotRequired[int]
    form_factor: NotRequired[str]
    set: NotRequired[str]
    locator: str
    bank_locator: NotRequired[str]
    type: NotRequired[str]
    type_detail: NotRequired[str]
    speed_mhz: NotRequired[int]
    manufacturer: NotRequired[str]
    serial_number: NotRequired[str]
    asset_tag: NotRequired[str]
    part_number: NotRequired[str]
    rank: NotRequired[int]


class DmidecodeMemoryResult(TypedDict):
    """Schema for 'dmidecode -t memory' parsed output."""

    physical_memory_arrays: dict[str, PhysicalMemoryArray]
    memory_devices: dict[str, MemoryDevice]


def _parse_kv_pairs(lines: list[str]) -> dict[str, str]:
    """Parse indented key-value lines into a dict, omitting sentinels."""
    result: dict[str, str] = {}
    for line in lines:
        match = _KV_RE.match(line)
        if match:
            key = match.group("key").strip()
            value = match.group("value").strip()
            if value not in _OMIT_VALUES:
                result[key] = value
    return result


def _extract_width(raw: str) -> int | None:
    """Extract integer width from a string like '10 bits'."""
    match = _WIDTH_RE.match(raw)
    return int(match.group("width")) if match else None


def _extract_numeric(raw: str) -> int | None:
    """Extract integer from a string like '1111 MB' or '1111 MHz'."""
    match = _NUMERIC_UNIT_RE.match(raw)
    return int(match.group("number")) if match else None


def _extract_size_mb(raw: str) -> int | None:
    """Extract size in MB from a dmidecode Size value (e.g. '16 GB')."""
    match = _SIZE_RE.match(raw)
    if not match:
        return None
    number = int(match.group("number"))
    unit = match.group("unit")
    return int(number * _SIZE_UNIT_TO_MB[unit])


def _split_sections(output: str) -> list[tuple[str, list[str]]]:
    """Split dmidecode output into (section_type, lines) pairs."""
    sections: list[tuple[str, list[str]]] = []
    current_type: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        if _SECTION_HEADER_RE.match(line):
            if current_type is not None:
                sections.append((current_type, current_lines))
            current_type = None
            current_lines = []
        elif current_type is None and line and not line.startswith("\t"):
            current_type = line.strip()
            current_lines = []
        elif current_type is not None:
            current_lines.append(line)

    if current_type is not None:
        sections.append((current_type, current_lines))

    return sections


def _build_physical_memory_array(kv: dict[str, str]) -> PhysicalMemoryArray:
    """Build a PhysicalMemoryArray from parsed key-value pairs."""
    array: PhysicalMemoryArray = {
        "location": kv["Location"],
        "use": kv["Use"],
        "maximum_capacity": kv["Maximum Capacity"],
        "number_of_devices": int(kv["Number Of Devices"]),
    }
    if "Error Correction Type" in kv:
        array["error_correction_type"] = kv["Error Correction Type"]
    return array


def _build_memory_device(kv: dict[str, str]) -> MemoryDevice:
    """Build a MemoryDevice from parsed key-value pairs."""
    device: dict[str, Any] = {"locator": kv["Locator"]}

    for dmi_key, output_key in _DEVICE_STRING_FIELDS:
        if dmi_key in kv:
            device[output_key] = kv[dmi_key]

    _set_width_fields(kv, device)
    _set_numeric_fields(kv, device)

    return cast(MemoryDevice, device)


def _set_width_fields(kv: dict[str, str], device: dict[str, Any]) -> None:
    """Set total_width_bits and data_width_bits on device if present."""
    for dmi_key, output_key in (
        ("Total Width", "total_width_bits"),
        ("Data Width", "data_width_bits"),
    ):
        if dmi_key in kv:
            width = _extract_width(kv[dmi_key])
            if width is not None:
                device[output_key] = width


def _set_numeric_fields(kv: dict[str, str], device: dict[str, Any]) -> None:
    """Set size_mb, speed_mhz, and rank on device if present."""
    if "Size" in kv:
        size = _extract_size_mb(kv["Size"])
        if size is not None:
            device["size_mb"] = size

    if "Speed" in kv:
        speed = _extract_numeric(kv["Speed"])
        if speed is not None:
            device["speed_mhz"] = speed

    if "Rank" in kv:
        device["rank"] = int(kv["Rank"])


@register(OS.LINUX, "dmidecode -t memory")
class DmidecodeMemoryParser(BaseParser[DmidecodeMemoryResult]):
    """Parser for 'dmidecode -t memory' command on Linux.

    Parses Physical Memory Array and Memory Device sections from
    dmidecode output, providing structured memory inventory data.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    @classmethod
    def parse(cls, output: str) -> DmidecodeMemoryResult:
        """Parse 'dmidecode -t memory' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict with physical_memory_arrays and memory_devices
            dicts keyed by location and locator respectively.

        Raises:
            ValueError: If no memory sections found in output.
        """
        arrays: dict[str, PhysicalMemoryArray] = {}
        devices: dict[str, MemoryDevice] = {}

        for section_type, lines in _split_sections(output):
            kv = _parse_kv_pairs(lines)
            if section_type == "Physical Memory Array":
                array = _build_physical_memory_array(kv)
                arrays[array["location"]] = array
            elif section_type == "Memory Device":
                device = _build_memory_device(kv)
                devices[device["locator"]] = device

        if not arrays and not devices:
            msg = "No memory information found in output"
            raise ValueError(msg)

        return DmidecodeMemoryResult(
            physical_memory_arrays=arrays,
            memory_devices=devices,
        )
