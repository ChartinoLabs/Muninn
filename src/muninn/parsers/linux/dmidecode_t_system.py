"""Parser for 'dmidecode -t system' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Sentinels that mean "no value" in dmidecode output.
_NO_VALUE_SENTINELS = frozenset({"Not Specified", "Not Present", "Unknown", ""})


class SystemResetEntry(TypedDict):
    """Schema for the System Reset section."""

    status: str
    watchdog_timer: str
    boot_option: str
    boot_option_on_limit: str
    reset_count: NotRequired[str]
    reset_limit: NotRequired[str]
    timer_interval: NotRequired[str]
    timeout: NotRequired[str]


class SystemEventLogEntry(TypedDict):
    """Schema for the System Event Log section."""

    area_length: str
    header_start_offset: str
    header_length: str
    data_start_offset: str
    access_method: str
    access_address: str
    status: str
    change_token: str
    header_format: str


class SystemBootInfoEntry(TypedDict):
    """Schema for the System Boot Information section."""

    status: str


class DmidecodeSystemResult(TypedDict):
    """Schema for 'dmidecode -t system' parsed output."""

    manufacturer: NotRequired[str]
    product_name: NotRequired[str]
    version: NotRequired[str]
    serial_number: NotRequired[str]
    uuid: NotRequired[str]
    wake_up_type: NotRequired[str]
    sku_number: NotRequired[str]
    family: NotRequired[str]
    system_configuration_options: NotRequired[list[str]]
    system_event_log: NotRequired[SystemEventLogEntry]
    system_reset: NotRequired[SystemResetEntry]
    system_boot_info: NotRequired[SystemBootInfoEntry]


# Maps "Key Name" from dmidecode to our snake_case key names
_SYSTEM_INFO_KEYS: dict[str, str] = {
    "Manufacturer": "manufacturer",
    "Product Name": "product_name",
    "Version": "version",
    "Serial Number": "serial_number",
    "UUID": "uuid",
    "Wake-up Type": "wake_up_type",
    "SKU Number": "sku_number",
    "Family": "family",
}

_EVENT_LOG_KEYS: dict[str, str] = {
    "Area Length": "area_length",
    "Header Start Offset": "header_start_offset",
    "Header Length": "header_length",
    "Data Start Offset": "data_start_offset",
    "Access Method": "access_method",
    "Access Address": "access_address",
    "Status": "status",
    "Change Token": "change_token",
    "Header Format": "header_format",
}

_RESET_KEYS: dict[str, str] = {
    "Status": "status",
    "Watchdog Timer": "watchdog_timer",
    "Boot Option": "boot_option",
    "Boot Option On Limit": "boot_option_on_limit",
    "Reset Count": "reset_count",
    "Reset Limit": "reset_limit",
    "Timer Interval": "timer_interval",
    "Timeout": "timeout",
}

_BOOT_INFO_KEYS: dict[str, str] = {
    "Status": "status",
}

# Pattern for a key: value line inside a dmidecode section
_KV_PATTERN = re.compile(r"^\t(?P<key>[^:]+):\s*(?P<value>.*)$")

# Pattern for a section header (e.g., "System Information", "System Reset")
_SECTION_HEADER_PATTERN = re.compile(r"^(?P<section>[A-Z][\w\s]+)$")

# Pattern for config option lines (e.g., "Option 1: ...")
_OPTION_PATTERN = re.compile(r"^\tOption \d+:\s*(?P<value>.+)$")


def _is_sentinel(value: str) -> bool:
    """Return True if the value is a no-value placeholder."""
    return value.strip() in _NO_VALUE_SENTINELS


def _parse_system_info(lines: list[str]) -> dict[str, str]:
    """Extract key-value pairs from a System Information block."""
    result: dict[str, str] = {}
    for line in lines:
        match = _KV_PATTERN.match(line)
        if match:
            raw_key = match.group("key")
            value = match.group("value").strip()
            mapped = _SYSTEM_INFO_KEYS.get(raw_key)
            if mapped and not _is_sentinel(value):
                result[mapped] = value
    return result


def _parse_config_options(lines: list[str]) -> list[str]:
    """Extract option values from a System Configuration Options block."""
    options: list[str] = []
    for line in lines:
        match = _OPTION_PATTERN.match(line)
        if match:
            value = match.group("value").strip()
            if not _is_sentinel(value):
                options.append(value)
    return options


def _parse_kv_section(lines: list[str], key_map: dict[str, str]) -> dict[str, str]:
    """Extract key-value pairs from a section using a given key map."""
    result: dict[str, str] = {}
    for line in lines:
        match = _KV_PATTERN.match(line)
        if match:
            raw_key = match.group("key")
            value = match.group("value").strip()
            mapped = key_map.get(raw_key)
            if mapped and not _is_sentinel(value):
                result[mapped] = value
    return result


def _is_skip_line(line: str) -> bool:
    """Return True for lines that are not section headers or body content."""
    return not line or line.startswith("Handle ") or line.startswith("#")


def _is_section_header(line: str) -> str | None:
    """Return section name if line is a section header, else None."""
    if line.startswith("\t"):
        return None
    header_match = _SECTION_HEADER_PATTERN.match(line)
    if header_match:
        return header_match.group("section").strip()
    return None


def _save_section(
    sections: dict[str, list[str]],
    name: str | None,
    lines: list[str],
) -> None:
    """Store a completed section into the sections dict."""
    if name is not None:
        sections[name] = lines


def _split_sections(output: str) -> dict[str, list[str]]:
    """Split dmidecode output into named sections with their body lines."""
    sections: dict[str, list[str]] = {}
    current_section: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        if _is_skip_line(line):
            if line == "":
                _save_section(sections, current_section, current_lines)
                current_section = None
                current_lines = []
            continue

        header = _is_section_header(line)
        if header is not None:
            _save_section(sections, current_section, current_lines)
            current_section = header
            current_lines = []
        elif current_section is not None:
            current_lines.append(line)

    _save_section(sections, current_section, current_lines)
    return sections


# Subsection name -> (result key, key map) for sections parsed as key-value.
_KV_SECTIONS: tuple[tuple[str, str, dict[str, str]], ...] = (
    ("System Event Log", "system_event_log", _EVENT_LOG_KEYS),
    ("System Reset", "system_reset", _RESET_KEYS),
    ("System Boot Information", "system_boot_info", _BOOT_INFO_KEYS),
)


def _build_result(sections: dict[str, list[str]]) -> dict[str, object]:
    """Build the result dict from parsed dmidecode sections."""
    result: dict[str, object] = {}

    if "System Information" in sections:
        result.update(_parse_system_info(sections["System Information"]))

    if "System Configuration Options" in sections:
        options = _parse_config_options(sections["System Configuration Options"])
        if options:
            result["system_configuration_options"] = options

    for section_name, result_key, key_map in _KV_SECTIONS:
        if section_name in sections:
            data = _parse_kv_section(sections[section_name], key_map)
            if data:
                result[result_key] = data

    return result


@register(OS.LINUX, "dmidecode -t system")
class DmidecodeSystemParser(BaseParser[DmidecodeSystemResult]):
    """Parser for 'dmidecode -t system' command on Linux.

    Parses system hardware information including manufacturer, product name,
    serial number, UUID, and related system configuration details.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    @classmethod
    def parse(cls, output: str) -> DmidecodeSystemResult:
        """Parse 'dmidecode -t system' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed system information dictionary.

        Raises:
            ValueError: If no system information can be parsed.
        """
        sections = _split_sections(output)

        if not sections:
            msg = "No system information sections found in output"
            raise ValueError(msg)

        result = _build_result(sections)

        if not result:
            msg = "No system information found in output"
            raise ValueError(msg)

        return DmidecodeSystemResult(**result)  # type: ignore[typeddict-item]
