"""Parser for 'dmidecode -t processor' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Values that indicate "no data" in dmidecode output — omit these keys.
_SKIP_VALUES = frozenset(
    {
        "Not Specified",
        "Unknown",
        "Not Provided",
    }
)


class ProcessorEntry(TypedDict):
    """Schema for a single processor socket."""

    type: NotRequired[str]
    family: NotRequired[str]
    manufacturer: NotRequired[str]
    id: NotRequired[str]
    signature: NotRequired[str]
    version: NotRequired[str]
    voltage: NotRequired[str]
    external_clock: NotRequired[str]
    max_speed: NotRequired[str]
    current_speed: NotRequired[str]
    status: NotRequired[str]
    upgrade: NotRequired[str]
    l1_cache_handle: NotRequired[str]
    l2_cache_handle: NotRequired[str]
    l3_cache_handle: NotRequired[str]
    serial_number: NotRequired[str]
    asset_tag: NotRequired[str]
    part_number: NotRequired[str]
    core_count: NotRequired[int]
    core_enabled: NotRequired[int]
    thread_count: NotRequired[int]
    flags: NotRequired[list[str]]
    characteristics: NotRequired[list[str]]


DmidecodeProcessorResult = dict[str, ProcessorEntry]

# Matches the "Handle" line that starts each processor block.
_HANDLE_RE = re.compile(r"^Handle\s+0x[0-9A-Fa-f]+,\s+DMI type\s+4")

# Matches a simple "Key: Value" line (indented with a tab).
_KV_RE = re.compile(r"^\t(?P<key>[^\t:]+):\s*(?P<value>.+)$")

# Matches a list header line like "\tFlags:" or "\tCharacteristics:" (no value).
_LIST_HEADER_RE = re.compile(r"^\t(?P<key>[^\t:]+):\s*$")

# Matches an indented list item (double-tab).
_LIST_ITEM_RE = re.compile(r"^\t\t(?P<item>.+)$")

# Fields that should be converted to integers.
_INT_FIELDS = frozenset({"core_count", "core_enabled", "thread_count"})

# Mapping from dmidecode key labels to our schema field names.
_KEY_MAP: dict[str, str] = {
    "Socket Designation": "socket_designation",
    "Type": "type",
    "Family": "family",
    "Manufacturer": "manufacturer",
    "ID": "id",
    "Signature": "signature",
    "Version": "version",
    "Voltage": "voltage",
    "External Clock": "external_clock",
    "Max Speed": "max_speed",
    "Current Speed": "current_speed",
    "Status": "status",
    "Upgrade": "upgrade",
    "L1 Cache Handle": "l1_cache_handle",
    "L2 Cache Handle": "l2_cache_handle",
    "L3 Cache Handle": "l3_cache_handle",
    "Serial Number": "serial_number",
    "Asset Tag": "asset_tag",
    "Part Number": "part_number",
    "Core Count": "core_count",
    "Core Enabled": "core_enabled",
    "Thread Count": "thread_count",
}

# Keys whose subsequent double-tab lines are collected into a list.
_LIST_KEYS = frozenset({"Flags", "Characteristics"})


def _try_collect_list_item(
    line: str,
    current_list_field: str | None,
    entry: dict[str, object],
) -> bool:
    """Append a double-tab list item to the active list field.

    Returns True if the line matched a list item pattern.
    """
    if current_list_field is None:
        return False
    list_match = _LIST_ITEM_RE.match(line)
    if not list_match:
        return False
    item = list_match.group("item").strip()
    if item:
        if current_list_field not in entry:
            entry[current_list_field] = []
        cast(list[str], entry[current_list_field]).append(item)
    return True


def _try_list_header(line: str) -> str | None:
    """Return the lowercase list field name if line is a list header, else None."""
    list_header_match = _LIST_HEADER_RE.match(line)
    if not list_header_match:
        return None
    raw_key = list_header_match.group("key").strip()
    if raw_key in _LIST_KEYS:
        return raw_key.lower()
    return None


def _store_kv(raw_key: str, raw_value: str, entry: dict[str, object]) -> None:
    """Store a key-value pair into the entry dict, applying type coercion."""
    field_name = _KEY_MAP.get(raw_key)
    if field_name is None or raw_value in _SKIP_VALUES:
        return
    if field_name in _INT_FIELDS:
        try:
            entry[field_name] = int(raw_value)
        except ValueError:
            entry[field_name] = raw_value
    else:
        entry[field_name] = raw_value


def _parse_block(lines: list[str]) -> tuple[str | None, ProcessorEntry]:
    """Parse a single processor block into a socket key and entry dict."""
    entry: dict[str, object] = {}
    socket: str | None = None
    current_list_field: str | None = None

    for line in lines:
        if _try_collect_list_item(line, current_list_field, entry):
            continue

        # Not a list continuation — reset.
        current_list_field = None

        current_list_field = _try_list_header(line)
        if current_list_field is not None:
            continue

        kv_match = _KV_RE.match(line)
        if not kv_match:
            continue

        raw_key = kv_match.group("key").strip()
        raw_value = kv_match.group("value").strip()

        if raw_key == "Socket Designation":
            socket = raw_value
        elif raw_key in _LIST_KEYS:
            current_list_field = raw_key.lower()
        else:
            _store_kv(raw_key, raw_value, entry)

    return socket, ProcessorEntry(**entry)  # type: ignore[arg-type]


def _split_blocks(output: str) -> list[list[str]]:
    """Split dmidecode output into per-processor line blocks."""
    blocks: list[list[str]] = []
    current: list[str] = []
    in_block = False

    for line in output.splitlines():
        if _HANDLE_RE.match(line):
            if in_block and current:
                blocks.append(current)
            current = []
            in_block = True
            continue
        if in_block:
            current.append(line)

    if in_block and current:
        blocks.append(current)

    return blocks


def _build_result(blocks: list[list[str]]) -> dict[str, ProcessorEntry]:
    """Parse all blocks and assemble the result dict."""
    result: dict[str, ProcessorEntry] = {}
    for block in blocks:
        socket, entry = _parse_block(block)
        if socket is not None:
            result[socket] = entry
    return result


@register(OS.LINUX, "dmidecode -t processor")
class DmidecodeProcessorParser(BaseParser[DmidecodeProcessorResult]):
    """Parser for 'dmidecode -t processor' command on Linux.

    Parses processor information from SMBIOS/DMI data including
    socket designation, type, family, manufacturer, speed, and capabilities.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    @classmethod
    def parse(cls, output: str) -> DmidecodeProcessorResult:
        """Parse 'dmidecode -t processor' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict of processor entries keyed by socket designation.

        Raises:
            ValueError: If no processor information is found.
        """
        result = _build_result(_split_blocks(output))

        if not result:
            msg = "No processor information found in output"
            raise ValueError(msg)

        return result
