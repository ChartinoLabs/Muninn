"""Parser for 'show table-map' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MappingEntry(TypedDict):
    """Schema for a single from/to mapping within a table-map."""

    from_value: int
    to_value: int


class TableMapEntry(TypedDict):
    """Schema for a single table-map.

    Mappings are keyed by the 'from' value as a string.
    """

    default: NotRequired[str]
    mappings: NotRequired[dict[str, MappingEntry]]


class ShowTableMapResult(TypedDict):
    """Schema for 'show table-map' parsed output.

    Keyed by table-map name.
    """

    table_maps: dict[str, TableMapEntry]


# Table Map <name>
_TABLE_MAP_HEADER = re.compile(r"^\s*Table\s+Map\s+(?P<name>\S+)\s*$")

# from <value> to <value>
_MAPPING_PATTERN = re.compile(
    r"^\s*from\s+(?P<from_val>\d+)\s+to\s+(?P<to_val>\d+)\s*$"
)

# default <action>
_DEFAULT_PATTERN = re.compile(r"^\s*default\s+(?P<default>\S+)\s*$")


def _parse_mapping(line: str, entry: TableMapEntry) -> bool:
    """Try to parse a from/to mapping line. Returns True if matched."""
    match = _MAPPING_PATTERN.match(line)
    if not match:
        return False

    from_val = int(match.group("from_val"))
    to_val = int(match.group("to_val"))
    mapping = MappingEntry(from_value=from_val, to_value=to_val)

    if "mappings" not in entry:
        entry["mappings"] = {}
    entry["mappings"][str(from_val)] = mapping
    return True


def _parse_default(line: str, entry: TableMapEntry) -> bool:
    """Try to parse a default action line. Returns True if matched."""
    match = _DEFAULT_PATTERN.match(line)
    if not match:
        return False

    entry["default"] = match.group("default")
    return True


@register(OS.CISCO_IOSXE, "show table-map")
class ShowTableMapParser(BaseParser[ShowTableMapResult]):
    """Parser for 'show table-map' command.

    Parses QoS table-map configurations showing name, from/to value
    mappings, and default action.

    Example output:
        Table Map t1
        from 8 to 16
        from 16 to 32
        default copy
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.QOS})

    @classmethod
    def parse(cls, output: str) -> ShowTableMapResult:
        """Parse 'show table-map' output.

        Args:
            output: Raw CLI output from 'show table-map' command.

        Returns:
            Parsed table-map data keyed by table-map name.

        Raises:
            ValueError: If no table-map entries found in output.
        """
        table_maps: dict[str, TableMapEntry] = {}
        current_entry: TableMapEntry | None = None

        for line in output.splitlines():
            if not line.strip():
                continue

            header_match = _TABLE_MAP_HEADER.match(line)
            if header_match:
                name = header_match.group("name")
                current_entry = TableMapEntry()
                table_maps[name] = current_entry
                continue

            if current_entry is None:
                continue

            if _parse_mapping(line, current_entry):
                continue

            _parse_default(line, current_entry)

        if not table_maps:
            msg = "No table-map entries found in output"
            raise ValueError(msg)

        return ShowTableMapResult(table_maps=table_maps)
