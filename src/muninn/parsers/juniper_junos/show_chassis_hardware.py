"""Parser for 'show chassis hardware' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class HardwareItem(TypedDict):
    """Schema for a single hardware inventory item."""

    version: NotRequired[str]
    part_number: NotRequired[str]
    serial_number: NotRequired[str]
    description: NotRequired[str]
    children: NotRequired[dict[str, "HardwareItem"]]


ShowChassisHardwareResult = dict[str, HardwareItem]


@register(OS.JUNIPER_JUNOS, "show chassis hardware")
class ShowChassisHardwareParser(BaseParser[ShowChassisHardwareResult]):
    """Parser for 'show chassis hardware' command on Juniper Junos.

    Parses the hierarchical hardware inventory table into a nested
    dict-of-dicts structure reflecting the chassis component hierarchy.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    _HEADER_PATTERN = re.compile(
        r"^Item\s+Version\s+Part number\s+Serial number\s+Description\s*$"
    )

    _PREAMBLE_PATTERN = re.compile(r"^Hardware inventory:\s*$")

    # Number of spaces per indentation level in the output
    _INDENT_SPACES = 2

    # Sentinel values that should be treated as absent
    _BUILTIN_SENTINEL = "BUILTIN"
    _NON_JNPR_SENTINEL = "NON-JNPR"

    _SKIP_SENTINELS: ClassVar[frozenset[str]] = frozenset(
        {_BUILTIN_SENTINEL, _NON_JNPR_SENTINEL}
    )

    # Column positions (0-indexed) from the standard Junos header layout:
    # Item             Version  Part number  Serial number     Description
    _COL_VERSION = 17
    _COL_PART_NUMBER = 26
    _COL_SERIAL_NUMBER = 39
    _COL_DESCRIPTION = 57

    @classmethod
    def _extract_column(cls, line: str, start: int, end: int) -> str:
        """Extract and strip a fixed-width column value from a line."""
        if len(line) <= start:
            return ""
        segment = line[start:end] if len(line) >= end else line[start:]
        return segment.strip()

    @classmethod
    def _is_skippable(cls, line: str) -> bool:
        """Return True if the line is not a data row."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._HEADER_PATTERN.match(stripped):
            return True
        return bool(cls._PREAMBLE_PATTERN.match(stripped))

    @classmethod
    def _keep_field(cls, value: str) -> str | None:
        """Return the value if it is meaningful, or None for sentinels/blanks."""
        if not value or value in cls._SKIP_SENTINELS:
            return None
        return value

    @classmethod
    def _build_item(cls, line: str) -> HardwareItem:
        """Build a HardwareItem from the column values in a data line."""
        item: HardwareItem = {}

        if version := cls._keep_field(
            cls._extract_column(line, cls._COL_VERSION, cls._COL_PART_NUMBER)
        ):
            item["version"] = version

        if part_number := cls._keep_field(
            cls._extract_column(line, cls._COL_PART_NUMBER, cls._COL_SERIAL_NUMBER)
        ):
            item["part_number"] = part_number

        if serial_number := cls._keep_field(
            cls._extract_column(line, cls._COL_SERIAL_NUMBER, cls._COL_DESCRIPTION)
        ):
            item["serial_number"] = serial_number

        if description := cls._extract_column(line, cls._COL_DESCRIPTION, len(line)):
            item["description"] = description

        return item

    @classmethod
    def _parse_line(cls, line: str) -> tuple[int, str, HardwareItem] | None:
        """Parse a hardware item line using fixed column positions.

        Returns:
            Tuple of (indent_level, item_name, item_dict), or None if the
            line is not a data row (header, preamble, or blank).
        """
        if cls._is_skippable(line):
            return None

        name = line[: cls._COL_VERSION].strip()
        if not name:
            return None

        indent_chars = len(line) - len(line.lstrip(" "))
        indent_level = indent_chars // cls._INDENT_SPACES

        return indent_level, name, cls._build_item(line)

    @classmethod
    def parse(cls, output: str) -> ShowChassisHardwareResult:
        """Parse 'show chassis hardware' output into structured data.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Nested dict-of-dicts representing the hardware inventory hierarchy.

        Raises:
            ValueError: If no hardware items are found in the output.
        """
        result: ShowChassisHardwareResult = {}

        # Stack tracks (indent_level, children_dict) for building hierarchy.
        # Root sentinel at level -1 holds the top-level result dict.
        stack: list[tuple[int, dict[str, HardwareItem]]] = [(-1, result)]

        for line in output.splitlines():
            parsed = cls._parse_line(line)
            if parsed is None:
                continue

            indent_level, name, item = parsed

            # Pop back to the nearest ancestor at a shallower indent level
            while len(stack) > 1 and stack[-1][0] >= indent_level:
                stack.pop()

            parent_dict = stack[-1][1]
            parent_dict[name] = item

            # Push a lazy children dict so deeper items nest under this one
            stack.append((indent_level, item.setdefault("children", {})))

        # Remove empty children dicts from leaf nodes
        cls._prune_empty_children(result)

        if not result:
            msg = "No hardware items found in output"
            raise ValueError(msg)

        return result

    @classmethod
    def _prune_empty_children(cls, items: dict[str, HardwareItem]) -> None:
        """Recursively remove empty 'children' dicts from leaf items."""
        for item in items.values():
            if "children" in item:
                children = item["children"]
                if children:
                    cls._prune_empty_children(children)
                else:
                    del item["children"]
