"""Parser for 'show interface description' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class InterfaceDescriptionEntry(TypedDict):
    """Schema for a single interface description entry."""

    type: NotRequired[str]
    speed: NotRequired[str]
    description: NotRequired[str]


class ShowInterfaceDescriptionResult(TypedDict):
    """Schema for 'show interface description' parsed output."""

    interfaces: dict[str, InterfaceDescriptionEntry]


# Header for sections with Type and Speed columns (physical ports)
_PORT_HEADER_PATTERN = re.compile(r"^Port\s+Type\s+Speed\s+Description\s*$")

# Header for sections without Type and Speed columns (logical interfaces)
_INTERFACE_HEADER_PATTERN = re.compile(r"^Interface\s+Description\s*$")

# Line with Type and Speed columns: Eth4/1  eth  10G  some description
_PORT_LINE_PATTERN = re.compile(
    r"^(?P<port>\S+)\s+(?P<type>\S+)\s+(?P<speed>\S+)(?:\s+(?P<description>.+?))?\s*$"
)

# Line without Type and Speed columns: Lo0  some description
_INTERFACE_LINE_PATTERN = re.compile(r"^(?P<port>\S+)(?:\s+(?P<description>.+?))?\s*$")

_SEPARATOR_PATTERN = re.compile(r"^-{3,}\s*$")


@register(OS.CISCO_NXOS, "show interface description")
class ShowInterfaceDescriptionParser(BaseParser[ShowInterfaceDescriptionResult]):
    """Parser for 'show interface description' command on NX-OS.

    Parses interface descriptions from two section formats:
    - Physical ports with Type, Speed, and Description columns.
    - Logical interfaces with only Description column.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"interfaces"})

    @classmethod
    def _normalize_description(cls, value: str | None) -> str | None:
        """Normalize a description value, converting -- to None.

        Args:
            value: Raw description value from CLI output.

        Returns:
            Normalized value or None if --/empty.
        """
        if value is None:
            return None
        value = value.strip()
        if not value or value == "--":
            return None
        return value

    @classmethod
    def _parse_port_line(
        cls,
        line: str,
        interfaces: dict[str, InterfaceDescriptionEntry],
    ) -> None:
        """Parse a physical port line with Type, Speed, and Description.

        Args:
            line: Stripped line from CLI output.
            interfaces: Dict to populate with parsed entry.
        """
        match = _PORT_LINE_PATTERN.match(line)
        if not match:
            return

        port = canonical_interface_name(match.group("port"), os=OS.CISCO_NXOS)
        desc = cls._normalize_description(match.group("description"))

        entry: InterfaceDescriptionEntry = {
            "type": match.group("type"),
            "speed": match.group("speed"),
        }
        if desc:
            entry["description"] = desc

        interfaces[port] = entry

    @classmethod
    def _parse_interface_line(
        cls,
        line: str,
        interfaces: dict[str, InterfaceDescriptionEntry],
    ) -> None:
        """Parse a logical interface line with only Description.

        Args:
            line: Stripped line from CLI output.
            interfaces: Dict to populate with parsed entry.
        """
        match = _INTERFACE_LINE_PATTERN.match(line)
        if not match:
            return

        port = canonical_interface_name(match.group("port"), os=OS.CISCO_NXOS)
        desc = cls._normalize_description(match.group("description"))

        entry: InterfaceDescriptionEntry = {}
        if desc:
            entry["description"] = desc

        interfaces[port] = entry

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceDescriptionResult:
        """Parse 'show interface description' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface description data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, InterfaceDescriptionEntry] = {}
        in_port_section = False

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or _SEPARATOR_PATTERN.match(stripped):
                continue

            if _PORT_HEADER_PATTERN.match(stripped):
                in_port_section = True
                continue
            if _INTERFACE_HEADER_PATTERN.match(stripped):
                in_port_section = False
                continue

            if in_port_section:
                cls._parse_port_line(stripped, interfaces)
            else:
                cls._parse_interface_line(stripped, interfaces)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowInterfaceDescriptionResult(interfaces=interfaces)
