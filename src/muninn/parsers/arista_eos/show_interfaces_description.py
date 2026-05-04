"""Parser for 'show interfaces description' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_HEADER_COLUMNS = ("Interface", "Status", "Protocol", "Description")


class InterfaceDescriptionEntry(TypedDict):
    """Schema for a single interface description entry."""

    status: str
    protocol: str
    description: NotRequired[str]


class ShowInterfacesDescriptionResult(TypedDict):
    """Schema for 'show interfaces description' parsed output on Arista EOS."""

    interfaces: dict[str, InterfaceDescriptionEntry]


@register(OS.ARISTA_EOS, "show interfaces description")
class ShowInterfacesDescriptionParser(
    BaseParser[ShowInterfacesDescriptionResult],
):
    """Parser for 'show interfaces description' command on Arista EOS.

    Parses interface description table including status, protocol status,
    and optional description text. Output is keyed by canonical interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    _HEADER_PATTERN = re.compile(r"^Interface\s+Status\s+Protocol")

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesDescriptionResult:
        """Parse 'show interfaces description' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface description data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, InterfaceDescriptionEntry] = {}
        column_starts: list[int] | None = None

        for line in output.splitlines():
            if not line.strip():
                continue

            if column_starts is None:
                if cls._HEADER_PATTERN.match(line):
                    column_starts = [line.index(name) for name in _HEADER_COLUMNS]
                continue

            entry_data = cls._parse_row(line, column_starts)
            if entry_data is None:
                continue
            interface_name, entry = entry_data
            interfaces[interface_name] = entry

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(ShowInterfacesDescriptionResult, {"interfaces": interfaces})

    @staticmethod
    def _parse_row(
        line: str, column_starts: list[int]
    ) -> tuple[str, InterfaceDescriptionEntry] | None:
        """Slice a data row into fields using header-derived column positions."""
        interface_start, status_start, protocol_start, description_start = column_starts
        interface_raw = line[interface_start:status_start].strip()
        status = line[status_start:protocol_start].strip()
        protocol = line[protocol_start:description_start].strip()
        description = line[description_start:].strip()

        if not interface_raw or not status or not protocol:
            return None

        interface = canonical_interface_name(interface_raw, os=OS.ARISTA_EOS)
        entry: InterfaceDescriptionEntry = {
            "status": status,
            "protocol": protocol,
        }
        if description:
            entry["description"] = description
        return interface, entry
