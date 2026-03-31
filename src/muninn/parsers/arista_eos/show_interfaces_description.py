"""Parser for 'show interfaces description' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


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

    # Column-based parsing: the header defines fixed column positions.
    # Interface  Status  Protocol  Description
    # Fields are whitespace-separated, but "admin down" is a two-word status
    # and description can contain spaces. We parse positionally.
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<status>admin down|up|down)\s+"
        r"(?P<protocol>\S+)"
        r"(?:\s{2,}(?P<description>.+?))?\s*$"
    )

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

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or cls._HEADER_PATTERN.match(stripped):
                continue

            match = cls._INTERFACE_PATTERN.match(stripped)
            if not match:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.ARISTA_EOS
            )
            status = match.group("status")
            protocol = match.group("protocol")
            description = match.group("description")

            entry: InterfaceDescriptionEntry = {
                "status": status,
                "protocol": protocol,
            }

            if description and description.strip():
                entry["description"] = description.strip()

            interfaces[interface] = entry

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(ShowInterfacesDescriptionResult, {"interfaces": interfaces})
