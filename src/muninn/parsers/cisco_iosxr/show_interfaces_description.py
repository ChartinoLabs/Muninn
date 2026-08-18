"""Parser for 'show interfaces description' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceDescriptionEntry(TypedDict):
    """Schema for a single interface entry in 'show interfaces description' output."""

    status: str
    protocol: str
    description: NotRequired[str]


class ShowInterfacesDescriptionResult(TypedDict):
    """Schema for 'show interfaces description' parsed output.

    Dict-of-dicts keyed by interface name.
    """

    interfaces: dict[str, InterfaceDescriptionEntry]


@register(OS.CISCO_IOSXR, "show interfaces description")
class ShowInterfacesDescriptionParser(BaseParser[ShowInterfacesDescriptionResult]):
    """Parser for 'show interfaces description' command on Cisco IOS-XR.

    Parses the tabular interface description output into a dict-of-dicts
    keyed by canonical interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Matches a data line in the interface description table.
    # Columns: Interface  Status  Protocol  Description (optional)
    # The description column may be absent when empty.
    _INTF_LINE = re.compile(
        r"^\s*(?P<name>\S+)"
        r"\s+(?P<status>up|down|admin-down|deleted)"
        r"\s+(?P<protocol>up|down|admin-down|deleted)"
        r"(?:\s+(?P<description>.+?))?"
        r"\s*$",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesDescriptionResult:
        """Parse 'show interfaces description' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface description information keyed by interface name.

        Raises:
            ValueError: If no interface entries can be parsed from the output.
        """
        interfaces: dict[str, InterfaceDescriptionEntry] = {}

        for line in output.splitlines():
            match = cls._INTF_LINE.match(line)
            if not match:
                continue

            name = canonical_interface_name(match.group("name"), os=OS.CISCO_IOSXR)
            entry = InterfaceDescriptionEntry(
                status=match.group("status"),
                protocol=match.group("protocol"),
            )
            description = match.group("description")
            if description:
                entry["description"] = description

            interfaces[name] = entry

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return cast(ShowInterfacesDescriptionResult, {"interfaces": interfaces})
