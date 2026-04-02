"""Parser for 'show vlans' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowVlansEntry(TypedDict):
    """Schema for a single VLAN entry."""

    tag: int
    routing_instance: str
    description: NotRequired[str]
    interfaces: list[str]


# Dict keyed by VLAN name, each value is a ShowVlansEntry.
ShowVlansResult = dict[str, ShowVlansEntry]


@register(OS.JUNIPER_JUNOS, "show vlans")
class ShowVlansParser(BaseParser[ShowVlansResult]):
    """Parser for 'show vlans' command on Juniper Junos.

    Parses VLAN name, tag (ID), routing instance, and member interfaces
    from the tabular output of EX and QFX series switches.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VLAN})

    # First line of a VLAN block: routing-instance, VLAN name, tag
    _VLAN_HEADER = re.compile(r"^(?P<instance>\S+)\s+(?P<name>\S+)\s+(?P<tag>\d+)\s*$")

    # Continuation line with only an interface name
    _INTERFACE_LINE = re.compile(r"^\s+(?P<iface>\S+)\s*$")

    # Junos prompt lines like "{master:0}" or "{primary:node0}"
    _PROMPT = re.compile(r"^\{.+\}\s*$")

    @classmethod
    def _is_skippable(cls, stripped: str) -> bool:
        """Return True if the line should be skipped entirely."""
        if not stripped:
            return True
        if cls._PROMPT.match(stripped):
            return True
        return stripped.startswith("Routing instance")

    @classmethod
    def parse(cls, output: str) -> ShowVlansResult:
        """Parse 'show vlans' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by VLAN name with tag, routing instance,
            and interface membership.
        """
        result: ShowVlansResult = {}
        current_entry: ShowVlansEntry | None = None

        for line in output.splitlines():
            stripped = line.strip()

            if cls._is_skippable(stripped):
                continue

            header_match = cls._VLAN_HEADER.match(stripped)
            if header_match:
                entry = ShowVlansEntry(
                    tag=int(header_match.group("tag")),
                    routing_instance=header_match.group("instance"),
                    interfaces=[],
                )
                result[header_match.group("name")] = entry
                current_entry = entry
                continue

            iface_match = cls._INTERFACE_LINE.match(line)
            if iface_match and current_entry is not None:
                current_entry["interfaces"].append(iface_match.group("iface"))

        return result
