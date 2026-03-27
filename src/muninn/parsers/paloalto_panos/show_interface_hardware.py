"""Parser for 'show interface hardware' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypeAlias, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class InterfaceHardwareEntry(TypedDict):
    """Schema for a single hardware interface entry."""

    id: int
    speed: str
    duplex: str
    state: str
    mac_address: str


ShowInterfaceHardwareResult: TypeAlias = dict[str, InterfaceHardwareEntry]


@register(OS.PALOALTO_PANOS, "show interface hardware")
class ShowInterfaceHardwareParser(BaseParser[ShowInterfaceHardwareResult]):
    """Parser for 'show interface hardware' command on Palo Alto PAN-OS.

    Parses the tabular output listing physical and logical interfaces
    with their ID, speed, duplex, state, and MAC address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # Matches interface data lines, e.g.:
    #   ethernet1/1             16    1000/full/up              00:1b:17:00:01:10
    #   vlan                    1     [n/a]/[n/a]/up            00:1b:17:00:01:01
    # Speed and duplex may contain brackets (e.g. [n/a]) so we match
    # bracketed tokens or slash-free tokens before the final /state.
    _INTERFACE_LINE = re.compile(
        r"^(?P<name>\S+)\s+"
        r"(?P<id>\d+)\s+"
        r"(?P<speed>(?:\[[^\]]*\]|[^\s/]+))/(?P<duplex>(?:\[[^\]]*\]|[^\s/]+))/(?P<state>\S+)\s+"
        r"(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*$"
    )

    # Header separator line
    _SEPARATOR = re.compile(r"^-{10,}$")

    # Header line identifying the table columns
    _HEADER = re.compile(
        r"^name\s+id\s+speed/duplex/state\s+mac\s+address",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceHardwareResult:
        """Parse 'show interface hardware' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface hardware data keyed by interface name.

        Raises:
            ValueError: If no interfaces are found in output.
        """
        result: dict[str, InterfaceHardwareEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            is_skip = (
                not stripped
                or cls._SEPARATOR.match(stripped)
                or cls._HEADER.match(stripped)
            )
            if is_skip:
                continue

            match = cls._INTERFACE_LINE.match(stripped)
            if not match:
                continue

            name = match.group("name")
            entry: InterfaceHardwareEntry = {
                "id": int(match.group("id")),
                "speed": match.group("speed"),
                "duplex": match.group("duplex"),
                "state": match.group("state"),
                "mac_address": match.group("mac"),
            }
            result[name] = entry

        if not result:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(ShowInterfaceHardwareResult, result)
