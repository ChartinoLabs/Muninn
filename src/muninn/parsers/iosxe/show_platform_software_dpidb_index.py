"""Parser for 'show platform software dpidb index' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class DpidbEntry(TypedDict):
    """Schema for a single DPIDB index entry."""

    index: int


class ShowPlatformSoftwareDpidbIndexResult(TypedDict):
    """Schema for 'show platform software dpidb index' parsed output.

    Keyed by canonical interface name.
    """

    interfaces: dict[str, DpidbEntry]


_ENTRY_PATTERN = re.compile(
    r"^Index\s+(?P<index>\d+)\s+--\s+swidb\s+(?P<interface>\S+)$"
)


@register(OS.CISCO_IOSXE, "show platform software dpidb index")
class ShowPlatformSoftwareDpidbIndexParser(
    BaseParser[ShowPlatformSoftwareDpidbIndexResult]
):
    """Parser for 'show platform software dpidb index' command.

    Example output::

        Index 1157 -- swidb Vl1
        Index 1028 -- swidb Gi0/0
        Index 1030 -- swidb Hu1/0/1
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.PLATFORM,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareDpidbIndexResult:
        """Parse 'show platform software dpidb index' output.

        Args:
            output: Raw CLI output from 'show platform software dpidb index'.

        Returns:
            Parsed DPIDB index data keyed by canonical interface name.

        Raises:
            ValueError: If no DPIDB index entries are found.
        """
        interfaces: dict[str, DpidbEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _ENTRY_PATTERN.match(line)
            if match:
                interface = canonical_interface_name(
                    match.group("interface"),
                    os=OS.CISCO_IOSXE,
                )
                interfaces[interface] = DpidbEntry(
                    index=int(match.group("index")),
                )

        if not interfaces:
            msg = "No DPIDB index entries found in output"
            raise ValueError(msg)

        return ShowPlatformSoftwareDpidbIndexResult(interfaces=interfaces)
