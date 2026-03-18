"""Parser for 'show lacp system-identifier' command on NX-OS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowLacpSystemIdentifierResult(TypedDict):
    """Schema for 'show lacp system-identifier' parsed output."""

    system_id_mac: str
    system_priority: int


@register(OS.CISCO_NXOS, "show lacp system-identifier")
class ShowLacpSystemIdentifierParser(BaseParser[ShowLacpSystemIdentifierResult]):
    """Parser for 'show lacp system-identifier' command.

    Example output:
        32768,5e-2-0-1-0-7
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
            ParserTag.LAG,
        }
    )

    _PATTERN = re.compile(
        r"^\s*(?P<system_priority>\d+),\s*(?P<system_id_mac>[\w.\-]+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowLacpSystemIdentifierResult:
        """Parse 'show lacp system-identifier' output.

        Args:
            output: Raw CLI output from 'show lacp system-identifier' command.

        Returns:
            Parsed system identifier data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            if not line.strip():
                continue

            match = cls._PATTERN.match(line)
            if match:
                return ShowLacpSystemIdentifierResult(
                    system_id_mac=match.group("system_id_mac"),
                    system_priority=int(match.group("system_priority")),
                )

        msg = "No matching system identifier line found"
        raise ValueError(msg)
