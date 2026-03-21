"""Parser for 'show netconf session' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowNetconfSessionResult(TypedDict):
    """Schema for 'show netconf session' parsed output."""

    open_sessions: int
    maximum_sessions: int


_LINE_PATTERN = re.compile(
    r"^Netconf Sessions:\s*(?P<open>\d+)\s+open,\s+maximum is\s+(?P<max>\d+)\s*$",
    re.IGNORECASE,
)


@register(OS.CISCO_IOSXE, "show netconf session")
class ShowNetconfSessionParser(BaseParser[ShowNetconfSessionResult]):
    """Parser for 'show netconf session' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowNetconfSessionResult:
        """Parse 'show netconf session' output.

        Args:
            output: Raw CLI output from 'show netconf session'.

        Returns:
            Open and maximum NETCONF session counts.

        Raises:
            ValueError: If the summary line is missing.
        """
        for raw in output.splitlines():
            line = raw.strip()
            match = _LINE_PATTERN.match(line)
            if match:
                return ShowNetconfSessionResult(
                    open_sessions=int(match.group("open")),
                    maximum_sessions=int(match.group("max")),
                )

        msg = "Netconf session summary line not found in output"
        raise ValueError(msg)
