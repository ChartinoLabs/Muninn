"""Parser for 'show privilege' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowPrivilegeResult(TypedDict):
    """Schema for 'show privilege' parsed output."""

    current_privilege_level: int


@register(OS.CISCO_IOSXE, "show privilege")
class ShowPrivilegeParser(BaseParser[ShowPrivilegeResult]):
    """Parser for 'show privilege' command.

    Example output:
        Current privilege level is 15
    """

    tags: ClassVar[frozenset[str]] = frozenset({"aaa", "system"})

    _PATTERN = re.compile(r"^Current\s+privilege\s+level\s+is\s+(?P<level>\d+)$")

    @classmethod
    def parse(cls, output: str) -> ShowPrivilegeResult:
        """Parse 'show privilege' output.

        Args:
            output: Raw CLI output from 'show privilege' command.

        Returns:
            Parsed privilege level data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._PATTERN.match(line)
            if match:
                return ShowPrivilegeResult(
                    current_privilege_level=int(match.group("level")),
                )

        msg = "No matching privilege line found"
        raise ValueError(msg)
