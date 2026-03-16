"""Parser for 'show vtp password' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class VtpStatus(TypedDict):
    """Schema for VTP password status."""

    configured: bool
    password: NotRequired[str]


class ShowVtpPasswordResult(TypedDict):
    """Schema for 'show vtp password' parsed output."""

    vtp: VtpStatus


@register(OS.CISCO_IOS, "show vtp password")
class ShowVtpPasswordParser(BaseParser[ShowVtpPasswordResult]):
    """Parser for 'show vtp password' command."""

    tags: ClassVar[frozenset[str]] = frozenset({"switching", "vtp"})

    _NOT_CONFIGURED_PATTERN = re.compile(
        r"^The\s+VTP\s+password\s+is\s+not\s+configured\.$", re.I
    )
    _PASSWORD_PATTERN = re.compile(r"^VTP\s+Password:\s*(?P<password>\S+)$", re.I)

    @classmethod
    def parse(cls, output: str) -> ShowVtpPasswordResult:
        """Parse 'show vtp password' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed VTP password status.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if cls._NOT_CONFIGURED_PATTERN.match(line):
                return ShowVtpPasswordResult(vtp={"configured": False})

            match = cls._PASSWORD_PATTERN.match(line)
            if match:
                return ShowVtpPasswordResult(
                    vtp={
                        "configured": True,
                        "password": match.group("password"),
                    }
                )

        msg = "No VTP password status found"
        raise ValueError(msg)
