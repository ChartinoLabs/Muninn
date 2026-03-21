"""Parser for 'show sdwan security-info' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowSdwanSecurityInfoResult(TypedDict):
    """Schema for 'show sdwan security-info' parsed output."""

    settings: dict[str, str]


_LINE_RE = re.compile(r"^security-info\s+(\S+)\s+(.+?)\s*$")


def _parse_security_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    m = _LINE_RE.match(line)
    if not m:
        return None
    key = m.group(1)
    val = m.group(2).strip()
    if val.startswith('"') and val.endswith('"'):
        val = val[1:-1]
    return key, val


@register(OS.CISCO_IOSXE, "show sdwan security-info")
class ShowSdwanSecurityInfoParser(BaseParser[ShowSdwanSecurityInfoResult]):
    """Parser for 'show sdwan security-info' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SDWAN, ParserTag.SECURITY}
    )

    @classmethod
    def parse(cls, output: str) -> ShowSdwanSecurityInfoResult:
        """Parse 'show sdwan security-info' output."""
        settings: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            pair = _parse_security_line(line)
            if pair:
                settings[pair[0]] = pair[1]
        if not settings:
            msg = "No security-info lines parsed"
            raise ValueError(msg)
        return cast(ShowSdwanSecurityInfoResult, {"settings": settings})
