"""Parser for 'show sdwan version' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowSdwanVersionResult(TypedDict):
    """Schema for 'show sdwan version' parsed output."""

    version: str


_VERSION_RE = re.compile(r"^[\d.]+\d$")


def _extract_version_line(lines: list[str]) -> str | None:
    for line in lines:
        s = line.strip()
        if not s or s.endswith("#"):
            continue
        if _VERSION_RE.match(s):
            return s
    return None


@register(OS.CISCO_IOSXE, "show sdwan version")
class ShowSdwanVersionParser(BaseParser[ShowSdwanVersionResult]):
    """Parser for 'show sdwan version' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SDWAN})

    @classmethod
    def parse(cls, output: str) -> ShowSdwanVersionResult:
        """Parse 'show sdwan version' output."""
        lines = output.splitlines()
        ver = _extract_version_line(lines)
        if not ver:
            msg = "SD-WAN version string not found"
            raise ValueError(msg)
        return cast(ShowSdwanVersionResult, {"version": ver})
