"""Parser for 'show disk' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FilesystemEntry(TypedDict):
    """Schema for a single filesystem entry."""

    filesystem: str
    size: str
    used: str
    available: str
    use_pct: int
    mounted_on: str


ShowDiskResult = dict[str, FilesystemEntry]


@register(OS.CISCO_FTD, "show disk")
class ShowDiskParser(BaseParser[ShowDiskResult]):
    """Parser for 'show disk' command on Cisco FTD.

    Parses df-style disk usage output containing filesystem name,
    size, used space, available space, usage percentage, and mount
    point for each mounted filesystem.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _ENTRY_RE = re.compile(
        r"^(?P<filesystem>\S+)\s+"
        r"(?P<size>\S+)\s+"
        r"(?P<used>\S+)\s+"
        r"(?P<avail>\S+)\s+"
        r"(?P<pct>\d+)%\s+"
        r"(?P<mount>/.*)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowDiskResult:
        """Parse 'show disk' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dictionary keyed by mount point with filesystem details.

        Raises:
            ValueError: If no filesystem entries can be parsed.
        """
        result: ShowDiskResult = {}

        for line in output.splitlines():
            match = cls._ENTRY_RE.match(line)
            if not match:
                continue
            mount = match.group("mount")
            result[mount] = FilesystemEntry(
                filesystem=match.group("filesystem"),
                size=match.group("size"),
                used=match.group("used"),
                available=match.group("avail"),
                use_pct=int(match.group("pct")),
                mounted_on=mount,
            )

        if not result:
            msg = "No filesystem entries found in 'show disk' output"
            raise ValueError(msg)

        return result
