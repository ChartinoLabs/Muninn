"""Parser for 'show file systems' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FileSystemEntry(TypedDict):
    """Schema for a single file system entry."""

    type: str
    flags: str
    is_default: bool
    size: NotRequired[int]
    free: NotRequired[int]


class ShowFileSystemsResult(TypedDict):
    """Schema for 'show file systems' parsed output.

    Keyed by file system prefix (e.g., "flash:", "nvram:").
    """

    file_systems: dict[str, FileSystemEntry]


_ROW_PATTERN = re.compile(
    r"^(?P<default>\*)?\s*"
    r"(?P<size>\d+|-)\s+"
    r"(?P<free>\d+|-)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<flags>r[wo])\s+"
    r"(?P<prefix>\S+)\s*$"
)


@register(OS.CISCO_IOSXE, "show file systems")
class ShowFileSystemsParser(BaseParser[ShowFileSystemsResult]):
    """Parser for 'show file systems' command.

    Example output:
           Size(b)       Free(b)      Type  Flags  Prefixes
        *  11353194496    9936510976      disk     rw   flash:
              2097152       2057602     nvram     rw   nvram:
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _ROW_PATTERN = _ROW_PATTERN

    @classmethod
    def parse(cls, output: str) -> ShowFileSystemsResult:
        """Parse 'show file systems' output.

        Args:
            output: Raw CLI output from 'show file systems' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        file_systems: dict[str, FileSystemEntry] = {}

        for line in output.splitlines():
            cleaned = line.strip()
            match = cls._ROW_PATTERN.match(cleaned)
            if not match:
                continue

            prefix = match.group("prefix")
            entry = FileSystemEntry(
                type=match.group("type"),
                flags=match.group("flags"),
                is_default=match.group("default") == "*",
            )

            size_str = match.group("size")
            free_str = match.group("free")
            if size_str != "-":
                entry["size"] = int(size_str)
            if free_str != "-":
                entry["free"] = int(free_str)

            file_systems[prefix] = entry

        if not file_systems:
            msg = "No file system entries found in output"
            raise ValueError(msg)

        return ShowFileSystemsResult(file_systems=file_systems)
