"""Parser for 'dir' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class FileEntry(TypedDict):
    """Schema for a single file or directory entry."""

    size: int
    date: str
    is_directory: NotRequired[bool]


class UsageInfo(TypedDict):
    """Schema for filesystem usage information."""

    bytes_used: int
    bytes_free: int
    bytes_total: int


class DirResult(TypedDict):
    """Schema for 'dir' parsed output."""

    files: dict[str, FileEntry]
    filesystem: NotRequired[str]
    usage: NotRequired[UsageInfo]


# Pattern for file/directory entries:
#   <size>    <month> <day> <time> <year>  <name>
_FILE_ENTRY = re.compile(
    r"^\s*(?P<size>\d+)\s+"
    r"(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+"
    r"(?P<name>\S+)\s*$",
)

# Usage line: "Usage for bootflash://"
_USAGE_HEADER = re.compile(
    r"^\s*Usage for\s+(?P<filesystem>\S+?)(?:/{0,2})\s*$",
)

# Space lines: "<number> bytes used/free/total"
_BYTES_USED = re.compile(r"^\s*(?P<value>\d+)\s+bytes\s+used\s*$")
_BYTES_FREE = re.compile(r"^\s*(?P<value>\d+)\s+bytes\s+free\s*$")
_BYTES_TOTAL = re.compile(r"^\s*(?P<value>\d+)\s+bytes\s+total\s*$")


def _parse_file_entry(line: str, files: dict[str, FileEntry]) -> bool:
    """Parse a file/directory entry line. Returns True if matched."""
    match = _FILE_ENTRY.match(line)
    if not match:
        return False
    name = match.group("name")
    entry: FileEntry = {
        "size": int(match.group("size")),
        "date": match.group("date"),
    }
    if name.endswith("/"):
        entry["is_directory"] = True
    files[name] = entry
    return True


def _parse_usage_line(
    line: str,
    usage: dict[str, int],
) -> str | None:
    """Parse a usage header or bytes line. Returns filesystem name if found."""
    if match := _USAGE_HEADER.match(line):
        return match.group("filesystem").rstrip(":/")

    if match := _BYTES_USED.match(line):
        usage["bytes_used"] = int(match.group("value"))
    elif match := _BYTES_FREE.match(line):
        usage["bytes_free"] = int(match.group("value"))
    elif match := _BYTES_TOTAL.match(line):
        usage["bytes_total"] = int(match.group("value"))

    return None


@register(OS.CISCO_NXOS, "dir")
class DirParser(BaseParser[DirResult]):
    """Parser for 'dir' command on NX-OS.

    Parses filesystem directory listings including file entries
    with sizes and dates, and optional usage summary.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"system"})

    @classmethod
    def parse(cls, output: str) -> DirResult:
        """Parse 'dir' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed directory listing.

        Raises:
            ValueError: If no file entries can be parsed.
        """
        files: dict[str, FileEntry] = {}
        filesystem: str | None = None
        usage: dict[str, int] = {}

        for line in output.splitlines():
            if _parse_file_entry(line, files):
                continue
            fs_name = _parse_usage_line(line, usage)
            if fs_name is not None:
                filesystem = fs_name

        if not files:
            msg = "No file entries found in output"
            raise ValueError(msg)

        result: DirResult = {"files": files}

        if filesystem:
            result["filesystem"] = filesystem

        if len(usage) == 3:
            result["usage"] = UsageInfo(
                bytes_used=usage["bytes_used"],
                bytes_free=usage["bytes_free"],
                bytes_total=usage["bytes_total"],
            )

        return result
