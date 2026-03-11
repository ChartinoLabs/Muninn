"""Parser for 'dir' and 'dir crashinfo:' commands on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class FileEntry(TypedDict):
    """Schema for a single file or directory entry."""

    permissions: str
    size: int
    date: str
    name: str
    inode: NotRequired[int]


class DirResult(TypedDict):
    """Schema for 'dir' parsed output."""

    directory: str
    files: dict[str, FileEntry]
    total_bytes: int
    free_bytes: int


_DIRECTORY_HEADER = re.compile(r"^Directory\s+of\s+(?P<directory>\S+)\s*$")

_FILE_ENTRY = re.compile(
    r"^\s*(?P<inode>\d+)\s+"
    r"(?P<permissions>[-drwx]+)\s+"
    r"(?P<size>\d+)\s+"
    r"(?P<date>\w+\s+\d+\s+\d{4}\s+\d+:\d+:\d+\s+[+-]?\d+:\d+)\s+"
    r"(?P<name>\S+)\s*$"
)

_SUMMARY = re.compile(
    r"^(?P<total>\d+)\s+bytes\s+total\s+"
    r"\((?P<free>\d+)\s+bytes\s+free\)\s*$"
)


def _build_file_entry(match: re.Match[str]) -> FileEntry:
    """Build a FileEntry from a regex match."""
    return FileEntry(
        permissions=match.group("permissions"),
        size=int(match.group("size")),
        date=match.group("date"),
        name=match.group("name"),
        inode=int(match.group("inode")),
    )


@register(OS.CISCO_IOSXE, "dir")
@register(OS.CISCO_IOSXE, "dir crashinfo:")
class DirParser(BaseParser[DirResult]):
    """Parser for 'dir' command.

    Example output:
        Directory of bootflash:/

           11  drwx            16384  Nov 25 2016 19:32:53 -07:00  lost+found
           12  -rw-                0  Dec 13 2016 11:36:36 -07:00  ds_stats.txt

        1940303872 bytes total (1036210176 bytes free)
    """

    @classmethod
    def parse(cls, output: str) -> DirResult:
        """Parse 'dir' output.

        Args:
            output: Raw CLI output from 'dir' command.

        Returns:
            Parsed directory listing data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        directory = _extract_directory(output)
        files = _extract_files(output)
        total_bytes, free_bytes = _extract_summary(output)

        return DirResult(
            directory=directory,
            files=files,
            total_bytes=total_bytes,
            free_bytes=free_bytes,
        )


def _extract_directory(output: str) -> str:
    """Extract the directory path from the header line."""
    for line in output.splitlines():
        match = _DIRECTORY_HEADER.match(line.strip())
        if match:
            return match.group("directory")
    msg = "No directory header found in output"
    raise ValueError(msg)


def _extract_files(output: str) -> dict[str, FileEntry]:
    """Extract all file entries from the output."""
    files: dict[str, FileEntry] = {}
    for line in output.splitlines():
        match = _FILE_ENTRY.match(line.strip())
        if match:
            entry = _build_file_entry(match)
            files[entry["name"]] = entry
    return files


def _extract_summary(output: str) -> tuple[int, int]:
    """Extract total and free bytes from the summary line."""
    for line in output.splitlines():
        match = _SUMMARY.match(line.strip())
        if match:
            return int(match.group("total")), int(match.group("free"))
    msg = "No summary line found in output"
    raise ValueError(msg)
