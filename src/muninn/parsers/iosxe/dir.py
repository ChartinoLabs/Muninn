"""Parser for 'dir' commands on Cisco IOS and IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


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

# The filename capture is optional to support narrow-terminal IOS captures
# (e.g. Catalyst 3750-X) where long filenames wrap onto the following line.
# When the name is absent, the wrapped filename is stitched in below.
_FILE_ENTRY = re.compile(
    r"^\s*(?P<inode>\d+)\s+"
    r"(?P<permissions>[-drwx]+)\s+"
    r"(?P<size>\d+)\s+"
    r"(?P<date>\w+\s+\d+\s+\d{4}\s+\d+:\d+:\d+\s+[+-]?\d+:\d+)"
    r"(?:\s+(?P<name>\S+))?\s*$"
)

_SUMMARY = re.compile(
    r"^(?P<total>\d+)\s+bytes\s+total\s+"
    r"\((?P<free>\d+)\s+bytes\s+free\)\s*$"
)


def _build_file_entry(match: re.Match[str], name: str) -> FileEntry:
    """Build a FileEntry from a regex match and an explicit filename."""
    return FileEntry(
        permissions=match.group("permissions"),
        size=int(match.group("size")),
        date=match.group("date"),
        name=name,
        inode=int(match.group("inode")),
    )


@register(OS.CISCO_IOS, "dir")
@register(OS.CISCO_IOS, r"dir (?P<filesystem>\S+)")
@register(OS.CISCO_IOSXE, "dir")
@register(OS.CISCO_IOSXE, r"dir (?P<filesystem>\S+)")
class DirParser(BaseParser[DirResult]):
    """Parser for 'dir' command output on Cisco IOS and IOS-XE.

    Example output:
        Directory of bootflash:/

           11  drwx            16384  Nov 25 2016 19:32:53 -07:00  lost+found
           12  -rw-                0  Dec 13 2016 11:36:36 -07:00  ds_stats.txt

        1940303872 bytes total (1036210176 bytes free)

    On narrow-terminal IOS captures, a long filename may wrap onto the
    following line; such wrapped names are stitched back onto their entry.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> DirResult:
        """Parse 'dir' output.

        Args:
            output: Raw CLI output from 'dir' command.

        Returns:
            Parsed directory listing data.

        Raises:
            ValueError: If the directory header or summary is missing.
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
    """Extract all file entries, joining wrapped filenames where needed."""
    files: dict[str, FileEntry] = {}
    # `pending` holds the prior file-entry match when its inline filename was
    # absent. Narrow-terminal IOS captures wrap long filenames onto the next
    # line, so the following non-matching line is treated as the wrapped name.
    pending: re.Match[str] | None = None
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        match = _FILE_ENTRY.match(line)
        if match:
            name = match.group("name")
            if name is not None:
                pending = None
                files[name] = _build_file_entry(match, name)
            else:
                pending = match
            continue
        if pending is not None:
            wrapped_name = line.strip()
            if wrapped_name:
                files[wrapped_name] = _build_file_entry(pending, wrapped_name)
            pending = None
    return files


def _extract_summary(output: str) -> tuple[int, int]:
    """Extract total and free bytes from the summary line."""
    for line in output.splitlines():
        match = _SUMMARY.match(line.strip())
        if match:
            return int(match.group("total")), int(match.group("free"))
    msg = "No summary line found in output"
    raise ValueError(msg)
