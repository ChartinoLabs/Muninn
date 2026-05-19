"""Parser for 'dir' command on Cisco IOS."""

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

# IOS file entry. Filename may be present (single-line entry) or absent
# (wrapped onto the next line in narrow-terminal captures).
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
class DirParser(BaseParser[DirResult]):
    r"""Parser for 'dir' command output on Cisco IOS.

    Example output:
        Directory of flash:/

            2  -rwx         676   Jan 2 2006 00:03:28 +00:00  vlan.dat
            3  -rwx    24436736  Jun 30 2011 00:34:09 +00:00
        c3750e-universalk9-mz.152-2.E5.bin

        57671680 bytes total (7130112 bytes free)

    Narrow-terminal captures may wrap a long filename onto the following
    line; the parser treats a non-matching line that follows a file-entry
    line with no inline filename as the wrapped filename.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> DirResult:
        """Parse 'dir' output on Cisco IOS.

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
                # Filename wrapped onto the next line.
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
