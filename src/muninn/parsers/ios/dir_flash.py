"""Parser for 'dir <filesystem>' commands on Cisco IOS."""

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
    """Schema for 'dir <filesystem>' parsed output."""

    directory: str
    files: dict[str, FileEntry]
    total_bytes: int
    free_bytes: int


_DIRECTORY_HEADER = re.compile(r"^Directory\s+of\s+(?P<directory>\S+)\s*$")

# Full file entry on a single line:
#     8  -rwx        7407  Mar 23 2007 07:32:54 +00:00  private-config.text
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
    """Build a FileEntry from a regex match and a resolved name."""
    return FileEntry(
        permissions=match.group("permissions"),
        size=int(match.group("size")),
        date=match.group("date"),
        name=name,
        inode=int(match.group("inode")),
    )


@register(OS.CISCO_IOS, r"dir (?P<filesystem>\S+)")
class DirFlashParser(BaseParser[DirResult]):
    """Parser for 'dir <filesystem>' command output on Cisco IOS.

    Handles any filesystem argument (e.g. ``dir flash:``, ``dir
    bootflash:``, ``dir slot0:``, ``dir nvram:``). The bare ``dir`` form
    is handled by ``DirParser`` in ``ios/dir.py``.

    Example output::

        Directory of flash:/

            2  -rwx         676   Jan 2 2006 00:03:28 +00:00  vlan.dat
            5  -rwx        7412   Feb 2 2024 20:30:38 +00:00  private-config.text

        57671680 bytes total (7130112 bytes free)

    Long filenames may wrap onto the following line; the parser stitches
    them back together.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> DirResult:
        """Parse 'dir <filesystem>' output.

        Args:
            output: Raw CLI output from a ``dir <filesystem>`` command.

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


def _is_wrapped_filename(line: str) -> bool:
    """Return True if the line looks like a wrapped filename continuation.

    A wrapped filename line has no leading inode/permissions/size; it is a
    single non-empty token that is not a summary line and not a directory
    header.
    """
    stripped = line.strip()
    if not stripped:
        return False
    if _SUMMARY.match(stripped):
        return False
    if _DIRECTORY_HEADER.match(stripped):
        return False
    if _FILE_ENTRY.match(line):
        return False
    # A wrapped name appears as a single whitespace-free token on its own
    # line. Anything with internal whitespace is not a filename continuation.
    return len(stripped.split()) == 1


def _extract_files(output: str) -> dict[str, FileEntry]:
    """Extract all file entries from the output, stitching wrapped names."""
    files: dict[str, FileEntry] = {}
    lines = output.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _FILE_ENTRY.match(line)
        if match:
            name = match.group("name")
            if name is None:
                # Filename wrapped to the next non-empty line.
                name = _consume_wrapped_name(lines, index + 1)
                if name is None:
                    index += 1
                    continue
            entry = _build_file_entry(match, name)
            files[entry["name"]] = entry
        index += 1
    return files


def _consume_wrapped_name(lines: list[str], start: int) -> str | None:
    """Return the wrapped filename starting at ``start``, or None."""
    for candidate in lines[start:]:
        if not candidate.strip():
            continue
        if _is_wrapped_filename(candidate):
            return candidate.strip()
        return None
    return None


def _extract_summary(output: str) -> tuple[int, int]:
    """Extract total and free bytes from the summary line."""
    for line in output.splitlines():
        match = _SUMMARY.match(line.strip())
        if match:
            return int(match.group("total")), int(match.group("free"))
    msg = "No summary line found in output"
    raise ValueError(msg)
