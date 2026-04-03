"""Parser for 'dir' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FileEntry(TypedDict):
    """Schema for a single file or directory entry."""

    permissions: str
    links: int
    size: int
    date: str
    name: str
    inode: NotRequired[int]
    owner: NotRequired[str]
    group: NotRequired[str]


class DirResult(TypedDict):
    """Schema for 'dir' parsed output."""

    directory: str
    files: dict[str, FileEntry]
    total_kbytes: int
    free_kbytes: int


_DIRECTORY_HEADER = re.compile(r"^Directory\s+of\s+(?P<directory>\S+)\s*$")

# IOS-XR dir entry format:
#   74 drwxrwxrwx. 2  4096 Dec  6 19:39 resmon_debug
#   38 -rw-------. 1   444 Nov 15  2023 .bash_history
#   15 lrwxrwxrwx. 1    12 Nov 15 14:58 config -> /misc/config
#
# Fields: inode, permissions (may end with .), links, [owner group], size,
#         month day time_or_year, name [-> target]
_FILE_ENTRY = re.compile(
    r"^\s*(?P<inode>\d+)\s+"
    r"(?P<permissions>[dlrwxsStT-]+\.?)\s+"
    r"(?P<links>\d+)\s+"
    r"(?:(?P<owner>\S+)\s+(?P<group>\S+)\s+)?"
    r"(?P<size>\d+)\s+"
    r"(?P<date>\w{3}\s+\d{1,2}\s+[\d:]+(?:\s+\d{4})?)\s+"
    r"(?P<name>\S+(?:\s+->\s+\S+)?)\s*$"
)

_SUMMARY = re.compile(
    r"^(?P<total>\d+)\s+kbytes\s+total\s+"
    r"\((?P<free>\d+)\s+kbytes\s+free\)\s*$"
)


def _build_file_entry(match: re.Match[str]) -> FileEntry:
    """Build a FileEntry from a regex match."""
    entry = FileEntry(
        permissions=match.group("permissions"),
        links=int(match.group("links")),
        size=int(match.group("size")),
        date=match.group("date"),
        name=match.group("name"),
        inode=int(match.group("inode")),
    )
    if match.group("owner"):
        entry["owner"] = match.group("owner")
    if match.group("group"):
        entry["group"] = match.group("group")
    return entry


@register(OS.CISCO_IOSXR, "dir")
@register(OS.CISCO_IOSXR, r"dir (?P<filesystem>\S+)")
class DirParser(BaseParser[DirResult]):
    """Parser for 'dir' command output on IOS-XR.

    Example output:
        Directory of /var/xr/scratch
        74 drwxrwxrwx. 2  4096 Dec  6 19:39 resmon_debug
        22 -rw-rw-rw-. 1  2464 Jan  7 19:34 status_file

        3365348 kbytes total (3163632 kbytes free)
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> DirResult:
        """Parse 'dir' output from IOS-XR.

        Args:
            output: Raw CLI output from 'dir' command.

        Returns:
            Parsed directory listing data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        directory = _extract_directory(output)
        files = _extract_files(output)
        total_kbytes, free_kbytes = _extract_summary(output)

        return DirResult(
            directory=directory,
            files=files,
            total_kbytes=total_kbytes,
            free_kbytes=free_kbytes,
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
        match = _FILE_ENTRY.match(line)
        if match:
            entry = _build_file_entry(match)
            files[entry["name"]] = entry
    return files


def _extract_summary(output: str) -> tuple[int, int]:
    """Extract total and free kbytes from the summary line."""
    for line in output.splitlines():
        match = _SUMMARY.match(line.strip())
        if match:
            return int(match.group("total")), int(match.group("free"))
    msg = "No summary line found in output"
    raise ValueError(msg)
