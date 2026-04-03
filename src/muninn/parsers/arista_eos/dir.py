"""Parser for 'dir' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FileEntry(TypedDict):
    """Schema for a single file or directory entry."""

    permissions: str
    size: int
    date: str
    type: str


class DirResult(TypedDict):
    """Schema for 'dir' parsed output on Arista EOS."""

    directory: str
    files: dict[str, FileEntry]
    total_bytes: int
    free_bytes: int


@register(OS.ARISTA_EOS, "dir")
class DirParser(BaseParser[DirResult]):
    """Parser for 'dir' command on Arista EOS.

    Parses directory listing including file entries with permissions,
    size, date, and name. Extracts total and free space from the
    summary line. Only the first directory section is parsed.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _DIRECTORY_HEADER = re.compile(r"^Directory of (?P<directory>\S+)")
    _FILE_ENTRY = re.compile(
        r"^\s+(?P<perms>[drwx-]+)\s+(?P<size>\d+)\s+"
        r"(?P<date>\S+\s+\S+\s+\S+)\s+(?P<name>\S+)$"
    )
    _SPACE_SUMMARY = re.compile(
        r"^(?P<total>\d+)\s+bytes total\s+\((?P<free>\d+)\s+bytes free\)"
    )

    @classmethod
    def _parse_file_entry(cls, line: str) -> tuple[str, FileEntry] | None:
        """Parse a single file entry line into a (name, entry) pair."""
        match = cls._FILE_ENTRY.match(line)
        if not match:
            return None
        perms = match.group("perms")
        file_type = "directory" if perms.startswith("d") else "file"
        return (
            match.group("name"),
            FileEntry(
                permissions=perms,
                size=int(match.group("size")),
                date=match.group("date"),
                type=file_type,
            ),
        )

    @classmethod
    def _parse_space_summary(cls, line: str) -> tuple[int, int] | None:
        """Parse the bytes total / bytes free summary line."""
        match = cls._SPACE_SUMMARY.match(line)
        if not match:
            return None
        return int(match.group("total")), int(match.group("free"))

    @classmethod
    def _validate(
        cls,
        directory: str | None,
        total_bytes: int | None,
        free_bytes: int | None,
    ) -> None:
        """Raise if required fields are missing."""
        if directory is None:
            msg = "No directory header found in output"
            raise ValueError(msg)
        if total_bytes is None or free_bytes is None:
            msg = "No space summary found in output"
            raise ValueError(msg)

    @classmethod
    def parse(cls, output: str) -> DirResult:
        """Parse 'dir' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed directory listing.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        directory: str | None = None
        files: dict[str, FileEntry] = {}
        total_bytes: int | None = None
        free_bytes: int | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := cls._DIRECTORY_HEADER.match(stripped):
                if directory is not None:
                    break  # Stop at second directory header (recursive output)
                directory = match.group("directory")
                continue

            if entry := cls._parse_file_entry(line):
                files[entry[0]] = entry[1]
                continue

            if space := cls._parse_space_summary(stripped):
                total_bytes, free_bytes = space

        cls._validate(directory, total_bytes, free_bytes)

        return cast(
            DirResult,
            {
                "directory": directory,
                "files": files,
                "total_bytes": total_bytes,
                "free_bytes": free_bytes,
            },
        )
