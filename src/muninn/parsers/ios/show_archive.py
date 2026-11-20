"""Parser for 'show archive' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Marker indicating the most recent archive entry
_MOST_RECENT_MARKER = "<- Most Recent"


class ArchiveEntry(TypedDict):
    """Schema for a single archive entry."""

    number: int
    filename: str
    most_recent: NotRequired[bool]


class ShowArchiveResult(TypedDict):
    """Schema for 'show archive' parsed output."""

    max_archive_count: NotRequired[int]
    current_count: NotRequired[int]
    next_filename: NotRequired[str]
    entries: dict[str, ArchiveEntry]


# Regex patterns
_MAX_ARCHIVE_RE = re.compile(r"^The maximum archive configurations allowed is (\d+)\.$")
_CURRENT_COUNT_RE = re.compile(
    r"^There are currently (\d+) archive configurations saved\.$"
)
_NEXT_FILENAME_RE = re.compile(r"^The next archive file will be named (.+)$")
_ENTRY_RE = re.compile(r"^\s*(\d+)\s+(\S+.*\S)\s*$")
_NOT_ENABLED_RE = re.compile(r"^\s*Archive feature not enabled\s*$", re.IGNORECASE)


def _try_parse_header(stripped: str, result: ShowArchiveResult) -> bool:
    """Try to parse header lines (max count, current count, next filename).

    Returns True if the line was consumed.
    """
    m = _MAX_ARCHIVE_RE.match(stripped)
    if m:
        result["max_archive_count"] = int(m.group(1))
        return True

    m = _CURRENT_COUNT_RE.match(stripped)
    if m:
        result["current_count"] = int(m.group(1))
        return True

    m = _NEXT_FILENAME_RE.match(stripped)
    if m:
        result["next_filename"] = m.group(1).strip()
        return True

    return False


def _try_parse_entry(stripped: str, result: ShowArchiveResult) -> bool:
    """Try to parse an archive entry line.

    Returns True if the line was consumed.
    """
    is_most_recent = _MOST_RECENT_MARKER in stripped
    clean_line = stripped.replace(_MOST_RECENT_MARKER, "").strip()

    m = _ENTRY_RE.match(clean_line)
    if not m:
        return False

    number = int(m.group(1))
    entry: ArchiveEntry = {
        "number": number,
        "filename": m.group(2).strip(),
    }
    if is_most_recent:
        entry["most_recent"] = True
    result["entries"][str(number)] = entry
    return True


@register(OS.CISCO_IOS, "show archive")
class ShowArchiveParser(BaseParser[ShowArchiveResult]):
    """Parser for 'show archive' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowArchiveResult:
        """Parse 'show archive' output into structured data.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed archive configuration entries.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: ShowArchiveResult = {"entries": {}}
        found_content = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if _NOT_ENABLED_RE.match(stripped):
                return {"entries": {}}

            if stripped.startswith("Archive #"):
                found_content = True
                continue

            if _try_parse_header(stripped, result):
                found_content = True
                continue

            if _try_parse_entry(stripped, result):
                found_content = True
                continue

            # Lines with just a number (empty archive slots) are skipped

        if not found_content:
            msg = "No archive data found in output"
            raise ValueError(msg)

        return result
