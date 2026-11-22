"""Parser for 'show configuration commit list' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class CommitEntry(TypedDict):
    """Schema for a single configuration commit entry."""

    sno: int
    user: str
    line: str
    client: str
    timestamp: str
    comment: NotRequired[str]


# Dict-of-dicts keyed by commit ID (Label/ID column).
ShowConfigurationCommitListResult = dict[str, CommitEntry]


@register(OS.CISCO_IOSXR, "show configuration commit list")
class ShowConfigurationCommitListParser(
    BaseParser[ShowConfigurationCommitListResult],
):
    """Parser for 'show configuration commit list' on Cisco IOS-XR.

    Parses the commit history table into a dict keyed by commit ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    # Header separator line of tildes
    _SEPARATOR = re.compile(r"^~{4,}")

    # Data line: sequence number, label/ID, user, line, client, timestamp
    # Columns are whitespace-separated; timestamp consumes the rest.
    _ENTRY = re.compile(
        r"^\s*(?P<sno>\d+)\s+"
        r"(?P<label_id>\d+)\s+"
        r"(?P<user>\S+)\s+"
        r"(?P<line>\S+)\s+"
        r"(?P<client>\S+)\s+"
        r"(?P<timestamp>.+?)\s*$",
    )

    # Comment line follows the entry with leading whitespace and no SNo
    _COMMENT = re.compile(r"^\s{2,}(?P<comment>\S.*)$")

    @classmethod
    def _extract_data_lines(cls, output: str) -> list[str]:
        """Return lines after the tilde separator header."""
        lines = output.splitlines()
        for idx, line in enumerate(lines):
            if cls._SEPARATOR.match(line):
                return lines[idx + 1 :]
        return []

    @classmethod
    def _build_entry(cls, match: re.Match[str]) -> CommitEntry:
        """Construct a CommitEntry from a regex match."""
        return CommitEntry(
            sno=int(match.group("sno")),
            user=match.group("user"),
            line=match.group("line"),
            client=match.group("client"),
            timestamp=match.group("timestamp"),
        )

    @classmethod
    def parse(cls, output: str) -> ShowConfigurationCommitListResult:
        """Parse 'show configuration commit list' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by commit ID with commit metadata.

        Raises:
            ValueError: If no commit entries are found.
        """
        result: ShowConfigurationCommitListResult = {}
        last_commit_id: str | None = None

        for line in cls._extract_data_lines(output):
            match = cls._ENTRY.match(line)
            if match:
                commit_id = match.group("label_id")
                result[commit_id] = cls._build_entry(match)
                last_commit_id = commit_id
                continue

            if last_commit_id is not None:
                comment_match = cls._COMMENT.match(line)
                if comment_match:
                    result[last_commit_id]["comment"] = comment_match.group(
                        "comment"
                    ).strip()

        if not result:
            msg = "No commit entries found in output"
            raise ValueError(msg)

        return result
