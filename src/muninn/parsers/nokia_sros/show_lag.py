"""Parser for 'show lag' command on Nokia SR OS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LagEntry(TypedDict):
    """Schema for a single LAG entry."""

    admin_state: str
    oper_state: str
    weighted: str
    threshold: int
    up_count: int
    mc_act_stdby: str


# Top-level result is a dict keyed by LAG ID
ShowLagResult = dict[str, LagEntry]


@register(OS.NOKIA_SROS, "show lag")
class ShowLagParser(BaseParser[ShowLagResult]):
    """Parser for 'show lag' command on Nokia SR OS.

    Parses the tabular LAG summary output, returning a dict keyed
    by LAG ID with each value containing LAG attributes.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.LAG,
        }
    )

    # Separator lines used to delimit table sections
    _SEPARATOR = re.compile(r"^[=\-]{10,}$")

    # Header lines identifying column headers (used to skip)
    _HEADER = re.compile(r"^\s*Lag-id\s+Adm\s+Opr", re.I)

    # Section title line
    _SECTION_TITLE = re.compile(r"^\s*Lag Data\s*$", re.I)

    # Summary/total line at the bottom
    _TOTAL_LINE = re.compile(r"^\s*Total Lag-ids:", re.I)

    # LAG data row
    _LAG_ROW = re.compile(
        r"^(?P<lag_id>\d+)\s+"
        r"(?P<admin_state>up|down)\s+"
        r"(?P<oper_state>up|down)\s+"
        r"(?P<weighted>\S+)\s+"
        r"(?P<threshold>\d+)\s+"
        r"(?P<up_count>\d+)\s+"
        r"(?P<mc_act_stdby>\S+)\s*$",
        re.I,
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True for lines that are not data rows."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._SEPARATOR.match(stripped):
            return True
        if cls._HEADER.match(stripped):
            return True
        if cls._SECTION_TITLE.match(stripped):
            return True
        if cls._TOTAL_LINE.match(stripped):
            return True
        return False

    @classmethod
    def parse(cls, output: str) -> ShowLagResult:
        """Parse 'show lag' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by LAG ID, each value a LagEntry dict.

        Raises:
            ValueError: If no LAG entries can be parsed.
        """
        result: dict[str, LagEntry] = {}

        for line in output.splitlines():
            if cls._is_skip_line(line):
                continue

            match = cls._LAG_ROW.match(line.strip())
            if match is None:
                continue

            lag_id = match.group("lag_id")
            entry: LagEntry = {
                "admin_state": match.group("admin_state"),
                "oper_state": match.group("oper_state"),
                "weighted": match.group("weighted"),
                "threshold": int(match.group("threshold")),
                "up_count": int(match.group("up_count")),
                "mc_act_stdby": match.group("mc_act_stdby"),
            }
            result[lag_id] = entry

        if not result:
            msg = "No LAG entries found in output"
            raise ValueError(msg)

        return cast(ShowLagResult, result)
