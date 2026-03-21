"""Parser for 'show gnxi state' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class GnxiStateRow(TypedDict):
    """One row from gnxi state table."""

    state: str
    status: str


class ShowGnxiStateResult(TypedDict):
    """Schema for 'show gnxi state' parsed output."""

    rows: dict[str, GnxiStateRow]


_ROW_RE = re.compile(r"^(?P<st>\S+)\s+(?P<s>\S+)\s*$")


def _parse_gnxi_row(line: str) -> GnxiStateRow | None:
    s = line.strip()
    if not s or s.lower().startswith("state"):
        return None
    if set(s) <= {"-"}:
        return None
    m = _ROW_RE.match(s)
    if not m:
        return None
    return GnxiStateRow(state=m.group("st"), status=m.group("s"))


@register(OS.CISCO_IOSXE, "show gnxi state")
class ShowGnxiStateParser(BaseParser[ShowGnxiStateResult]):
    """Parser for 'show gnxi state' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowGnxiStateResult:
        """Parse 'show gnxi state' output."""
        rows: dict[str, GnxiStateRow] = {}
        for line in output.splitlines():
            row = _parse_gnxi_row(line)
            if row:
                rows[row["state"]] = row
        if not rows:
            msg = "No gNXI state rows parsed"
            raise ValueError(msg)
        return cast(ShowGnxiStateResult, {"rows": rows})
