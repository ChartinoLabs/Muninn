"""Parser for 'show module online diag' command on IOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag


class OnlineDiagEntry(TypedDict):
    """Schema for a single module online diag entry."""

    status: str


class ShowModuleOnlineDiagResult(TypedDict):
    """Schema for 'show module online diag' parsed output."""

    modules: dict[str, OnlineDiagEntry]


_ROW_PATTERN = re.compile(r"^\s*(?P<mod>\d+)\s+(?P<status>\S+)\s*$")

_HEADER_PATTERN = re.compile(r"^\s*Mod\s+Online\s+Diag\s+Status", re.IGNORECASE)

_SEPARATOR = SEPARATOR_DASH_SPACE_RE


@register(OS.CISCO_IOS, "show module online diag")
class ShowModuleOnlineDiagParser(BaseParser[ShowModuleOnlineDiagResult]):
    """Parser for 'show module online diag' command.

    Example output:
        Mod  Online Diag Status
        ---- -------------------
        1  Pass
        2  Pass
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INVENTORY,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowModuleOnlineDiagResult:
        """Parse 'show module online diag' output.

        Args:
            output: Raw CLI output from 'show module online diag' command.

        Returns:
            Parsed data with module online diag status.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        modules: dict[str, OnlineDiagEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if (
                not stripped
                or _HEADER_PATTERN.match(stripped)
                or _SEPARATOR.match(stripped)
            ):
                continue

            match = _ROW_PATTERN.match(stripped)
            if match:
                mod = match.group("mod")
                modules[mod] = {"status": match.group("status")}

        if not modules:
            msg = "No module online diag entries found in output"
            raise ValueError(msg)

        return {"modules": modules}
