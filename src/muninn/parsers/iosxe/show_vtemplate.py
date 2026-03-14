"""Parser for 'show vtemplate' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class VtemplateEntry(TypedDict):
    """Schema for a single virtual template entry."""

    type: str
    in_use: int
    protect: NotRequired[bool]


class ShowVtemplateResult(TypedDict):
    """Schema for 'show vtemplate' parsed output.

    Keyed by virtual template number (as string).
    """

    templates: dict[str, VtemplateEntry]


# Table row pattern:
# 1                 PPTP        0
# 2                 L2TP        3          Yes
_TABLE_ROW = re.compile(
    r"^(?P<number>\d+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<in_use>\d+)"
    r"(?:\s+(?P<protect>\S+))?\s*$"
)


def _parse_protect(value: str | None) -> bool | None:
    """Convert protect column value to boolean, or None if absent."""
    if value is None:
        return None
    return value.strip().lower() == "yes"


@register(OS.CISCO_IOSXE, "show vtemplate")
class ShowVtemplateParser(BaseParser[ShowVtemplateResult]):
    """Parser for 'show vtemplate' command.

    Example output::

        Virtual-Template  Type        In Use  Protect
        1                 PPTP        0
        2                 L2TP        3       Yes
    """

    @classmethod
    def parse(cls, output: str) -> ShowVtemplateResult:
        """Parse 'show vtemplate' output.

        Args:
            output: Raw CLI output from 'show vtemplate' command.

        Returns:
            Parsed virtual template data keyed by template number.

        Raises:
            ValueError: If no virtual template entries are found.
        """
        templates: dict[str, VtemplateEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _TABLE_ROW.match(line)
            if not match:
                continue

            number = match.group("number")
            entry = VtemplateEntry(
                type=match.group("type"),
                in_use=int(match.group("in_use")),
            )

            protect = _parse_protect(match.group("protect"))
            if protect is not None:
                entry["protect"] = protect

            templates[number] = entry

        if not templates:
            msg = "No virtual template entries found in output"
            raise ValueError(msg)

        return ShowVtemplateResult(templates=templates)
