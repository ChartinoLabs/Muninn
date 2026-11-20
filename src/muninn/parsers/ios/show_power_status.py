"""Parser for 'show power status' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply entry."""

    status: str
    model: NotRequired[str]
    type: NotRequired[str]
    fan_sensor: NotRequired[str]
    inline_status: NotRequired[str]


class ShowPowerStatusResult(TypedDict):
    """Schema for 'show power status' parsed output."""

    supplies: dict[str, PowerSupplyEntry]


# Main power supply line with model, type, status, and optional fan/inline columns.
# Example: "PS1     PWR-C45-4200ACV   AC 4200W   good         good     good"
_MAIN_PS_RE = re.compile(
    r"^(?P<name>PS\d+)\s+"
    r"(?P<model>\S+)\s+"
    r"(?P<type>\S+(?:\s+\S+)?)\s{2,}"
    r"(?P<status>\S+)"
    r"(?:\s+(?P<fan>\S+))?"
    r"(?:\s+(?P<inline>\S+))?\s*$"
)

# Sub-supply line with optional voltage and status.
# Example: "PS1-1                         220V   good"
_SUB_PS_RE = re.compile(
    r"^(?P<name>PS\d+-\d+)\s+"
    r"(?:(?P<type>\d+V)\s+)?"
    r"(?P<status>\S+)\s*$"
)

# Lines to skip: headers, separators, blank, footer messages
_HEADER_RE = re.compile(r"^\s*(?:Power|Supply|------)", re.IGNORECASE)
_FOOTER_RE = re.compile(r"^\s*\*{3}")


def _is_skip_line(line: str) -> bool:
    """Return True if the line is a header, separator, blank, or footer."""
    stripped = line.strip()
    if not stripped:
        return True
    if _HEADER_RE.match(stripped):
        return True
    return bool(_FOOTER_RE.match(stripped))


def _normalize_sentinel(value: str | None) -> str | None:
    """Return None if value is a sentinel or empty, otherwise return it."""
    if value is None:
        return None
    value = value.strip()
    if not value or value in ("--", "N/A", "n.a."):
        return None
    return value


def _parse_main_line(match: re.Match[str]) -> tuple[str, PowerSupplyEntry]:
    """Build entry from a main power supply regex match."""
    name = match.group("name")
    entry: PowerSupplyEntry = {"status": match.group("status").lower()}

    model = _normalize_sentinel(match.group("model"))
    if model is not None:
        entry["model"] = model

    ps_type = _normalize_sentinel(match.group("type"))
    if ps_type is not None:
        entry["type"] = ps_type

    fan = _normalize_sentinel(match.group("fan"))
    if fan is not None:
        entry["fan_sensor"] = fan.lower()

    inline = _normalize_sentinel(match.group("inline"))
    if inline is not None:
        entry["inline_status"] = inline.lower()

    return name, entry


def _parse_sub_line(match: re.Match[str]) -> tuple[str, PowerSupplyEntry]:
    """Build entry from a sub-supply regex match."""
    name = match.group("name")
    entry: PowerSupplyEntry = {"status": match.group("status").lower()}

    ps_type = _normalize_sentinel(match.group("type"))
    if ps_type is not None:
        entry["type"] = ps_type

    return name, entry


@register(OS.CISCO_IOS, "show power status")
class ShowPowerStatusParser(BaseParser[ShowPowerStatusResult]):
    """Parser for 'show power status' command.

    Example output:
        PS1     PWR-C45-4200ACV   AC 4200W   good         good     good
        PS1-1                         220V   good
        PS2     PWR-C4KX-750AC-R  AC 750W    good         good     n.a.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ENVIRONMENT,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowPowerStatusResult:
        """Parse 'show power status' output.

        Args:
            output: Raw CLI output from 'show power status' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        supplies: dict[str, PowerSupplyEntry] = {}

        for line in output.splitlines():
            if _is_skip_line(line):
                continue

            match = _MAIN_PS_RE.match(line.strip())
            if match:
                name, entry = _parse_main_line(match)
                supplies[name] = entry
                continue

            match = _SUB_PS_RE.match(line.strip())
            if match:
                name, entry = _parse_sub_line(match)
                supplies[name] = entry
                continue

        if not supplies:
            msg = "No power supply entries found in output"
            raise ValueError(msg)

        return {"supplies": supplies}
