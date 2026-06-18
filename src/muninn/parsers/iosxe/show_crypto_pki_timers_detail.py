"""Parser for 'show crypto pki timers detail' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Section header, e.g. "PKI Timers" or "Trustpool Timers"
_SECTION_RE = re.compile(r"^(?P<section>\S.*Timers)\s*$")

# Top-level timer line: |<countdown>  (<absolute>)
# Sub-timer line:   |<countdown>  (<absolute>) <NAME>
_TIMER_RE = re.compile(
    r"^\s*\|\s*"
    r"(?P<countdown>\S+)"
    r"\s+\((?P<absolute>[^)]+)\)"
    r"(?:\s+(?P<name>\S.*))?$"
)


class TimerEntry(TypedDict):
    """A single timer entry."""

    countdown: str
    absolute: str


class SectionEntry(TypedDict):
    """A timer section (e.g. PKI Timers, Trustpool Timers)."""

    next_expiry: NotRequired[TimerEntry]
    timers: NotRequired[dict[str, TimerEntry]]


ShowCryptoPkiTimersDetailResult = dict[str, SectionEntry]


def _make_entry(match: re.Match[str]) -> TimerEntry:
    """Build a TimerEntry from a regex match."""
    return {
        "countdown": match.group("countdown"),
        "absolute": match.group("absolute"),
    }


def _parse_sections(
    lines: list[str],
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, TimerEntry]]]:
    """Walk lines and extract section data and named timers."""
    result: dict[str, dict[str, object]] = {}
    section_timers: dict[str, dict[str, TimerEntry]] = {}
    current_section: str | None = None
    seen_top_timer = False

    for line in lines:
        section_match = _SECTION_RE.match(line)
        if section_match:
            current_section = section_match.group("section")
            result[current_section] = {}
            section_timers[current_section] = {}
            seen_top_timer = False
            continue

        if current_section is None:
            continue

        timer_match = _TIMER_RE.match(line)
        if not timer_match:
            continue

        name = timer_match.group("name")
        if not seen_top_timer and name is None:
            result[current_section]["next_expiry"] = _make_entry(timer_match)
            seen_top_timer = True
        elif name:
            section_timers[current_section][name] = _make_entry(timer_match)

    return result, section_timers


@register(OS.CISCO_IOSXE, "show crypto pki timers detail")
class ShowCryptoPkiTimersDetailParser(
    BaseParser[ShowCryptoPkiTimersDetailResult],
):
    """Parser for 'show crypto pki timers detail' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiTimersDetailResult:
        """Parse 'show crypto pki timers detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dictionary keyed by section name, each containing the
            next expiry timer and named sub-timers.

        Raises:
            ValueError: If no timer sections are found in the output.
        """
        result, section_timers = _parse_sections(output.splitlines())

        if not result:
            msg = "No timer sections found in output"
            raise ValueError(msg)

        for section, timers in section_timers.items():
            if timers:
                result[section]["timers"] = timers

        return cast(ShowCryptoPkiTimersDetailResult, result)
