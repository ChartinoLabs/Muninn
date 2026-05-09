"""Parser for 'show counter global' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class CounterEntry(TypedDict):
    """Schema for a single global counter entry."""

    value: int
    rate: int
    severity: str
    category: str
    aspect: str
    description: str


class ShowCounterGlobalResult(TypedDict):
    """Schema for 'show counter global' parsed output."""

    elapsed_time_seconds: NotRequired[float]
    counters: dict[str, CounterEntry]


@register(OS.PALOALTO_PANOS, "show counter global")
class ShowCounterGlobalParser(BaseParser[ShowCounterGlobalResult]):
    """Parser for 'show counter global' command on Palo Alto PAN-OS.

    Parses the tabular global counters output. The result includes the
    sampling window header (``elapsed_time_seconds``) when present and a
    ``counters`` dict keyed by counter name, each entry containing value,
    rate, severity, category, aspect, and description.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    # Header line: "Elapsed time since last sampling: 349.576 seconds"
    _ELAPSED_TIME_LINE = re.compile(
        r"^Elapsed time since last sampling:\s+(?P<seconds>[\d.]+)\s+seconds\s*$"
    )

    # Matches counter lines: name, value, rate, severity, category, aspect, description
    _COUNTER_LINE = re.compile(
        r"^(?P<name>\S+)"
        r"\s+(?P<value>\d+)"
        r"\s+(?P<rate>\d+)"
        r"\s+(?P<severity>\S+)"
        r"\s+(?P<category>\S+)"
        r"\s+(?P<aspect>\S+)"
        r"\s+(?P<description>.+?)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowCounterGlobalResult:
        """Parse 'show counter global' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict containing optional ``elapsed_time_seconds`` and a
            ``counters`` mapping keyed by counter name.

        Raises:
            ValueError: If no counters are found in the output.
        """
        counters: dict[str, CounterEntry] = {}
        elapsed_time_seconds: float | None = None

        for raw_line in output.splitlines():
            line = raw_line.strip()

            if elapsed_time_seconds is None:
                elapsed_match = cls._ELAPSED_TIME_LINE.match(line)
                if elapsed_match:
                    elapsed_time_seconds = float(elapsed_match.group("seconds"))
                    continue

            match = cls._COUNTER_LINE.match(line)
            if not match:
                continue

            name = match.group("name")
            counters[name] = CounterEntry(
                value=int(match.group("value")),
                rate=int(match.group("rate")),
                severity=match.group("severity"),
                category=match.group("category"),
                aspect=match.group("aspect"),
                description=match.group("description"),
            )

        if not counters:
            msg = "No counters found in output"
            raise ValueError(msg)

        result: ShowCounterGlobalResult = {"counters": counters}
        if elapsed_time_seconds is not None:
            result["elapsed_time_seconds"] = elapsed_time_seconds
        return result
