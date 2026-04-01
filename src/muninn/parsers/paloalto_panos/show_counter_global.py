"""Parser for 'show counter global' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict

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


ShowCounterGlobalResult = dict[str, CounterEntry]


@register(OS.PALOALTO_PANOS, "show counter global")
class ShowCounterGlobalParser(BaseParser[ShowCounterGlobalResult]):
    """Parser for 'show counter global' command on Palo Alto PAN-OS.

    Parses the tabular global counters output into a dict-of-dicts keyed
    by counter name, with each entry containing value, rate, severity,
    category, aspect, and description.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

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
            Dict of counter entries keyed by counter name.

        Raises:
            ValueError: If no counters are found in the output.
        """
        result: ShowCounterGlobalResult = {}

        for line in output.splitlines():
            match = cls._COUNTER_LINE.match(line.strip())
            if not match:
                continue

            name = match.group("name")
            result[name] = CounterEntry(
                value=int(match.group("value")),
                rate=int(match.group("rate")),
                severity=match.group("severity"),
                category=match.group("category"),
                aspect=match.group("aspect"),
                description=match.group("description"),
            )

        if not result:
            msg = "No counters found in output"
            raise ValueError(msg)

        return result
