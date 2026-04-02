"""Parser for 'show controllers fabric fia drops ingress location' on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FiaCounterEntry(TypedDict):
    """Schema for an individual drop counter within a FIA instance."""

    count: int


class FiaInstanceEntry(TypedDict):
    """Schema for a single FIA instance's drop counters.

    Keys are counter names (e.g. "From Spaui Drop-0", "sp0 crc err").
    Values are dicts with a ``count`` field.
    """

    category: str
    counters: dict[str, FiaCounterEntry]


# Top-level result keyed by FIA instance name (e.g. "FIA-0", "FIA-1").
ShowControllersFabricFiaDropsIngressLocationResult = dict[str, FiaInstanceEntry]


@register(OS.CISCO_IOSXR, "show controllers fabric fia drops ingress location")
class ShowControllersFabricFiaDropsIngressLocationParser(
    BaseParser[ShowControllersFabricFiaDropsIngressLocationResult],
):
    """Parser for 'show controllers fabric fia drops ingress location'.

    Extracts per-FIA-instance ingress drop counters including category
    and individual counter name/value pairs.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    _FIA_HEADER = re.compile(r"^\s*\*{10}\s+(?P<fia>FIA-\d+)\s+\*{10}\s*$")
    _CATEGORY = re.compile(r"^Category:\s+(?P<category>\S+)")
    _COUNTER = re.compile(r"^(?P<name>.+?)\s{2,}(?P<count>\d+)\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowControllersFabricFiaDropsIngressLocationResult:
        """Parse FIA ingress drop counters from raw CLI output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by FIA instance name, each containing a category
            string and a counters dict mapping counter names to counts.

        Raises:
            ValueError: If no FIA instances are found in the output.
        """
        result: ShowControllersFabricFiaDropsIngressLocationResult = {}
        current_fia: str | None = None
        current_entry: FiaInstanceEntry | None = None

        for line in output.splitlines():
            # Check for FIA header
            if match := cls._FIA_HEADER.match(line):
                current_fia = match.group("fia")
                current_entry = FiaInstanceEntry(category="", counters={})
                result[current_fia] = current_entry
                continue

            if current_entry is None:
                continue

            # Check for category line
            if match := cls._CATEGORY.match(line):
                current_entry["category"] = match.group("category")
                continue

            # Check for counter line
            stripped = line.strip()
            if not stripped:
                continue

            if match := cls._COUNTER.match(stripped):
                counter_name = match.group("name").strip()
                counter_value = int(match.group("count"))
                current_entry["counters"][counter_name] = FiaCounterEntry(
                    count=counter_value,
                )

        if not result:
            msg = "No FIA instances found in output"
            raise ValueError(msg)

        return result
