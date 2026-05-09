"""Parser for 'show controllers fabric fia drops egress location' on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FiaDropCounters(TypedDict):
    """Schema for drop counters within a single FIA instance.

    Dict-of-dicts keyed by counter name, value is the drop count.
    """

    counters: dict[str, int]


class ShowControllersFabricFiaDropsEgressLocationResult(TypedDict):
    """Schema for 'show controllers fabric fia drops egress location' output.

    Dict-of-dicts keyed by FIA instance name (e.g. "FIA-0").
    """

    fia_instances: dict[str, FiaDropCounters]


@register(
    OS.CISCO_IOSXR,
    r"show controllers fabric fia drops egress location (?P<location>\S+)",
)
class ShowControllersFabricFiaDropsEgressLocationParser(
    BaseParser[ShowControllersFabricFiaDropsEgressLocationResult],
):
    """Parser for 'show controllers fabric fia drops egress location' on IOS-XR.

    Parses FIA fabric ASIC egress drop counters grouped by FIA instance.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    _FIA_HEADER = re.compile(r"\*{2,}\s+(?P<fia>FIA-\d+)\s+\*{2,}")
    _COUNTER_LINE = re.compile(r"^\s+(?P<name>.+?)\s{2,}(?P<count>\d+)\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowControllersFabricFiaDropsEgressLocationResult:
        """Parse egress FIA drop counter output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed FIA drop counters grouped by instance.

        Raises:
            ValueError: If no FIA instances are found in the output.
        """
        fia_instances: dict[str, FiaDropCounters] = {}
        current_fia: str | None = None

        for line in output.splitlines():
            header_match = cls._FIA_HEADER.search(line)
            if header_match:
                current_fia = header_match.group("fia")
                fia_instances[current_fia] = FiaDropCounters(counters={})
                continue

            if current_fia is None:
                continue

            # Skip the "Category:" line
            stripped = line.strip()
            if stripped.startswith("Category:"):
                continue

            counter_match = cls._COUNTER_LINE.match(line)
            if counter_match:
                name = counter_match.group("name").strip()
                count = int(counter_match.group("count"))
                fia_instances[current_fia]["counters"][name] = count

        if not fia_instances:
            msg = "No FIA instances found in output"
            raise ValueError(msg)

        return cast(
            ShowControllersFabricFiaDropsEgressLocationResult,
            {"fia_instances": fia_instances},
        )
