"""Parser for 'show controllers fabric fia errors ingress location' on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FiaErrorCounter(TypedDict):
    """Schema for a single FIA error counter."""

    category: str
    counters: dict[str, int]


class ShowControllersFabricFiaErrorsIngressLocationResult(TypedDict):
    """Schema for 'show controllers fabric fia errors ingress location' parsed output.

    Keyed by FIA instance identifier (e.g. "0", "1").
    Each FIA instance contains a category string and a dict of counter name to value.
    """

    fia_instances: dict[str, FiaErrorCounter]


@register(
    OS.CISCO_IOSXR,
    r"show controllers fabric fia errors ingress location (?P<location>\S+)",
)
class ShowControllersFabricFiaErrorsIngressLocationParser(
    BaseParser[ShowControllersFabricFiaErrorsIngressLocationResult],
):
    """Parser for 'show controllers fabric fia errors ingress location' on IOS-XR.

    Parses FIA instance error counters from fabric ingress diagnostics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    _FIA_HEADER = re.compile(r"^\s*\*{10}\s+FIA-(?P<instance>\d+)\s+\*{10}")
    _CATEGORY = re.compile(r"^Category:\s+(?P<category>\S+)")
    _COUNTER = re.compile(r"^(?P<name>.+?)\s{2,}(?P<value>\d+)\s*$")

    @classmethod
    def _save_instance(
        cls,
        fia_instances: dict[str, FiaErrorCounter],
        instance: str | None,
        category: str | None,
        counters: dict[str, int],
    ) -> None:
        """Store a completed FIA instance into the results dict."""
        if instance is not None and category is not None:
            fia_instances[instance] = FiaErrorCounter(
                category=category,
                counters=counters,
            )

    @classmethod
    def _parse_counter_line(cls, line: str, counters: dict[str, int]) -> None:
        """Parse a counter line and add it to the counters dict if it matches."""
        if match := cls._COUNTER.match(line):
            counters[match.group("name").strip()] = int(match.group("value"))

    @classmethod
    def parse(cls, output: str) -> ShowControllersFabricFiaErrorsIngressLocationResult:
        """Parse FIA ingress error counters.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed FIA error counter data keyed by instance number.

        Raises:
            ValueError: If no FIA instances are found in the output.
        """
        fia_instances: dict[str, FiaErrorCounter] = {}
        current_instance: str | None = None
        current_category: str | None = None
        current_counters: dict[str, int] = {}

        for line in output.splitlines():
            if match := cls._FIA_HEADER.match(line):
                cls._save_instance(
                    fia_instances, current_instance, current_category, current_counters
                )
                current_instance = match.group("instance")
                current_category = None
                current_counters = {}
            elif current_instance is not None and (cat := cls._CATEGORY.match(line)):
                current_category = cat.group("category")
            elif current_instance is not None:
                cls._parse_counter_line(line, current_counters)

        cls._save_instance(
            fia_instances, current_instance, current_category, current_counters
        )

        if not fia_instances:
            msg = "No FIA instances found in output"
            raise ValueError(msg)

        return ShowControllersFabricFiaErrorsIngressLocationResult(
            fia_instances=fia_instances,
        )
