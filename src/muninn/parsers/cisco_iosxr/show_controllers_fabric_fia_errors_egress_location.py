"""Parser for 'show controllers fabric fia errors egress location' on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FiaErrorCounters(TypedDict):
    """Error counters for a single FIA instance."""

    category: str
    to_spaui_error_0: int
    to_spaui_error_1: int
    rl_over_under_flow_cnt: int


# Top-level result keyed by FIA instance name (e.g. 'FIA-0').
ShowControllersFabricFiaErrorsEgressLocationResult = dict[str, FiaErrorCounters]

# Compiled patterns for matching FIA block structure and counter lines.
_FIA_HEADER = re.compile(r"^\*+\s+(?P<fia>FIA-\d+)\s+\*+$")
_COUNTER_PATTERNS: tuple[tuple[re.Pattern[str], str, bool], ...] = (
    (re.compile(r"^Category:\s+(?P<value>\S+)"), "category", False),
    (re.compile(r"To Spaui Error-0\s+(?P<value>\d+)"), "to_spaui_error_0", True),
    (re.compile(r"To Spaui Error-1\s+(?P<value>\d+)"), "to_spaui_error_1", True),
    (
        re.compile(r"RL over/under flow cnt\s+(?P<value>\d+)"),
        "rl_over_under_flow_cnt",
        True,
    ),
)


def _parse_counter_line(line: str, entry: dict[str, object]) -> None:
    """Match a counter line and store its value in *entry*."""
    for pattern, key, is_int in _COUNTER_PATTERNS:
        if match := pattern.search(line):
            entry[key] = int(match.group("value")) if is_int else match.group("value")
            return


@register(
    OS.CISCO_IOSXR,
    r"show controllers fabric fia errors egress location (?P<location>\S+)",
)
class ShowControllersFabricFiaErrorsEgressLocationParser(
    BaseParser[ShowControllersFabricFiaErrorsEgressLocationResult],
):
    """Parser for 'show controllers fabric fia errors egress location <location>'.

    Parses per-FIA egress error counters from the fabric controller output.
    The IOS-XR ``location`` keyword requires a node identifier
    (e.g. ``0/RP0/CPU0`` or ``all``) to actually run on a device, so the
    parser is registered as a regex pattern that captures the location.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    @classmethod
    def parse(cls, output: str) -> ShowControllersFabricFiaErrorsEgressLocationResult:
        """Parse egress FIA error counters.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by FIA instance name with error counters.

        Raises:
            ValueError: If no FIA blocks are found in the output.
        """
        result: dict[str, dict[str, object]] = {}
        current_fia: str | None = None
        current_entry: dict[str, object] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := _FIA_HEADER.search(stripped):
                if current_fia is not None:
                    result[current_fia] = current_entry
                current_fia = match.group("fia")
                current_entry = {}
                continue

            _parse_counter_line(stripped, current_entry)

        # Flush last FIA block
        if current_fia is not None:
            result[current_fia] = current_entry

        if not result:
            msg = "No FIA blocks found in output"
            raise ValueError(msg)

        return cast(ShowControllersFabricFiaErrorsEgressLocationResult, result)
