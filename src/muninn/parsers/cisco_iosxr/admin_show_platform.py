"""Parser for 'admin show platform' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Sentinel values that mean "no value" and should be omitted from output.
_NA_SENTINELS = frozenset({"N/A", "n/a", "NA"})


class AdminShowPlatformEntry(TypedDict):
    """Schema for a single node entry in 'admin show platform' output."""

    type: str
    hw_state: str
    sw_state: NotRequired[str]
    config_state: str


AdminShowPlatformResult = dict[str, AdminShowPlatformEntry]


@register(OS.CISCO_IOSXR, "admin show platform")
class AdminShowPlatformParser(BaseParser[AdminShowPlatformResult]):
    """Parser for 'admin show platform' on Cisco IOS-XR.

    Returns a dict keyed by node location (e.g. '0/0', '0/RP0').
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    _SEPARATOR = re.compile(r"^-{3,}$")

    _NODE_LINE = re.compile(
        r"^(?P<location>\S+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<hw_state>\S+)\s+"
        r"(?P<sw_state>\S+)\s+"
        r"(?P<config_state>\S+)\s*$"
    )

    @classmethod
    def _build_entry(cls, match: re.Match[str]) -> AdminShowPlatformEntry:
        """Build a platform entry from a regex match, omitting N/A sentinels."""
        entry = AdminShowPlatformEntry(
            type=match.group("type"),
            hw_state=match.group("hw_state"),
            config_state=match.group("config_state"),
        )
        sw_state = match.group("sw_state")
        if sw_state not in _NA_SENTINELS:
            entry["sw_state"] = sw_state
        return entry

    @classmethod
    def parse(cls, output: str) -> AdminShowPlatformResult:
        """Parse 'admin show platform' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by node location with card type, HW/SW/config state.

        Raises:
            ValueError: If no platform entries are found.
        """
        result: AdminShowPlatformResult = {}
        past_header = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if cls._SEPARATOR.match(stripped):
                past_header = True
                continue

            if not past_header:
                continue

            match = cls._NODE_LINE.match(stripped)
            if match:
                result[match.group("location")] = cls._build_entry(match)

        if not result:
            msg = "No platform entries found in output"
            raise ValueError(msg)

        return result
