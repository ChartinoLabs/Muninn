"""Parser for 'show platform' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class ShowPlatformNodeEntry(TypedDict):
    """Schema for a single node entry in 'show platform' output."""

    type: str
    state: str
    config_state: NotRequired[str]


# Dict keyed by node name (e.g. '0/RSP0/CPU0') -> node details.
ShowPlatformResult = dict[str, ShowPlatformNodeEntry]


@register(OS.CISCO_IOSXR, "show platform")
class ShowPlatformParser(BaseParser[ShowPlatformResult]):
    """Parser for 'show platform' command on Cisco IOS-XR.

    Parses the tabular output of node/slot inventory with type, state,
    and optional config state information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.PLATFORM, ParserTag.SYSTEM}
    )

    # Match lines like:
    # 0/RSP0/CPU0     A9K-RSP440-TR(Active)     IOS XR RUN       PWR,NSHUT,MON
    # 0/FT0/SP        ASR-9010-FAN-V2           READY
    _NODE_LINE = re.compile(
        r"^(?P<node>\d+\S+)"
        r"\s+"
        r"(?P<type>\S+)"
        r"\s+"
        r"(?P<state>.+?)"
        r"(?:\s{2,}(?P<config_state>\S+.*))?$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowPlatformResult:
        """Parse 'show platform' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by node name with type, state, and config_state.

        Raises:
            ValueError: If no platform entries are found.
        """
        result: ShowPlatformResult = {}
        past_header = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Skip until we pass the separator line
            if SEPARATOR_DASH_RE.match(stripped):
                past_header = True
                continue

            if not past_header:
                continue

            match = cls._NODE_LINE.match(stripped)
            if match:
                node = match.group("node")
                config_state = match.group("config_state")
                entry = ShowPlatformNodeEntry(
                    type=match.group("type"),
                    state=match.group("state").strip(),
                )
                if config_state and config_state.strip():
                    entry["config_state"] = config_state.strip()
                result[node] = entry

        if not result:
            msg = "No platform entries found in output"
            raise ValueError(msg)

        return result
