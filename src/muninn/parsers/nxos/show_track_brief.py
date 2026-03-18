"""Parser for 'show track brief' command on NX-OS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TrackBriefEntry(TypedDict):
    """Schema for a single track brief entry."""

    tracktype: str
    instance: str
    parameter: str
    state: str
    last_change: str


class ShowTrackBriefResult(TypedDict):
    """Schema for 'show track brief' parsed output."""

    track: dict[str, TrackBriefEntry]


@register(OS.CISCO_NXOS, "show track brief")
class ShowTrackBriefParser(BaseParser[ShowTrackBriefResult]):
    """Parser for 'show track brief' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.TRACKING})

    _ROW_PATTERN = re.compile(
        r"^(?P<track>\d+)\s+"
        r"(?P<type>IP Route|Interface|IP SLA|IPv6 Route|List)\s+"
        r"(?P<instance>\S+)\s+"
        r"(?P<parameter>.+?)\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<last_change>\S+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowTrackBriefResult:
        """Parse 'show track brief' output.

        Args:
            output: Raw CLI output from 'show track brief' command.

        Returns:
            Parsed track brief data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: ShowTrackBriefResult = {"track": {}}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.lower().startswith("track type"):
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                track_id = match.group("track")
                result["track"][track_id] = {
                    "tracktype": match.group("type"),
                    "instance": match.group("instance"),
                    "parameter": match.group("parameter"),
                    "state": match.group("state"),
                    "last_change": match.group("last_change"),
                }

        if not result["track"]:
            msg = "No track brief entries found"
            raise ValueError(msg)

        return result
