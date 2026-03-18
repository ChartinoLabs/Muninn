"""Parser for 'show track' command on NX-OS."""

import re
from typing import Any, ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TrackEntry(TypedDict):
    """Schema for a single track entry."""

    type: str
    instance: str
    subtrack: str
    state: str
    change_count: int
    last_change: str


class ShowTrackResult(TypedDict):
    """Schema for 'show track' parsed output."""

    track: dict[str, TrackEntry]


@register(OS.CISCO_NXOS, "show track")
class ShowTrackParser(BaseParser[ShowTrackResult]):
    """Parser for 'show track' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.TRACKING})

    _TRACK_ID_PATTERN = re.compile(r"^Track\s+(?P<id>\d+)$", re.I)
    _DETAIL_PATTERN = re.compile(
        r"^(?P<type>IPv6 Route|IP Route|IP SLA|Interface|List)\s+"
        r"(?P<instance>\S+)\s+(?P<subtrack>\S+)$"
    )
    _STATE_PATTERN = re.compile(r"^(?P<subtrack>\S+)\s+is\s+(?P<state>\S+)$")
    _CHANGE_PATTERN = re.compile(
        r"^(?P<count>\d+)\s+changes,\s+last\s+change\s+(?P<last>\S+)$",
        re.I,
    )

    @classmethod
    def parse(cls, output: str) -> ShowTrackResult:
        """Parse 'show track' output.

        Args:
            output: Raw CLI output from 'show track' command.

        Returns:
            Parsed track data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, dict[str, Any]] = {"track": {}}
        current_id: str | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._TRACK_ID_PATTERN.match(line)
            if match:
                current_id = match.group("id")
                result["track"][current_id] = {}
                continue

            if current_id is None:
                continue

            match = cls._DETAIL_PATTERN.match(line)
            if match:
                entry = result["track"][current_id]
                entry["type"] = match.group("type")
                entry["instance"] = match.group("instance")
                entry["subtrack"] = match.group("subtrack")
                continue

            match = cls._STATE_PATTERN.match(line)
            if match:
                result["track"][current_id]["state"] = match.group("state")
                continue

            match = cls._CHANGE_PATTERN.match(line)
            if match:
                entry = result["track"][current_id]
                entry["change_count"] = int(match.group("count"))
                entry["last_change"] = match.group("last")

        if not result["track"]:
            msg = "No track entries found"
            raise ValueError(msg)

        return cast(ShowTrackResult, result)
