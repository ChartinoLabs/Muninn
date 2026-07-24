"""Parser for 'show sdr' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag

# Sentinel values indicating absence of a meaningful value.
_NA_SENTINELS = frozenset({"N/A", "n/a", "NA", ""})


class ShowSdrNodeEntry(TypedDict):
    """Schema for a single node entry in 'show sdr' output."""

    type: str
    node_state: str
    red_state: NotRequired[str]
    partner_name: NotRequired[str]


# Dict keyed by node name (e.g. '0/RP0/CPU0') -> node details.
ShowSdrResult = dict[str, ShowSdrNodeEntry]


@register(OS.CISCO_IOSXR, "show sdr")
class ShowSdrParser(BaseParser[ShowSdrResult]):
    """Parser for 'show sdr' on Cisco IOS-XR.

    Parses the Secure Domain Router (SDR) node table, returning a dict
    keyed by node name with type, node state, redundancy state, and
    partner information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.PLATFORM, ParserTag.REDUNDANCY}
    )

    # Fixed-column positions derived from the header layout:
    #   Type                  NodeName       NodeState      RedState       PartnerName
    #   0                     22             37             52             67
    _COL_NODE_NAME = 22
    _COL_NODE_STATE = 37
    _COL_RED_STATE = 52
    _COL_PARTNER_NAME = 67

    # Header line pattern to detect column positions dynamically.
    _HEADER_RE = re.compile(
        r"^Type\s+NodeName\s+NodeState\s+RedState\s+PartnerName\s*$"
    )

    @classmethod
    def _parse_fixed_width_line(cls, line: str) -> tuple[str, ShowSdrNodeEntry] | None:
        """Parse a single fixed-width data line into a node entry.

        Args:
            line: Raw line from the table body.

        Returns:
            Tuple of (node_name, entry) or None if line cannot be parsed.
        """
        if len(line) < cls._COL_NODE_STATE:
            return None

        type_field = line[: cls._COL_NODE_NAME].strip()
        node_name = line[cls._COL_NODE_NAME : cls._COL_NODE_STATE].strip()
        node_state = line[cls._COL_NODE_STATE : cls._COL_RED_STATE].strip()
        red_state = line[cls._COL_RED_STATE : cls._COL_PARTNER_NAME].strip()
        partner_name = line[cls._COL_PARTNER_NAME :].strip()

        if not type_field or not node_name or not node_state:
            return None

        entry = ShowSdrNodeEntry(
            type=type_field,
            node_state=node_state,
        )

        if red_state not in _NA_SENTINELS:
            entry["red_state"] = red_state

        if partner_name not in _NA_SENTINELS:
            entry["partner_name"] = partner_name

        return node_name, entry

    @classmethod
    def parse(cls, output: str) -> ShowSdrResult:
        """Parse 'show sdr' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by node name with type, node state, redundancy
            state, and partner name.

        Raises:
            ValueError: If no SDR node entries are found.
        """
        result: ShowSdrResult = {}
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

            parsed = cls._parse_fixed_width_line(line)
            if parsed:
                node_name, entry = parsed
                result[node_name] = entry

        if not result:
            msg = "No SDR node entries found in output"
            raise ValueError(msg)

        return result
