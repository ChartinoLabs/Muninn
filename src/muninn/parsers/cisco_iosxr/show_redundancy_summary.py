"""Parser for 'show redundancy summary' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RedundancyPairEntry(TypedDict):
    """Schema for a single redundancy pair (one line of output)."""

    active_node: str
    active_role: str
    standby_node: str
    standby_role: str
    nsr_status: NotRequired[str]


class ShowRedundancySummaryResult(TypedDict):
    """Schema for 'show redundancy summary' parsed output on IOS-XR.

    The output contains one or more redundancy pairs, each showing
    active/standby node locations, their roles, and readiness status.
    Pairs are keyed by ready status (e.g. "Node Ready", "Proc Group Ready").
    """

    pairs: dict[str, RedundancyPairEntry]


@register(OS.CISCO_IOSXR, "show redundancy summary")
class ShowRedundancySummaryParser(BaseParser[ShowRedundancySummaryResult]):
    """Parser for 'show redundancy summary' command on Cisco IOS-XR.

    Parses active/standby node pairs, roles, and readiness status
    from the redundancy summary output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    # Matches lines like:
    #   0/RSP0/CPU0(A)   0/RSP1/CPU0(S) (Node Ready, NSR: Ready)
    #   0/RSP0/CPU0(P)   0/RSP1/CPU0(B) (Proc Group Ready, NSR: Ready)
    _PAIR_PATTERN = re.compile(
        r"^\s*"
        r"(?P<active_node>\S+)"
        r"\((?P<active_role>[A-Z])\)"
        r"\s+"
        r"(?P<standby_node>\S+)"
        r"\((?P<standby_role>[A-Z])\)"
        r"\s+"
        r"\((?P<ready_status>[^,)]+)"
        r"(?:,\s*NSR:\s*(?P<nsr_status>[^)]+))?"
        r"\)"
    )

    _ROLE_MAP: ClassVar[dict[str, str]] = {
        "A": "Active",
        "S": "Standby",
        "P": "Primary",
        "B": "Backup",
    }

    @classmethod
    def parse(cls, output: str) -> ShowRedundancySummaryResult:
        """Parse 'show redundancy summary' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed redundancy summary keyed by ready status.

        Raises:
            ValueError: If no redundancy pairs are found in the output.
        """
        pairs: dict[str, RedundancyPairEntry] = {}

        for line in output.splitlines():
            match = cls._PAIR_PATTERN.search(line)
            if match:
                ready_status = match.group("ready_status").strip()
                entry = RedundancyPairEntry(
                    active_node=match.group("active_node"),
                    active_role=cls._ROLE_MAP.get(
                        match.group("active_role"), match.group("active_role")
                    ),
                    standby_node=match.group("standby_node"),
                    standby_role=cls._ROLE_MAP.get(
                        match.group("standby_role"), match.group("standby_role")
                    ),
                )
                nsr = match.group("nsr_status")
                if nsr:
                    entry["nsr_status"] = nsr.strip()

                pairs[ready_status] = entry

        if not pairs:
            msg = "No redundancy pairs found in output"
            raise ValueError(msg)

        return ShowRedundancySummaryResult(pairs=pairs)
