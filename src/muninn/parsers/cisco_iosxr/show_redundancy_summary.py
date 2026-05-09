"""Parser for 'show redundancy summary' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RedundancyPairEntry(TypedDict):
    """Schema for a single redundancy pair (one line of output).

    A pair represents either node-level (Active/Standby) or process-group-level
    (Primary/Backup) redundancy. Standby fields are absent when the device
    reports `N/A` for the standby/backup node.
    """

    active_node: str
    active_role: str
    standby_node: NotRequired[str]
    standby_role: NotRequired[str]
    ready_status: str
    nsr_status: NotRequired[str]


class ShowRedundancySummaryResult(TypedDict):
    """Schema for 'show redundancy summary' parsed output on IOS-XR.

    The output contains one or more redundancy pairs. Pairs are keyed by the
    type of redundancy they describe, derived from the role characters:

    - ``node`` — active/standby node-level pair (roles A/S).
    - ``proc_group`` — primary/backup process-group-level pair (roles P/B).

    Keying by pair type (rather than by readiness text) keeps the schema
    stable across ready / not-ready device states.
    """

    pairs: dict[str, RedundancyPairEntry]


# Active and standby segments. The standby half is optional because the
# device emits a literal `N/A` (no parens, no role) for unresolved peers.
_ACTIVE_RE = re.compile(
    r"^\s*(?P<active_node>\S+)\((?P<active_role>[A-Z])\)\s+"
    r"(?:"
    r"(?P<standby_node>\S+)\((?P<standby_role>[A-Z])\)"
    r"|"
    r"(?P<standby_na>N/A)"
    r")"
    r"\s+\((?P<status_block>[^)]+)\)"
)


@register(OS.CISCO_IOSXR, "show redundancy summary")
class ShowRedundancySummaryParser(BaseParser[ShowRedundancySummaryResult]):
    """Parser for 'show redundancy summary' command on Cisco IOS-XR.

    Parses active/standby node pairs, roles, and readiness status
    from the redundancy summary output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    _ROLE_MAP: ClassVar[dict[str, str]] = {
        "A": "Active",
        "S": "Standby",
        "P": "Primary",
        "B": "Backup",
    }

    # Maps the active-side role letter to the pair-type key. Both pair members
    # share the level (A↔S are node-level, P↔B are process-group-level), so we
    # only need to look at the active letter.
    _PAIR_TYPE_MAP: ClassVar[dict[str, str]] = {
        "A": "node",
        "S": "node",
        "P": "proc_group",
        "B": "proc_group",
    }

    @classmethod
    def parse(cls, output: str) -> ShowRedundancySummaryResult:
        """Parse 'show redundancy summary' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed redundancy summary keyed by pair type (``node`` /
            ``proc_group``).

        Raises:
            ValueError: If no redundancy pairs are found in the output.
        """
        pairs: dict[str, RedundancyPairEntry] = {}

        for line in output.splitlines():
            match = _ACTIVE_RE.search(line)
            if not match:
                continue

            active_role_letter = match.group("active_role")
            pair_type = cls._PAIR_TYPE_MAP.get(active_role_letter)
            if pair_type is None:
                continue

            entry: RedundancyPairEntry = {
                "active_node": match.group("active_node"),
                "active_role": cls._ROLE_MAP.get(
                    active_role_letter, active_role_letter
                ),
                "ready_status": _parse_ready_status(match.group("status_block")),
            }

            if match.group("standby_node") is not None:
                entry["standby_node"] = match.group("standby_node")
                standby_role_letter = match.group("standby_role")
                entry["standby_role"] = cls._ROLE_MAP.get(
                    standby_role_letter, standby_role_letter
                )

            nsr = _parse_nsr_status(match.group("status_block"))
            if nsr is not None:
                entry["nsr_status"] = nsr

            pairs[pair_type] = entry

        if not pairs:
            msg = "No redundancy pairs found in output"
            raise ValueError(msg)

        return ShowRedundancySummaryResult(pairs=pairs)


def _parse_ready_status(status_block: str) -> str:
    """Return the readiness portion of the status block.

    Status blocks look like ``Node Ready, NSR: Ready`` or
    ``Proc Group Not Ready``. The readiness portion is everything before the
    optional ``, NSR: ...`` suffix.
    """
    head, _, _ = status_block.partition(",")
    return head.strip()


def _parse_nsr_status(status_block: str) -> str | None:
    """Return the NSR status portion, or ``None`` when absent."""
    _, sep, tail = status_block.partition(",")
    if not sep:
        return None
    nsr_match = re.match(r"\s*NSR:\s*(?P<nsr>.+)$", tail)
    if not nsr_match:
        return None
    return nsr_match.group("nsr").strip()
