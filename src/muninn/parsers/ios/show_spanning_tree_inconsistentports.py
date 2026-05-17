"""Parser for 'show spanning-tree inconsistentports' command on IOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_HEADER_RE = re.compile(r"^\s*Name\s+Interface\s+Inconsistency\s*$", re.IGNORECASE)
_ROW_RE = re.compile(
    r"^VLAN(?P<vlan>\d+)\s+(?P<interface>\S+)\s+(?P<inconsistency>.+?)\s*$"
)
_COUNT_RE = re.compile(
    r"^Number of inconsistent ports \(segments\) in the system\s*:\s*"
    r"(?P<count>\d+)\s*$",
    re.IGNORECASE,
)


class ShowSpanningTreeInconsistentPortsResult(TypedDict):
    """Schema for 'show spanning-tree inconsistentports' parsed output."""

    vlans: dict[str, dict[str, str]]
    inconsistent_count: int


def _try_row(line: str, vlans: dict[str, dict[str, str]]) -> bool:
    """Attempt to parse one inconsistent-port row into the vlans map."""
    match = _ROW_RE.match(line)
    if match is None:
        return False
    vlan_id = str(int(match.group("vlan")))
    interface = canonical_interface_name(match.group("interface"), os=OS.CISCO_IOS)
    vlans.setdefault(vlan_id, {})[interface] = match.group("inconsistency").strip()
    return True


@register(OS.CISCO_IOS, "show spanning-tree inconsistentports")
class ShowSpanningTreeInconsistentPortsParser(
    BaseParser[ShowSpanningTreeInconsistentPortsResult]
):
    """Parser for 'show spanning-tree inconsistentports' on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.STP,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowSpanningTreeInconsistentPortsResult:
        """Parse 'show spanning-tree inconsistentports' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Mapping of VLAN ID to interface-to-inconsistency-state map, plus
            the device-reported total inconsistent-port count.

        Raises:
            ValueError: If the footer count line is missing from the output.
        """
        vlans: dict[str, dict[str, str]] = {}
        count: int | None = None

        for line in output.splitlines():
            if (
                not line.strip()
                or _HEADER_RE.match(line)
                or SEPARATOR_DASH_SPACE_RE.match(line)
            ):
                continue

            count_match = _COUNT_RE.match(line)
            if count_match:
                count = int(count_match.group("count"))
                continue

            _try_row(line, vlans)

        if count is None:
            msg = (
                "Missing 'Number of inconsistent ports' footer in "
                "'show spanning-tree inconsistentports' output"
            )
            raise ValueError(msg)

        return cast(
            ShowSpanningTreeInconsistentPortsResult,
            {"vlans": vlans, "inconsistent_count": count},
        )
