"""Parser for 'show vlan summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowVlanSummaryResult(TypedDict):
    """Schema for 'show vlan summary' parsed output.

    ``existing_vlans`` is always present; the other counters are
    ``NotRequired`` because not all IOS-XE versions emit them.
    """

    existing_vlans: int
    vtp_vlans: NotRequired[int]
    extended_vlans: NotRequired[int]


_EXISTING_VLANS_RE = re.compile(
    r"^\s*Number of existing VLANs\s*:\s*(?P<count>\d+)\s*$"
)
_VTP_VLANS_RE = re.compile(r"^\s*Number of existing VTP VLANs\s*:\s*(?P<count>\d+)\s*$")
_EXTENDED_VLANS_RE = re.compile(
    r"^\s*Number of existing extended VLANS\s*:\s*(?P<count>\d+)\s*$"
)


@register(OS.CISCO_IOSXE, "show vlan summary")
class ShowVlanSummaryParser(BaseParser[ShowVlanSummaryResult]):
    """Parser for 'show vlan summary' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SWITCHING, ParserTag.VLAN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowVlanSummaryResult:
        """Parse 'show vlan summary' output.

        Args:
            output: Raw CLI output from 'show vlan summary' command.

        Returns:
            Parsed VLAN summary counters.

        Raises:
            ValueError: If no VLAN count line is found in the output.
        """
        result: dict = {}

        for raw_line in output.splitlines():
            match = _EXISTING_VLANS_RE.match(raw_line)
            if match:
                result["existing_vlans"] = int(match.group("count"))
                continue

            match = _VTP_VLANS_RE.match(raw_line)
            if match:
                result["vtp_vlans"] = int(match.group("count"))
                continue

            match = _EXTENDED_VLANS_RE.match(raw_line)
            if match:
                result["extended_vlans"] = int(match.group("count"))
                continue

        if "existing_vlans" not in result:
            msg = "No 'show vlan summary' content recognized in output"
            raise ValueError(msg)

        return cast(ShowVlanSummaryResult, result)
