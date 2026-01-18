"""Parser for 'show vdc current-vdc' command on NX-OS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class VdcCurrentInfo(TypedDict):
    """Schema for current VDC info."""

    id: str
    name: str


class ShowVdcCurrentResult(TypedDict):
    """Schema for 'show vdc current-vdc' parsed output."""

    current_vdc: VdcCurrentInfo


@register(OS.CISCO_NXOS, "show vdc current-vdc")
class ShowVdcCurrentParser(BaseParser[ShowVdcCurrentResult]):
    """Parser for 'show vdc current-vdc' command.

    Example output:
        Current vdc is 1 - PE1
    """

    _PATTERN = re.compile(
        r"^Current\s+vdc\s+is\s+(?P<id>\d+)\s*-\s*(?P<name>\S+)$",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowVdcCurrentResult:
        """Parse 'show vdc current-vdc' output.

        Args:
            output: Raw CLI output from 'show vdc current-vdc' command.

        Returns:
            Parsed current VDC data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._PATTERN.match(line)
            if match:
                return ShowVdcCurrentResult(
                    current_vdc=VdcCurrentInfo(
                        id=match.group("id"),
                        name=match.group("name"),
                    )
                )

        msg = "No matching current VDC line found"
        raise ValueError(msg)
