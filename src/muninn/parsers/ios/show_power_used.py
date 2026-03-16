"""Parser for 'show power used' command on IOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowPowerUsedResult(TypedDict):
    """Schema for 'show power used' parsed output."""

    watts: float
    amps: float
    volts: int


@register(OS.CISCO_IOS, "show power used")
class ShowPowerUsedParser(BaseParser[ShowPowerUsedResult]):
    """Parser for 'show power used' command.

    Example output:
        system power used =      2255.76 Watts (43.38 Amps @ 52V)
    """

    tags: ClassVar[frozenset[str]] = frozenset({"environment", "system"})

    _PATTERN = re.compile(
        r"system\s+power\s+used\s*=\s*"
        r"(?P<watts>[\d.]+)\s*Watts\s*"
        r"\((?P<amps>[\d.]+)\s*Amps\s*@\s*(?P<volts>\d+)V\)",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowPowerUsedResult:
        """Parse 'show power used' output.

        Args:
            output: Raw CLI output from 'show power used' command.

        Returns:
            Parsed power usage data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._PATTERN.match(line)
            if match:
                return ShowPowerUsedResult(
                    watts=float(match.group("watts")),
                    amps=float(match.group("amps")),
                    volts=int(match.group("volts")),
                )

        msg = "No matching power usage line found"
        raise ValueError(msg)
