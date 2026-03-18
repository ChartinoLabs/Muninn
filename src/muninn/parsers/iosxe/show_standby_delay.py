"""Parser for 'show standby delay' command on IOS-XE."""

import re
from typing import ClassVar, TypeAlias, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DelayInfo(TypedDict):
    """Schema for standby delay values."""

    minimum_delay: int
    reload_delay: int


class InterfaceDelay(TypedDict):
    """Schema for per-interface standby delay info."""

    delay: DelayInfo


ShowStandbyDelayResult: TypeAlias = dict[str, InterfaceDelay]


@register(OS.CISCO_IOSXE, "show standby delay")
class ShowStandbyDelayParser(BaseParser[ShowStandbyDelayResult]):
    """Parser for 'show standby delay' command.

    Example output:
        Interface          Minimum Reload
        GigabitEthernet1   99      888
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.FHRP})

    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+(?P<minimum>\d+)\s+(?P<reload>\d+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowStandbyDelayResult:
        """Parse 'show standby delay' output.

        Args:
            output: Raw CLI output from 'show standby delay' command.

        Returns:
            Parsed standby delay data keyed by interface.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: ShowStandbyDelayResult = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.lower().startswith("interface"):
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                interface = match.group("interface")
                result[interface] = {
                    "delay": {
                        "minimum_delay": int(match.group("minimum")),
                        "reload_delay": int(match.group("reload")),
                    }
                }

        if not result:
            msg = "No matching standby delay lines found"
            raise ValueError(msg)

        return result
