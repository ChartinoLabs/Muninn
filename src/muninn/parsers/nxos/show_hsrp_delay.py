"""Parser for 'show hsrp delay' command on NX-OS."""

import re
from typing import TypeAlias, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class DelayInfo(TypedDict):
    """Schema for HSRP delay values."""

    minimum_delay: int
    reload_delay: int


class InterfaceDelay(TypedDict):
    """Schema for per-interface HSRP delay info."""

    delay: DelayInfo


ShowHsrpDelayResult: TypeAlias = dict[str, InterfaceDelay]


@register(OS.CISCO_NXOS, "show hsrp delay")
class ShowHsrpDelayParser(BaseParser):
    """Parser for 'show hsrp delay' command.

    Example output:
        Interface          Minimum Reload
        GigabitEthernet1   99      888
    """

    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+(?P<minimum>\d+)\s+(?P<reload>\d+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowHsrpDelayResult:
        """Parse 'show hsrp delay' output.

        Args:
            output: Raw CLI output from 'show hsrp delay' command.

        Returns:
            Parsed HSRP delay data keyed by interface.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: ShowHsrpDelayResult = {}

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
            msg = "No matching HSRP delay lines found"
            raise ValueError(msg)

        return result
