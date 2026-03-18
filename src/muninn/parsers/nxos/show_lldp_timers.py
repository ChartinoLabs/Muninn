"""Parser for 'show lldp timers' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowLldpTimersResult(TypedDict):
    """Schema for 'show lldp timers' parsed output."""

    hold_timer: int
    reinit_timer: int
    hello_timer: int
    transmit_delay: NotRequired[int]
    hold_multiplier: NotRequired[int]
    notification_interval: NotRequired[int]


@register(OS.CISCO_NXOS, "show lldp timers")
class ShowLldpTimersParser(BaseParser[ShowLldpTimersResult]):
    """Parser for 'show lldp timers' command.

    Example output:
        LLDP Timers:
        Holdtime in seconds: 120
        Reinit-time in seconds: 2
        Transmit interval in seconds: 30
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    _FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        (
            re.compile(r"^Holdtime\s+in\s+seconds:\s+(?P<value>\d+)$", re.I),
            "hold_timer",
        ),
        (
            re.compile(r"^Reinit-time\s+in\s+seconds:\s+(?P<value>\d+)$", re.I),
            "reinit_timer",
        ),
        (
            re.compile(r"^Transmit\s+interval\s+in\s+seconds:\s+(?P<value>\d+)$", re.I),
            "hello_timer",
        ),
        (
            re.compile(r"^Transmit\s+delay\s+in\s+seconds:\s+(?P<value>\d+)$", re.I),
            "transmit_delay",
        ),
        (
            re.compile(r"^Hold\s+multiplier\s+in\s+seconds:\s+(?P<value>\d+)$", re.I),
            "hold_multiplier",
        ),
        (
            re.compile(
                r"^Notification\s+interval\s+in\s+seconds:\s+(?P<value>\d+)$", re.I
            ),
            "notification_interval",
        ),
    )
    _REQUIRED_FIELDS = ("hold_timer", "reinit_timer", "hello_timer")

    @classmethod
    def parse(cls, output: str) -> ShowLldpTimersResult:
        """Parse 'show lldp timers' output.

        Args:
            output: Raw CLI output from 'show lldp timers' command.

        Returns:
            Parsed LLDP timer data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, int] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            for pattern, field in cls._FIELD_PATTERNS:
                match = pattern.match(line)
                if match:
                    result[field] = int(match.group("value"))
                    break

        if not result:
            msg = "No matching LLDP timer lines found"
            raise ValueError(msg)

        missing = [key for key in cls._REQUIRED_FIELDS if key not in result]
        if missing:
            msg = f"Missing required timer fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowLldpTimersResult, result)
