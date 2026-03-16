"""Parser for 'show meraki' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class SwitchEntry(TypedDict):
    """Schema for a single switch entry in 'show meraki' output."""

    pid: str
    serial_number: str
    meraki_id: str
    mac_address: str
    registration_status: str
    mode: NotRequired[str]


class ShowMerakiResult(TypedDict):
    """Schema for 'show meraki' parsed output.

    Keyed by switch number (e.g., "1", "2").
    """

    switches: dict[str, SwitchEntry]


# Matches data lines: switch_num, PID, serial, meraki/cloud ID,
# MAC, status, optional mode
_ENTRY_PATTERN = re.compile(
    r"^\s*(?P<switch_num>\d+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<serial>\S+)\s+"
    r"(?P<meraki_id>\S+)\s+"
    r"(?P<mac>\S+)\s+"
    r"(?P<status>\S+)"
    r"(?:\s+(?P<mode>\S+))?\s*$"
)

# Header separator line
_SEPARATOR = re.compile(r"^-{10,}$")


@register(OS.CISCO_IOSXE, "show meraki")
class ShowMerakiParser(BaseParser[ShowMerakiResult]):
    """Parser for 'show meraki' command.

    Shows Meraki cloud management registration status for each switch
    in the stack.

    Example output::

        Switch              Serial                        Migration
        Num  PID            Number       Meraki ID        Status    Mode
        ---------------------------------------------------------------
        1  C9300-48P        FJC2345T05A  Q5TE-5HWS-J3G8  Registered C9K-C
    """

    tags: ClassVar[frozenset[str]] = frozenset({"sdwan"})

    @classmethod
    def parse(cls, output: str) -> ShowMerakiResult:
        """Parse 'show meraki' output.

        Args:
            output: Raw CLI output from 'show meraki' command.

        Returns:
            Parsed Meraki registration data keyed by switch number.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        switches: dict[str, SwitchEntry] = {}
        past_header = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Detect separator line to know we've passed the header
            if _SEPARATOR.match(stripped):
                past_header = True
                continue

            if not past_header:
                continue

            match = _ENTRY_PATTERN.match(line)
            if not match:
                continue

            switch_num = match.group("switch_num")
            entry = SwitchEntry(
                pid=match.group("pid"),
                serial_number=match.group("serial"),
                meraki_id=match.group("meraki_id"),
                mac_address=match.group("mac"),
                registration_status=match.group("status"),
            )

            mode = match.group("mode")
            if mode:
                entry["mode"] = mode

            switches[switch_num] = entry

        if not switches:
            msg = "No Meraki switch entries found in output"
            raise ValueError(msg)

        return ShowMerakiResult(switches=switches)
