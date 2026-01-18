"""Parser for 'show mac address-table aging-time' command on NX-OS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowMacAddressTableAgingTimeResult(TypedDict):
    """Schema for 'show mac address-table aging-time' parsed output."""

    mac_aging_time: int


@register(OS.CISCO_NXOS, "show mac address-table aging-time")
class ShowMacAddressTableAgingTimeParser(
    BaseParser[ShowMacAddressTableAgingTimeResult]
):
    """Parser for 'show mac address-table aging-time' command."""

    _VALUE_PATTERN = re.compile(r"^(?P<value>\d+)$")

    @classmethod
    def parse(cls, output: str) -> ShowMacAddressTableAgingTimeResult:
        """Parse 'show mac address-table aging-time' output.

        Args:
            output: Raw CLI output from 'show mac address-table aging-time' command.

        Returns:
            Parsed aging-time data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._VALUE_PATTERN.match(line)
            if match:
                return ShowMacAddressTableAgingTimeResult(
                    mac_aging_time=int(match.group("value"))
                )

        msg = "No aging-time value found"
        raise ValueError(msg)
