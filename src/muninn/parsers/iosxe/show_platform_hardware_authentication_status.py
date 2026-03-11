"""Parser for 'show platform hardware authentication status' command on IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ComponentAuthEntry(TypedDict):
    """Schema for a single component's authentication status."""

    status: str


class SwitchEntry(TypedDict):
    """Schema for a switch containing component authentication entries."""

    components: dict[str, ComponentAuthEntry]


class ShowPlatformHardwareAuthenticationStatusResult(TypedDict):
    """Schema for 'show platform hardware authentication status' parsed output."""

    switches: dict[str, SwitchEntry]


# Switch header: "Switch 1:" or "Switch 2:"
_SWITCH_HEADER = re.compile(r"^Switch\s+(?P<num>\d+)\s*:\s*$")

# Authentication line:
#   "Mainboard Authentication:     Passed"
#   "Fan Tray Authentication:  pass"
#   "Line Card:1 Authentication:  pass"
#   "SUP 0 Authentication:  pass"
#   "SSD FRU Authentication:  Not Available"
_AUTH_LINE = re.compile(
    r"^\s*(?P<component>.+?)\s+Authentication:\s+(?P<status>.+?)\s*$"
)


def _parse_lines(
    lines: list[str],
) -> dict[str, SwitchEntry]:
    """Parse output lines into switches dict."""
    switches: dict[str, SwitchEntry] = {}
    current_switch = "1"

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Skip the command echo line
        if stripped.lower().startswith("show platform"):
            continue

        switch_match = _SWITCH_HEADER.match(stripped)
        if switch_match:
            current_switch = switch_match.group("num")
            continue

        auth_match = _AUTH_LINE.match(stripped)
        if auth_match:
            component = auth_match.group("component").strip()
            status = auth_match.group("status").strip()

            if current_switch not in switches:
                switches[current_switch] = SwitchEntry(components={})

            switches[current_switch]["components"][component] = ComponentAuthEntry(
                status=status,
            )

    return switches


@register(OS.CISCO_IOSXE, "show platform hardware authentication status")
class ShowPlatformHardwareAuthenticationStatusParser(
    BaseParser[ShowPlatformHardwareAuthenticationStatusResult],
):
    """Parser for 'show platform hardware authentication status' command.

    Example output::

        Switch 1:
            Mainboard Authentication:     Passed
            FRU Authentication:           Not Available
            Stack Cable A Authentication: Passed

    Or for chassis-based platforms::

           Fan Tray Authentication:  pass
        Line Card:1 Authentication:  pass
               SUP0 Authentication:  pass
    """

    @classmethod
    def parse(cls, output: str) -> ShowPlatformHardwareAuthenticationStatusResult:
        """Parse 'show platform hardware authentication status' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed hardware authentication status data keyed by switch.

        Raises:
            ValueError: If no authentication data is found.
        """
        lines = output.splitlines()
        switches = _parse_lines(lines)

        if not switches:
            msg = "No hardware authentication status data found in output"
            raise ValueError(msg)

        return ShowPlatformHardwareAuthenticationStatusResult(switches=switches)
