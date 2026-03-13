"""Parser for 'show platform software meraki-service' command on IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ProcessEntry(TypedDict):
    """Schema for a single Meraki process status."""

    running: bool


class ShowPlatformSoftwareMerakiServiceResult(TypedDict):
    """Schema for 'show platform software meraki-service' parsed output.

    Keyed by process name (e.g., "meraki_mgrd", "meraki_tunnel_client").
    Each entry contains a boolean indicating whether the process is running.
    """

    processes: dict[str, ProcessEntry]


# Pattern matches lines like:
#   Meraki Mgrd                    : Running
#   Nextunnel Packet Capture       : Not Running
_PROCESS_LINE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9 ]+?)\s*:\s*(?P<status>.+)$")

# Header and separator lines to skip
_HEADER_LINE = re.compile(r"^Meraki Process Summary", re.IGNORECASE)
_SEPARATOR_LINE = re.compile(r"^-+$")


def _normalize_name(name: str) -> str:
    """Convert a display name to a snake_case key.

    Example: "Meraki Mgrd" -> "meraki_mgrd"
    """
    return name.strip().lower().replace(" ", "_")


def _is_running(status: str) -> bool:
    """Determine if a process status indicates running."""
    return status.strip().lower() == "running"


@register(OS.CISCO_IOSXE, "show platform software meraki-service")
class ShowPlatformSoftwareMerakiServiceParser(
    BaseParser[ShowPlatformSoftwareMerakiServiceResult],
):
    """Parser for 'show platform software meraki-service' command.

    Parses the Meraki process summary output into structured data keyed
    by process name.

    Example output:
        Meraki Process Summary:
        ----------------------------------------------
        Meraki Mgrd                    : Running
        Meraki Tunnel Client           : Running
        IOS Console Service            : Running
        Nextunnel Packet Capture       : Not Running
    """

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareMerakiServiceResult:
        """Parse 'show platform software meraki-service' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed process status data keyed by normalized process name.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        processes: dict[str, ProcessEntry] = {}

        for line in output.splitlines():
            line = line.strip()

            if not line:
                continue

            if _HEADER_LINE.match(line) or _SEPARATOR_LINE.match(line):
                continue

            match = _PROCESS_LINE.match(line)
            if match:
                name = _normalize_name(match.group("name"))
                status = match.group("status")
                processes[name] = ProcessEntry(running=_is_running(status))

        if not processes:
            msg = "No Meraki process information found in output"
            raise ValueError(msg)

        return ShowPlatformSoftwareMerakiServiceResult(processes=processes)
