"""Parser for 'show platform software yang-management process' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ProcessEntry(TypedDict):
    """Schema for a single YANG management process."""

    status: str


class ShowPlatformSoftwareYangManagementProcessResult(TypedDict):
    """Schema for 'show platform software yang-management process' parsed output."""

    processes: dict[str, ProcessEntry]


# confd            : Running
# gnmib            : Not Running
_PROCESS_LINE = re.compile(r"^(?P<name>\S+)\s*:\s*(?P<status>Running|Not Running)\s*$")


@register(OS.CISCO_IOSXE, "show platform software yang-management process")
class ShowPlatformSoftwareYangManagementProcessParser(
    BaseParser[ShowPlatformSoftwareYangManagementProcessResult],
):
    """Parser for 'show platform software yang-management process' command.

    Parses YANG management process names and their running status.

    Example output::

        confd            : Running
        nesd             : Running
        syncfd           : Running
        ncsshd           : Running
        dmiauthd         : Running
        nginx            : Running
        ndbmand          : Running
        pubd             : Running
        gnmib            : Not Running
    """

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareYangManagementProcessResult:
        """Parse 'show platform software yang-management process' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed process data keyed by process name.

        Raises:
            ValueError: If no YANG management process data is found.
        """
        processes: dict[str, ProcessEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := _PROCESS_LINE.match(stripped):
                name = match.group("name")
                processes[name] = ProcessEntry(status=match.group("status"))

        if not processes:
            msg = "No YANG management process data found in output"
            raise ValueError(msg)

        return ShowPlatformSoftwareYangManagementProcessResult(processes=processes)
