"""Parser for 'show redundancy config-sync failures mcl' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

_EMPTY_LIST = re.compile(r"^The\s+list\s+is\s+Empty$", re.IGNORECASE)
_HEADER = re.compile(r"^Mismatched\s+Command\s+List$", re.IGNORECASE)
_SEPARATOR = re.compile(r"^-+$")

# Max characters to scan for command echo prompt marker
_PROMPT_SCAN_LIMIT = 50


class ShowRedundancyConfigSyncFailuresMclResult(TypedDict):
    """Schema for 'show redundancy config-sync failures mcl' parsed output."""

    failures: list[str]


def _is_skip_line(line: str) -> bool:
    """Return True for lines that carry no MCL data."""
    if not line:
        return True
    if _SEPARATOR.match(line):
        return True
    return "#" in line[:_PROMPT_SCAN_LIMIT] and "show redundancy" in line.lower()


def _extract_failures(lines: list[str]) -> ShowRedundancyConfigSyncFailuresMclResult:
    """Walk lines after the header and collect MCL failure entries.

    Returns:
        Parsed result with failure lines (empty list if device reports no failures).

    Raises:
        ValueError: If no header is found.
    """
    header_found = False
    failures: list[str] = []

    for line in lines:
        stripped = line.strip()

        if _is_skip_line(stripped):
            continue

        if _HEADER.match(stripped):
            header_found = True
            continue

        if _EMPTY_LIST.match(stripped):
            return ShowRedundancyConfigSyncFailuresMclResult(failures=[])

        if header_found:
            failures.append(stripped)

    if not header_found:
        msg = "No 'Mismatched Command List' header found in output"
        raise ValueError(msg)

    return ShowRedundancyConfigSyncFailuresMclResult(failures=failures)


@register(OS.CISCO_IOSXE, "show redundancy config-sync failures mcl")
class ShowRedundancyConfigSyncFailuresMclParser(
    BaseParser[ShowRedundancyConfigSyncFailuresMclResult],
):
    """Parser for 'show redundancy config-sync failures mcl' command.

    Displays mismatched command list (MCL) entries from config-sync failures.

    Example output (empty):
        Mismatched Command List
        -----------------------

        The list is Empty

    Example output (with failures):
        Mismatched Command List
        -----------------------
        00:06:31: Config Sync: Starting lines from MCL file:
        interface GigabitEthernet7/7
        ! <submode> "interface"
        - ip address 192.0.2.0 255.255.255.0
        ! </submode> "interface"
    """

    tags: ClassVar[frozenset[str]] = frozenset({"redundancy", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowRedundancyConfigSyncFailuresMclResult:
        """Parse 'show redundancy config-sync failures mcl' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed MCL failure data with a list of failure lines.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        return _extract_failures(output.splitlines())
