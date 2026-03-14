"""Parser for 'show switch virtual' command on IOS.

Parses VSS (Virtual Switching System) status output, which reports
one or two member sections depending on whether the command is
executed from the active switch (showing both active and standby).
"""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class SwitchMemberEntry(TypedDict):
    """Schema for a single VSS member switch."""

    switch_mode: str
    domain_number: int
    operational_role: str
    peer_number: NotRequired[int]
    peer_operational_role: NotRequired[str]


class ShowSwitchVirtualResult(TypedDict):
    """Schema for 'show switch virtual' parsed output.

    Keyed by switch number (as string).
    """

    switches: dict[str, SwitchMemberEntry]


# --- Regex patterns ---

# Section header: "Executing the command on VSS member switch role = VSS Active, id = 1"
_SECTION_HEADER_RE = re.compile(
    r"^Executing the command on VSS member switch role\s*=\s*\S+\s+\S+,\s*id\s*=\s*\d+",
    re.IGNORECASE,
)

# Key-value lines (colon-separated)
_SWITCH_MODE_RE = re.compile(r"^\s*Switch\s+mode\s*:\s*(.+?)\s*$", re.IGNORECASE)
_DOMAIN_NUMBER_RE = re.compile(
    r"^\s*Virtual\s+switch\s+domain\s+number\s*:\s*(\d+)\s*$", re.IGNORECASE
)
_LOCAL_NUMBER_RE = re.compile(
    r"^\s*Local\s+switch\s+number\s*:\s*(\d+)\s*$", re.IGNORECASE
)
_LOCAL_ROLE_RE = re.compile(
    r"^\s*Local\s+switch\s+operational\s+role\s*:\s*(.+?)\s*$", re.IGNORECASE
)
_PEER_NUMBER_RE = re.compile(
    r"^\s*Peer\s+switch\s+number\s*:\s*(\d+)\s*$", re.IGNORECASE
)
_PEER_ROLE_RE = re.compile(
    r"^\s*Peer\s+switch\s+operational\s+role\s*:\s*(.+?)\s*$", re.IGNORECASE
)

# Ordered list of (regex, dict_key) for field extraction
_FIELD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_SWITCH_MODE_RE, "switch_mode"),
    (_DOMAIN_NUMBER_RE, "domain_number"),
    (_LOCAL_NUMBER_RE, "local_number"),
    (_LOCAL_ROLE_RE, "local_role"),
    (_PEER_NUMBER_RE, "peer_number"),
    (_PEER_ROLE_RE, "peer_role"),
]


def _extract_fields(lines: list[str]) -> dict[str, str]:
    """Extract key-value fields from a member section's lines."""
    fields: dict[str, str] = {}
    for line in lines:
        for pattern, key in _FIELD_PATTERNS:
            m = pattern.match(line)
            if m:
                fields[key] = m.group(1)
                break
    return fields


def _parse_member_section(lines: list[str]) -> tuple[str, SwitchMemberEntry] | None:
    """Parse a single member section and return (switch_number, entry) or None."""
    fields = _extract_fields(lines)

    # Validate required fields
    required = ("switch_mode", "domain_number", "local_number", "local_role")
    if not all(key in fields for key in required):
        return None

    entry: SwitchMemberEntry = {
        "switch_mode": fields["switch_mode"],
        "domain_number": int(fields["domain_number"]),
        "operational_role": fields["local_role"],
    }

    if "peer_number" in fields:
        entry["peer_number"] = int(fields["peer_number"])
    if "peer_role" in fields:
        entry["peer_operational_role"] = fields["peer_role"]

    return fields["local_number"], entry


def _split_sections(lines: list[str]) -> list[list[str]]:
    """Split output into per-member sections based on section headers."""
    sections: list[list[str]] = []
    current: list[str] = []

    for line in lines:
        if _SECTION_HEADER_RE.match(line):
            if current:
                sections.append(current)
            current = []
            continue
        current.append(line)

    if current:
        sections.append(current)

    return sections


@register(OS.CISCO_IOS, "show switch virtual")
class ShowSwitchVirtualParser(BaseParser[ShowSwitchVirtualResult]):
    """Parser for 'show switch virtual' on IOS.

    Example output::

        Executing the command on VSS member switch role = VSS Active, id = 1

        Switch mode                  : Virtual Switch
        Virtual switch domain number : 100
        Local switch number          : 1
        Local switch operational role: Virtual Switch Active
        Peer switch number           : 2
        Peer switch operational role : Virtual Switch Standby
    """

    @classmethod
    def parse(cls, output: str) -> ShowSwitchVirtualResult:
        """Parse 'show switch virtual' output.

        Args:
            output: Raw CLI output from 'show switch virtual' command.

        Returns:
            Parsed data with VSS member switch information.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        sections = _split_sections(lines)

        switches: dict[str, SwitchMemberEntry] = {}

        for section in sections:
            result = _parse_member_section(section)
            if result:
                switch_number, entry = result
                switches[switch_number] = entry

        if not switches:
            msg = "No VSS member switch entries found in output"
            raise ValueError(msg)

        return {"switches": switches}
