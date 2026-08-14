"""Parser for 'show failover state' command on Cisco FTD."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FailoverHostEntry(TypedDict):
    """Schema for a single failover host (this or other)."""

    role: str
    state: str
    last_failure_reason: NotRequired[str]
    last_failure_time: NotRequired[str]


class ShowFailoverStateResult(TypedDict):
    """Schema for 'show failover state' parsed output on Cisco FTD."""

    this_host: FailoverHostEntry
    other_host: FailoverHostEntry
    configuration_state: str
    communication_state: str


@register(OS.CISCO_FTD, "show failover state")
class ShowFailoverStateParser(BaseParser[ShowFailoverStateResult]):
    """Parser for 'show failover state' command on Cisco FTD.

    Parses failover state including host roles, states, failure reasons,
    and configuration/communication synchronization status.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    _HOST_RE = re.compile(
        r"^(?P<host>This host|Other host)\s+-\s+(?P<role>Primary|Secondary)\s*$"
    )
    _STATE_RE = re.compile(
        r"^\s+(?P<state>Active|Standby Ready|Standby|Cold Standby|Failed|"
        r"Negotiation|Disabled|Not Detected)"
        r"(?:\s{2,}(?P<reason>.+?)(?:\s{2,}(?P<time>\S+.*))?)?$"
    )
    _CONFIG_STATE_RE = re.compile(r"^====Configuration State===\s*$")
    _COMM_STATE_RE = re.compile(r"^====Communication State===\s*$")

    @classmethod
    def _find_state_match(
        cls, lines: list[str], start_idx: int
    ) -> tuple[re.Match[str], int]:
        """Skip blank lines after a host header and return the state match.

        Returns the regex match object and the index of the state line.

        Raises:
            ValueError: If no state line is found or it cannot be parsed.
        """
        idx = start_idx + 1

        while idx < len(lines) and not lines[idx].strip():
            idx += 1

        if idx >= len(lines):
            msg = f"No state line found for host at line {start_idx}"
            raise ValueError(msg)

        state_match = cls._STATE_RE.match(lines[idx])
        if not state_match:
            msg = f"Cannot parse state line: {lines[idx]!r}"
            raise ValueError(msg)

        return state_match, idx

    @staticmethod
    def _extract_failure_fields(state_match: re.Match[str]) -> dict[str, str]:
        """Extract optional failure reason and time from a state match.

        Returns a dict with 'last_failure_reason' and/or 'last_failure_time'
        if present and non-empty.
        """
        fields: dict[str, str] = {}

        reason = state_match.group("reason")
        if reason and reason.strip() and reason.strip() != "None":
            fields["last_failure_reason"] = reason.strip()

        time_str = state_match.group("time")
        if time_str and time_str.strip():
            fields["last_failure_time"] = time_str.strip()

        return fields

    @classmethod
    def _parse_host_block(
        cls, lines: list[str], start_idx: int
    ) -> tuple[FailoverHostEntry, int]:
        """Parse a host block starting at the host header line.

        Returns the parsed entry and the index after the state line.
        """
        host_match = cls._HOST_RE.match(lines[start_idx])
        if not host_match:
            msg = f"Expected host header at line {start_idx}"
            raise ValueError(msg)

        state_match, state_idx = cls._find_state_match(lines, start_idx)

        entry: FailoverHostEntry = {
            "role": host_match.group("role"),
            "state": state_match.group("state"),
            **cls._extract_failure_fields(state_match),
        }

        return entry, state_idx + 1

    @classmethod
    def _parse_section_value(cls, lines: list[str], start_idx: int) -> str:
        """Parse the value line following a section header.

        Returns the stripped text content.
        """
        idx = start_idx + 1
        while idx < len(lines) and not lines[idx].strip():
            idx += 1

        if idx >= len(lines):
            msg = f"No value found after section header at line {start_idx}"
            raise ValueError(msg)

        return lines[idx].strip()

    @classmethod
    def parse(cls, output: str) -> ShowFailoverStateResult:
        """Parse 'show failover state' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed failover state information including host roles, states,
            and synchronization status.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        lines = output.splitlines()
        this_host: FailoverHostEntry | None = None
        other_host: FailoverHostEntry | None = None
        configuration_state: str | None = None
        communication_state: str | None = None

        idx = 0
        while idx < len(lines):
            line = lines[idx]

            host_match = cls._HOST_RE.match(line)
            if host_match:
                host_label = host_match.group("host")
                entry, idx = cls._parse_host_block(lines, idx)
                if host_label == "This host":
                    this_host = entry
                else:
                    other_host = entry
                continue

            if cls._CONFIG_STATE_RE.match(line):
                configuration_state = cls._parse_section_value(lines, idx)
                idx += 1
                continue

            if cls._COMM_STATE_RE.match(line):
                communication_state = cls._parse_section_value(lines, idx)
                idx += 1
                continue

            idx += 1

        if this_host is None:
            msg = "Failed to parse 'This host' block"
            raise ValueError(msg)
        if other_host is None:
            msg = "Failed to parse 'Other host' block"
            raise ValueError(msg)
        if configuration_state is None:
            msg = "Failed to parse configuration state"
            raise ValueError(msg)
        if communication_state is None:
            msg = "Failed to parse communication state"
            raise ValueError(msg)

        return ShowFailoverStateResult(
            this_host=this_host,
            other_host=other_host,
            configuration_state=configuration_state,
            communication_state=communication_state,
        )
