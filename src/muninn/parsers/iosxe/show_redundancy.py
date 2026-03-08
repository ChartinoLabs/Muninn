"""Parser for 'show redundancy' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ProcessorEntry(TypedDict):
    """Schema for a single processor (active or standby)."""

    location: str
    software_state: str
    uptime_in_current_state: str
    image_version: str
    boot: NotRequired[str]
    config_file: NotRequired[str]
    bootldr: NotRequired[str]
    config_register: NotRequired[str]
    fast_switchover: NotRequired[str]
    initial_garp: NotRequired[str]


class ShowRedundancyResult(TypedDict):
    """Schema for 'show redundancy' parsed output."""

    available_system_uptime: str
    switchovers_system_experienced: int
    standby_failures: int
    last_switchover_reason: str
    hardware_mode: str
    configured_redundancy_mode: str
    operating_redundancy_mode: str
    maintenance_mode: str
    communications: str
    communications_reason: NotRequired[str]
    active: ProcessorEntry
    standby: NotRequired[ProcessorEntry]


# -- Section headers --

_CURRENT_PROCESSOR_HEADER = re.compile(
    r"^Current\s+Processor\s+Information", re.IGNORECASE
)
_PEER_PROCESSOR_HEADER = re.compile(
    r"^Peer\s+(?:\(slot:\s+\S+\)\s+information|Processor\s+Information)",
    re.IGNORECASE,
)
_PEER_UNAVAILABLE = re.compile(
    r"^Peer\s+\(slot:\s+\S+\)\s+information\s+is\s+not\s+available",
    re.IGNORECASE,
)

# -- System-level field patterns --

_SYSTEM_PATTERNS: tuple[tuple[re.Pattern[str], str, type], ...] = (
    (
        re.compile(r"^Available\s+system\s+uptime\s*=\s*(?P<value>.+)$", re.IGNORECASE),
        "available_system_uptime",
        str,
    ),
    (
        re.compile(
            r"^Switchovers\s+system\s+experienced\s*=\s*(?P<value>\d+)$", re.IGNORECASE
        ),
        "switchovers_system_experienced",
        int,
    ),
    (
        re.compile(r"^Standby\s+failures\s*=\s*(?P<value>\d+)$", re.IGNORECASE),
        "standby_failures",
        int,
    ),
    (
        re.compile(r"^Last\s+switchover\s+reason\s*=\s*(?P<value>.+)$", re.IGNORECASE),
        "last_switchover_reason",
        str,
    ),
    (
        re.compile(r"^Hardware\s+Mode\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "hardware_mode",
        str,
    ),
    (
        re.compile(
            r"^Configured\s+Redundancy\s+Mode\s*=\s*(?P<value>.+)$", re.IGNORECASE
        ),
        "configured_redundancy_mode",
        str,
    ),
    (
        re.compile(
            r"^Operating\s+Redundancy\s+Mode\s*=\s*(?P<value>.+)$", re.IGNORECASE
        ),
        "operating_redundancy_mode",
        str,
    ),
    (
        re.compile(r"^Maintenance\s+Mode\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "maintenance_mode",
        str,
    ),
    (
        re.compile(
            r"^Communications\s*=\s*(?P<value>\S+)(?:\s+Reason:\s*(?P<reason>.+))?$",
            re.IGNORECASE,
        ),
        "communications",
        str,
    ),
)

# -- Processor-level field patterns --

_PROCESSOR_PATTERNS: tuple[tuple[re.Pattern[str], str, type], ...] = (
    (
        re.compile(
            r"^(?:Active|Standby)\s+Location\s*=\s*(?P<value>.+)$", re.IGNORECASE
        ),
        "location",
        str,
    ),
    (
        re.compile(r"^Current\s+Software\s+state\s*=\s*(?P<value>.+)$", re.IGNORECASE),
        "software_state",
        str,
    ),
    (
        re.compile(
            r"^Uptime\s+in\s+current\s+state\s*=\s*(?P<value>.+)$", re.IGNORECASE
        ),
        "uptime_in_current_state",
        str,
    ),
    (
        re.compile(r"^Image\s+Version\s*=\s*(?P<value>.+)$", re.IGNORECASE),
        "image_version",
        str,
    ),
    (
        re.compile(r"^BOOT\s*=\s*(?P<value>.+)$", re.IGNORECASE),
        "boot",
        str,
    ),
    (
        re.compile(r"^CONFIG_FILE\s*=\s*(?P<value>.*)$", re.IGNORECASE),
        "config_file",
        str,
    ),
    (
        re.compile(r"^BOOTLDR\s*=\s*(?P<value>.*)$", re.IGNORECASE),
        "bootldr",
        str,
    ),
    (
        re.compile(r"^Configuration\s+register\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "config_register",
        str,
    ),
    (
        re.compile(r"^Fast\s+Switchover\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "fast_switchover",
        str,
    ),
    (
        re.compile(r"^Initial\s+Garp\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "initial_garp",
        str,
    ),
)

_SEPARATOR = re.compile(r"^-+$")


def _is_skip_line(line: str) -> bool:
    """Return True for lines that should be skipped."""
    if not line:
        return True
    if _SEPARATOR.match(line):
        return True
    if line.startswith("Copyright") or line.startswith("Compiled"):
        return True
    if line.startswith("Technical Support:"):
        return True
    return bool("#" in line[:50] and "show redundancy" in line.lower())


def _parse_system_section(lines: list[str], idx: int, result: dict[str, object]) -> int:
    """Parse the Redundant System Information section. Returns new index."""
    while idx < len(lines):
        line = lines[idx].strip()
        if _CURRENT_PROCESSOR_HEADER.match(line) or _PEER_PROCESSOR_HEADER.match(line):
            break
        if _is_skip_line(line):
            idx += 1
            continue
        for pattern, field, converter in _SYSTEM_PATTERNS:
            match = pattern.match(line)
            if match:
                value = match.group("value").strip()
                result[field] = converter(value)
                if field == "communications" and match.group("reason"):
                    result["communications_reason"] = match.group("reason").strip()
                break
        idx += 1
    return idx


_OPTIONAL_EMPTY_FIELDS = frozenset({"config_file", "bootldr"})


def _apply_processor_patterns(line: str, entry: dict[str, str]) -> None:
    """Try each processor pattern against line; set field on match."""
    for pattern, field, converter in _PROCESSOR_PATTERNS:
        match = pattern.match(line)
        if not match:
            continue
        value = match.group("value").strip()
        if not value and field in _OPTIONAL_EMPTY_FIELDS:
            return
        if value:
            entry[field] = converter(value)
        return


def _is_processor_boundary(line: str) -> bool:
    """Return True if line marks the start of a peer processor section."""
    return bool(_PEER_PROCESSOR_HEADER.match(line))


def _parse_processor_section(
    lines: list[str], idx: int
) -> tuple[int, ProcessorEntry | None]:
    """Parse a processor section (active or standby). Returns new index and entry."""
    entry: dict[str, str] = {}
    while idx < len(lines):
        line = lines[idx].strip()
        if _is_processor_boundary(line):
            break
        if _is_skip_line(line) or _CURRENT_PROCESSOR_HEADER.match(line):
            idx += 1
            continue
        _apply_processor_patterns(line, entry)
        idx += 1
    if not entry:
        return idx, None
    return idx, ProcessorEntry(**entry)  # type: ignore[typeddict-item]


@register(OS.CISCO_IOSXE, "show redundancy")
class ShowRedundancyParser(BaseParser[ShowRedundancyResult]):
    """Parser for 'show redundancy' command.

    Example output:
        Redundant System Information :
        Available system uptime = 15 hours, 4 minutes
        Hardware Mode = Duplex
        Communications = Up
    """

    @classmethod
    def parse(cls, output: str) -> ShowRedundancyResult:
        """Parse 'show redundancy' output.

        Args:
            output: Raw CLI output from 'show redundancy' command.

        Returns:
            Parsed redundancy data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        result: dict[str, object] = {}
        idx = 0

        # Parse system information section
        idx = _parse_system_section(lines, idx, result)

        # Parse current (active) processor section
        idx, active = _parse_processor_section(lines, idx)
        if active is None:
            msg = "No active processor information found in output"
            raise ValueError(msg)
        result["active"] = active

        # Parse peer (standby) processor section if present
        if idx < len(lines):
            line = lines[idx].strip()
            if _PEER_UNAVAILABLE.match(line):
                pass  # No standby info available
            elif _PEER_PROCESSOR_HEADER.match(line):
                idx += 1
                _, standby = _parse_processor_section(lines, idx)
                if standby is not None:
                    result["standby"] = standby

        _validate_required_fields(result)

        return ShowRedundancyResult(**result)  # type: ignore[typeddict-item]


def _validate_required_fields(result: dict[str, object]) -> None:
    """Validate that all required system-level fields were parsed."""
    required = (
        "available_system_uptime",
        "switchovers_system_experienced",
        "standby_failures",
        "last_switchover_reason",
        "hardware_mode",
        "configured_redundancy_mode",
        "operating_redundancy_mode",
        "maintenance_mode",
        "communications",
    )
    missing = [f for f in required if f not in result]
    if missing:
        msg = f"Missing required fields: {', '.join(missing)}"
        raise ValueError(msg)
