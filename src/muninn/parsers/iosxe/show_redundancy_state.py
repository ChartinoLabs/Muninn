"""Parser for 'show redundancy state' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowRedundancyStateResult(TypedDict):
    """Schema for 'show redundancy state' parsed output."""

    my_state: str
    peer_state: str
    mode: str
    unit: str
    unit_id: int
    redundancy_mode_operational: str
    redundancy_mode_configured: str
    redundancy_state: str
    maintenance_mode: str
    manual_swact: str
    communications: str
    communications_reason: NotRequired[str]
    client_count: int
    client_notification_tmr_milliseconds: int
    rf_debug_mask: str


# Communications has a special 'reason' group so is handled separately.
_COMMUNICATIONS_RE = re.compile(
    r"^\s*Communications\s*=\s*(?P<value>\S+)"
    r"(?:\s+Reason:\s*(?P<reason>.+))?$",
    re.IGNORECASE,
)

# Pattern table: (compiled regex, field name, type converter).
# Each regex must have a named group 'value'.
_PATTERNS: tuple[tuple[re.Pattern[str], str, type], ...] = (
    (
        re.compile(r"^\s*my\s+state\s*=\s*\d+\s*-(?P<value>.+)$", re.IGNORECASE),
        "my_state",
        str,
    ),
    (
        re.compile(r"^\s*peer\s+state\s*=\s*\d+\s*-(?P<value>.+)$", re.IGNORECASE),
        "peer_state",
        str,
    ),
    (
        re.compile(r"^\s*Mode\s*=\s*(?P<value>.+)$"),
        "mode",
        str,
    ),
    (
        re.compile(r"^\s*Unit\s*=\s*(?P<value>.+)$"),
        "unit",
        str,
    ),
    (
        re.compile(r"^\s*Unit\s+ID\s*=\s*(?P<value>\d+)$"),
        "unit_id",
        int,
    ),
    (
        re.compile(
            r"^\s*Redundancy\s+Mode\s+\(Operational\)\s*=\s*(?P<value>.+)$",
            re.IGNORECASE,
        ),
        "redundancy_mode_operational",
        str,
    ),
    (
        re.compile(
            r"^\s*Redundancy\s+Mode\s+\(Configured\)\s*=\s*(?P<value>.+)$",
            re.IGNORECASE,
        ),
        "redundancy_mode_configured",
        str,
    ),
    (
        re.compile(r"^\s*Redundancy\s+State\s*=\s*(?P<value>.+)$", re.IGNORECASE),
        "redundancy_state",
        str,
    ),
    (
        re.compile(r"^\s*Maintenance\s+Mode\s*=\s*(?P<value>.+)$", re.IGNORECASE),
        "maintenance_mode",
        str,
    ),
    (
        re.compile(r"^\s*Manual\s+Swact\s*=\s*(?P<value>.+)$", re.IGNORECASE),
        "manual_swact",
        str,
    ),
    (
        re.compile(r"^\s*client\s+count\s*=\s*(?P<value>\d+)$", re.IGNORECASE),
        "client_count",
        int,
    ),
    (
        re.compile(
            r"^\s*client_notification_TMR\s*=\s*"
            r"(?P<value>\d+)\s*milliseconds$",
            re.IGNORECASE,
        ),
        "client_notification_tmr_milliseconds",
        int,
    ),
    (
        re.compile(r"^\s*RF\s+debug\s+mask\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "rf_debug_mask",
        str,
    ),
)


@register(OS.CISCO_IOSXE, "show redundancy state")
class ShowRedundancyStateParser(BaseParser[ShowRedundancyStateResult]):
    """Parser for 'show redundancy state' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.REDUNDANCY, ParserTag.SYSTEM}
    )

    @classmethod
    def parse(cls, output: str) -> ShowRedundancyStateResult:
        """Parse 'show redundancy state' output.

        Args:
            output: Raw CLI output from 'show redundancy state' command.

        Returns:
            Parsed redundancy state data.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        result: dict[str, str | int] = {}

        for line in output.splitlines():
            _try_pattern_table(line, result)
            _try_communications(line, result)

        _validate_required_fields(result)
        return cast(ShowRedundancyStateResult, result)


def _try_pattern_table(line: str, result: dict[str, str | int]) -> None:
    """Match line against the pattern table and store any hit."""
    for pattern, field, converter in _PATTERNS:
        match = pattern.match(line)
        if match:
            value = match.group("value").strip()
            result[field] = converter(value)
            return


def _try_communications(line: str, result: dict[str, str | int]) -> None:
    """Handle the communications line which has an optional reason group."""
    if "communications" in result:
        return
    match = _COMMUNICATIONS_RE.match(line)
    if match:
        result["communications"] = match.group("value").strip()
        if match.group("reason"):
            result["communications_reason"] = match.group("reason").strip()


def _validate_required_fields(result: dict[str, str | int]) -> None:
    """Validate that all required fields were parsed."""
    required = (
        "my_state",
        "peer_state",
        "mode",
        "unit",
        "unit_id",
        "redundancy_mode_operational",
        "redundancy_mode_configured",
        "redundancy_state",
        "maintenance_mode",
        "manual_swact",
        "communications",
        "client_count",
        "client_notification_tmr_milliseconds",
        "rf_debug_mask",
    )
    missing = [f for f in required if f not in result]
    if missing:
        msg = f"Missing required fields: {', '.join(missing)}"
        raise ValueError(msg)
