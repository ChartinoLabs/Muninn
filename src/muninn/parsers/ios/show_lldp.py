"""Parser for 'show lldp' command on Cisco IOS and IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowLldpResult(TypedDict):
    """Schema for 'show lldp' parsed output.

    Represents global LLDP configuration on the device. When LLDP is not
    enabled, only ``lldp_enabled`` is populated (set to ``False``).
    """

    lldp_enabled: bool
    status: NotRequired[str]
    hello_timer_seconds: NotRequired[int]
    hold_timer_seconds: NotRequired[int]
    reinit_delay_seconds: NotRequired[int]


# % LLDP is not enabled
_LLDP_NOT_ENABLED_RE = re.compile(
    r"^\s*%?\s*LLDP\s+is\s+not\s+enabled\s*$",
    re.IGNORECASE,
)

# Global LLDP Information:
_GLOBAL_HEADER_RE = re.compile(
    r"^\s*Global\s+LLDP\s+Information:\s*$",
    re.IGNORECASE,
)

# Status: ACTIVE
_STATUS_RE = re.compile(
    r"^\s*Status:\s+(?P<status>\S+)\s*$",
    re.IGNORECASE,
)

# LLDP advertisements are sent every 30 seconds
_HELLO_TIMER_RE = re.compile(
    r"^\s*LLDP\s+advertisements\s+are\s+sent\s+every\s+"
    r"(?P<value>\d+)\s+seconds?\s*$",
    re.IGNORECASE,
)

# LLDP hold time advertised is 120 seconds
_HOLD_TIMER_RE = re.compile(
    r"^\s*LLDP\s+hold\s+time\s+advertised\s+is\s+"
    r"(?P<value>\d+)\s+seconds?\s*$",
    re.IGNORECASE,
)

# LLDP interface reinitialisation delay is 2 seconds
_REINIT_DELAY_RE = re.compile(
    r"^\s*LLDP\s+interface\s+reinitiali[sz]ation\s+delay\s+is\s+"
    r"(?P<value>\d+)\s+seconds?\s*$",
    re.IGNORECASE,
)

# Maps an integer field name to its compiled regex.
_INT_FIELD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("hello_timer_seconds", _HELLO_TIMER_RE),
    ("hold_timer_seconds", _HOLD_TIMER_RE),
    ("reinit_delay_seconds", _REINIT_DELAY_RE),
)


def _try_int_field(line: str, result: ShowLldpResult) -> bool:
    """Try to match any integer ``_seconds`` field on the line.

    Returns ``True`` when a match is found and the field is written to
    ``result``.
    """
    for field, pattern in _INT_FIELD_PATTERNS:
        match = pattern.match(line)
        if match:
            result["lldp_enabled"] = True
            # field is one of three known NotRequired keys
            if field == "hello_timer_seconds":
                result["hello_timer_seconds"] = int(match.group("value"))
            elif field == "hold_timer_seconds":
                result["hold_timer_seconds"] = int(match.group("value"))
            else:
                result["reinit_delay_seconds"] = int(match.group("value"))
            return True
    return False


def _try_status_field(line: str, result: ShowLldpResult) -> bool:
    """Try to match the ``Status:`` line and write it to ``result``."""
    match = _STATUS_RE.match(line)
    if match:
        result["lldp_enabled"] = True
        result["status"] = match.group("status").upper()
        return True
    return False


def _has_any_enabled_field(result: ShowLldpResult) -> bool:
    """Return True if any enabled-state field has been written."""
    return (
        "status" in result
        or "hello_timer_seconds" in result
        or "hold_timer_seconds" in result
        or "reinit_delay_seconds" in result
    )


class _ParseState:
    """Mutable state tracked while walking ``show lldp`` output."""

    def __init__(self) -> None:
        self.saw_disabled = False
        self.saw_global_header = False


def _consume_line(line: str, result: ShowLldpResult, state: _ParseState) -> None:
    """Dispatch a single non-blank line to the appropriate field handler."""
    if _LLDP_NOT_ENABLED_RE.match(line):
        state.saw_disabled = True
        return
    if _GLOBAL_HEADER_RE.match(line):
        state.saw_global_header = True
        result["lldp_enabled"] = True
        return
    if _try_status_field(line, result):
        return
    _try_int_field(line, result)


@register(OS.CISCO_IOS, "show lldp")
@register(OS.CISCO_IOSXE, "show lldp")
class ShowLldpParser(BaseParser[ShowLldpResult]):
    """Parser for 'show lldp' command on Cisco IOS and IOS-XE.

    Parses global LLDP configuration. The command may report either that
    LLDP is not enabled (a single status line) or, when enabled, a block
    of global LLDP timer/status fields. The output format is identical
    across both IOS and IOS-XE platforms.

    Example output when enabled::

        Global LLDP Information:
            Status: ACTIVE
            LLDP advertisements are sent every 30 seconds
            LLDP hold time advertised is 120 seconds
            LLDP interface reinitialisation delay is 2 seconds

    Example output when disabled::

        % LLDP is not enabled
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    @classmethod
    def parse(cls, output: str) -> ShowLldpResult:
        """Parse 'show lldp' output.

        Args:
            output: Raw CLI output from 'show lldp' command.

        Returns:
            Parsed LLDP global configuration data.

        Raises:
            ValueError: If the output cannot be recognised as either an
                enabled-state or disabled-state ``show lldp`` response.
        """
        result: ShowLldpResult = {"lldp_enabled": False}
        state = _ParseState()

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if line.strip():
                _consume_line(line, result, state)

        recognised = (
            state.saw_disabled
            or state.saw_global_header
            or _has_any_enabled_field(result)
        )
        if not recognised:
            msg = "Output does not match 'show lldp' format"
            raise ValueError(msg)

        return result
