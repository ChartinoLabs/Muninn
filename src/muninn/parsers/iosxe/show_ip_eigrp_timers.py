"""Parser for 'show ip eigrp timers' command on IOS-XE."""

import re
from typing import Any, ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class TimerAttributes(TypedDict):
    """Schema for timer attributes."""

    expiration: float


class InterfaceTimers(TypedDict):
    """Schema for interface-scoped timers."""

    interfaces: dict[str, TimerAttributes]


class TimerEntries(TypedDict):
    """Schema for timers represented as repeated entries."""

    entries: list[TimerAttributes]


class EigrpProcessTimers(TypedDict):
    """Schema for timers within a single EIGRP process section."""

    timers: dict[str, InterfaceTimers | TimerEntries]


class EigrpInstanceTimers(TypedDict):
    """Schema for timers within a single EIGRP AS instance."""

    processes: dict[str, EigrpProcessTimers]


class ShowIpEigrpTimersResult(TypedDict):
    """Schema for 'show ip eigrp timers' parsed output."""

    instances: dict[str, EigrpInstanceTimers]


_COMMAND_LINE = "show ip eigrp timers"

_AS_PATTERN = re.compile(r"^EIGRP-IPv[46]\s+Timers\s+for\s+AS\((?P<as_number>\d+)\)")
_SECTION_PATTERN = re.compile(r"^(?P<section>Hello|Update|SIA)\s+Process$")
_TIMER_PATTERN = re.compile(r"^\|?\s+\|?\s*(?P<expiration>\d+\.\d+)\s+(?P<type>.+)$")
_INTERFACE_TIMER_PATTERN = re.compile(
    r"^(?P<timer_type>.+?)\s+\((?P<interface>[^()]+)\)$"
)


def _is_skip_line(line: str) -> bool:
    """Return True if the line should be skipped."""
    return not line or line.startswith("Expiration") or line == _COMMAND_LINE


class _ParserState:
    """Mutable state for the EIGRP timers parser."""

    def __init__(self) -> None:
        self.instances: dict[str, EigrpInstanceTimers] = {}
        self.current_as: str | None = None
        self.current_section: str | None = None


def _handle_as_line(match: re.Match[str], state: _ParserState) -> None:
    """Handle an AS header line."""
    state.current_as = match.group("as_number")
    state.instances[state.current_as] = EigrpInstanceTimers(processes={})
    state.current_section = None


def _handle_section_line(match: re.Match[str], state: _ParserState) -> None:
    """Handle a process section header line."""
    if state.current_as is None:
        return
    state.current_section = match.group("section").lower()
    processes = state.instances[state.current_as]["processes"]
    processes[state.current_section] = EigrpProcessTimers(timers={})


def _normalize_timer_name(timer_type: str) -> str:
    """Normalize timer names to snake_case keys."""
    return re.sub(r"[^a-z0-9]+", "_", timer_type.lower()).strip("_")


def _handle_timer_line(match: re.Match[str], state: _ParserState) -> None:
    """Handle a timer entry line."""
    if state.current_as is None or state.current_section is None:
        return
    timer_type = match.group("type").strip()
    timer_data = TimerAttributes(expiration=float(match.group("expiration")))
    processes = state.instances[state.current_as]["processes"]
    timers = processes[state.current_section]["timers"]

    interface_match = _INTERFACE_TIMER_PATTERN.match(timer_type)
    if interface_match and interface_match.group("interface") != "parent":
        timer_name = _normalize_timer_name(interface_match.group("timer_type"))
        interface = canonical_interface_name(
            interface_match.group("interface"), os=OS.CISCO_IOSXE
        )

        timers.setdefault(timer_name, InterfaceTimers(interfaces={}))
        intf_bucket: dict[str, Any] = timers[timer_name]
        intf_bucket["interfaces"][interface] = timer_data
        return

    timer_name = _normalize_timer_name(timer_type.strip("()"))
    timers.setdefault(timer_name, TimerEntries(entries=[]))
    entry_bucket: dict[str, Any] = timers[timer_name]
    entry_bucket["entries"].append(timer_data)


@register(OS.CISCO_IOSXE, "show ip eigrp timers")
class ShowIpEigrpTimersParser(BaseParser[ShowIpEigrpTimersResult]):
    """Parser for 'show ip eigrp timers' command.

    Example output:
        EIGRP-IPv4 Timers for AS(100)
          Hello Process
            Expiration    Type
        |           1.724  (parent)
          |           1.724  Hello (Te0/0/6.20)
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.EIGRP,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpEigrpTimersResult:
        """Parse 'show ip eigrp timers' output.

        Args:
            output: Raw CLI output from 'show ip eigrp timers'.

        Returns:
            Parsed timer data keyed by AS number, process, and timer type.

        Raises:
            ValueError: If no EIGRP timer data found in output.
        """
        state = _ParserState()

        for line in output.splitlines():
            stripped = line.strip()
            if _is_skip_line(stripped):
                continue

            as_match = _AS_PATTERN.match(stripped)
            if as_match:
                _handle_as_line(as_match, state)
                continue

            section_match = _SECTION_PATTERN.match(stripped)
            if section_match and state.current_as is not None:
                _handle_section_line(section_match, state)
                continue

            timer_match = _TIMER_PATTERN.match(stripped)
            if timer_match and state.current_section is not None:
                _handle_timer_line(timer_match, state)

        if not state.instances:
            msg = "No EIGRP timer data found in output"
            raise ValueError(msg)

        return ShowIpEigrpTimersResult(instances=state.instances)
