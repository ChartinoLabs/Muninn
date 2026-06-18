"""Parser for 'show ip ospf nsf' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_PROCESS_RE = re.compile(r'^\s*Routing Process "ospf (?P<pid>\d+)"')
_IETF_NSF_RE = re.compile(r"^\s*IETF NSF helper support (?P<state>\S+)")
_CISCO_NSF_RE = re.compile(r"^\s*Cisco NSF helper support (?P<state>\S+)")
_RESTART_STATE_RE = re.compile(r"^\s*OSPF restart state is (?P<state>.+)")
_HANDLE_RE = re.compile(
    r"^\s*Handle (?P<handle>\d+),\s*"
    r"Router ID (?P<router_id>\S+),\s*"
    r"checkpoint Router ID (?P<checkpoint_router_id>\S+)"
)
_CONFIG_WAIT_RE = re.compile(
    r"^\s*Config wait timer interval (?P<interval>\d+),\s*"
    r"timer (?P<state>.+)"
)
_DBASE_WAIT_RE = re.compile(
    r"^\s*Dbase wait timer interval (?P<interval>\d+),\s*"
    r"timer (?P<state>.+)"
)


class NsfProcessEntry(TypedDict):
    """Schema for a single OSPF process NSF entry."""

    ietf_nsf_helper: bool
    cisco_nsf_helper: bool
    restart_state: str
    router_id: str
    checkpoint_router_id: NotRequired[str]
    handle: NotRequired[str]
    config_wait_timer_interval: int
    config_wait_timer_running: bool
    dbase_wait_timer_interval: int
    dbase_wait_timer_running: bool


class ShowIpOspfNsfResult(TypedDict):
    """Schema for 'show ip ospf nsf' parsed output."""

    processes: dict[str, NsfProcessEntry]


def _try_nsf_helpers(line: str, entry: dict) -> bool:
    """Try to parse IETF/Cisco NSF helper lines."""
    match = _IETF_NSF_RE.match(line)
    if match:
        entry["ietf_nsf_helper"] = match.group("state").lower() == "enabled"
        return True

    match = _CISCO_NSF_RE.match(line)
    if match:
        entry["cisco_nsf_helper"] = match.group("state").lower() == "enabled"
        return True

    return False


def _try_restart_and_handle(line: str, entry: dict) -> bool:
    """Try to parse restart state and handle/router-ID lines."""
    match = _RESTART_STATE_RE.match(line)
    if match:
        entry["restart_state"] = match.group("state").strip()
        return True

    match = _HANDLE_RE.match(line)
    if match:
        entry["handle"] = match.group("handle")
        entry["router_id"] = match.group("router_id")
        checkpoint = match.group("checkpoint_router_id")
        if checkpoint != "0.0.0.0":
            entry["checkpoint_router_id"] = checkpoint
        return True

    return False


def _try_timers(line: str, entry: dict) -> bool:
    """Try to parse config/dbase wait timer lines."""
    match = _CONFIG_WAIT_RE.match(line)
    if match:
        entry["config_wait_timer_interval"] = int(match.group("interval"))
        entry["config_wait_timer_running"] = "not running" not in match.group("state")
        return True

    match = _DBASE_WAIT_RE.match(line)
    if match:
        entry["dbase_wait_timer_interval"] = int(match.group("interval"))
        entry["dbase_wait_timer_running"] = "not running" not in match.group("state")
        return True

    return False


def _dispatch_line(line: str, entry: dict) -> None:
    """Route a single line to the appropriate field-extraction helper."""
    if _try_nsf_helpers(line, entry):
        return
    if _try_restart_and_handle(line, entry):
        return
    _try_timers(line, entry)


def _parse_processes(output: str) -> dict[str, NsfProcessEntry]:
    """Split output into per-process sections and parse each."""
    processes: dict[str, NsfProcessEntry] = {}
    current_pid: str | None = None
    current: dict = {}

    for line in output.splitlines():
        match = _PROCESS_RE.match(line)
        if match:
            if current_pid is not None and current:
                processes[current_pid] = cast(NsfProcessEntry, current)
            current_pid = match.group("pid")
            current = {}
        else:
            _dispatch_line(line, current)

    if current_pid is not None and current:
        processes[current_pid] = cast(NsfProcessEntry, current)

    return processes


@register(OS.CISCO_IOSXE, "show ip ospf nsf")
class ShowIpOspfNsfParser(BaseParser[ShowIpOspfNsfResult]):
    """Parser for 'show ip ospf nsf' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfNsfResult:
        """Parse 'show ip ospf nsf' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed NSF data keyed by OSPF process ID.

        Raises:
            ValueError: If no OSPF processes found.
        """
        processes = _parse_processes(output)

        if not processes:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfNsfResult, {"processes": processes})
