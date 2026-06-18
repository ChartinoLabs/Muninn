"""Parser for 'show ip ospf nsr' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

_RP_ROLE_RE = re.compile(r"^(?P<role>Active RP|Standby RP)\s*$")
_MODE_RE = re.compile(r"^\s+Operating in (?P<mode>\S+) mode\s*$")
_REDUNDANCY_STATE_RE = re.compile(r"^\s+Redundancy state:\s+(?P<state>.+?)\s*$")
_PEER_STATE_RE = re.compile(r"^\s+Peer redundancy state:\s+(?P<state>.+?)\s*$")
_CHECKPOINT_PEER_RE = re.compile(r"^\s+Checkpoint peer (?P<status>.+?)\s*$")
_CHECKPOINT_MSG_RE = re.compile(r"^\s+Checkpoint messages (?P<status>\S+)\s*$")
_ISSU_NEGOTIATION_RE = re.compile(r"^\s+ISSU negotiation (?P<status>.+?)\s*$")
_ISSU_VERSIONS_RE = re.compile(r"^\s+ISSU versions (?P<status>.+?)\s*$")
_PROCESS_RE = re.compile(
    r"^\s+Routing Process \"ospf (?P<pid>\d+)\""
    r" with ID (?P<router_id>" + IPV4_ADDRESS + r")\s*$"
)
_NSR_STATUS_RE = re.compile(r"^\s+NSR (?P<status>.+?)\s*$")

_HEADER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (_RP_ROLE_RE, "rp_role", "role"),
    (_MODE_RE, "operating_mode", "mode"),
    (_REDUNDANCY_STATE_RE, "redundancy_state", "state"),
    (_PEER_STATE_RE, "peer_redundancy_state", "state"),
    (_CHECKPOINT_PEER_RE, "checkpoint_peer_status", "status"),
    (_CHECKPOINT_MSG_RE, "checkpoint_messages", "status"),
    (_ISSU_NEGOTIATION_RE, "issu_negotiation", "status"),
    (_ISSU_VERSIONS_RE, "issu_versions", "status"),
]


class ProcessEntry(TypedDict):
    """Schema for a single OSPF process NSR entry."""

    router_id: str
    nsr_status: str


class ShowIpOspfNsrResult(TypedDict):
    """Schema for 'show ip ospf nsr' parsed output."""

    rp_role: str
    operating_mode: str
    redundancy_state: str
    peer_redundancy_state: str
    checkpoint_peer_status: str
    checkpoint_messages: str
    issu_negotiation: NotRequired[str]
    issu_versions: NotRequired[str]
    processes: dict[str, ProcessEntry]


def _try_header_line(line: str, result: dict[str, object]) -> bool:
    """Attempt to match a header/redundancy line."""
    for pattern, key, group in _HEADER_PATTERNS:
        m = pattern.match(line)
        if m:
            result[key] = m.group(group)
            return True
    return False


def _try_process_line(
    line: str,
    processes: dict[str, ProcessEntry],
    current_pid: str | None,
) -> str | None:
    """Attempt to match a process or NSR status line.

    Returns the current process ID (updated if a new process was found).
    """
    m = _PROCESS_RE.match(line)
    if m:
        pid = m.group("pid")
        processes[pid] = ProcessEntry(
            router_id=m.group("router_id"),
            nsr_status="",
        )
        return pid

    m = _NSR_STATUS_RE.match(line)
    if m and current_pid is not None:
        processes[current_pid]["nsr_status"] = m.group("status")

    return current_pid


@register(OS.CISCO_IOSXE, "show ip ospf nsr")
class ShowIpOspfNsrParser(BaseParser[ShowIpOspfNsrResult]):
    """Parser for 'show ip ospf nsr' on IOS-XE.

    Parses OSPF NSR (Non-Stop Routing) status including RP role,
    redundancy state, checkpoint/ISSU status, and per-process NSR
    configuration.

    Example output::

        Active RP
         Operating in simplex mode
         Redundancy state: ACTIVE
         Peer redundancy state: DISABLED
         Checkpoint peer not ready
         Checkpoint messages enabled
         ISSU negotiation not complete
         ISSU versions not compatible

         Routing Process "ospf 1" with ID 192.0.2.3
         NSR not configured
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.REDUNDANCY}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfNsrResult:
        """Parse 'show ip ospf nsr' output."""
        result: dict[str, object] = {}
        processes: dict[str, ProcessEntry] = {}
        current_pid: str | None = None

        for line in output.splitlines():
            if not line.strip():
                continue

            if _try_header_line(line, result):
                continue

            current_pid = _try_process_line(line, processes, current_pid)

        for required in (
            "rp_role",
            "operating_mode",
            "redundancy_state",
            "peer_redundancy_state",
            "checkpoint_peer_status",
            "checkpoint_messages",
        ):
            if required not in result:
                msg = f"Missing required field: {required}"
                raise ValueError(msg)

        if not processes:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        result["processes"] = processes
        return cast(ShowIpOspfNsrResult, result)
