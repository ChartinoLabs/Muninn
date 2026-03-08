"""Parser for 'show processes' command on NX-OS."""

import re
from typing import NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ProcessEntry(TypedDict):
    """Schema for a single process entry."""

    state: str
    type: str
    start_cnt: int
    pid: NotRequired[int]
    pc: NotRequired[str]
    tty: NotRequired[int]


class ShowProcessesResult(TypedDict):
    """Schema for 'show processes' parsed output."""

    processes: dict[str, ProcessEntry]


_RUNNING_PATTERN = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<state>\S+)\s+(?P<pc>\S+)\s+"
    r"(?P<start_cnt>\d+)\s+(?P<tty>\S+)\s+(?P<type>\S+)\s+(?P<process>\S+)\s*$"
)

_NOT_RUNNING_PATTERN = re.compile(
    r"^\s*-\s+(?P<state>\S+)\s+(?:-)\s+"
    r"(?P<start_cnt>\d+)\s+(?P<tty>\S+)\s+(?P<type>\S+)\s+(?P<process>\S+)\s*$"
)


@register(OS.CISCO_NXOS, "show processes")
class ShowProcessesParser(BaseParser[ShowProcessesResult]):
    """Parser for 'show processes' command.

    Example output:
        PID    State  PC        Start_cnt    TTY   Type  Process
        -----  -----  --------  -----------  ----  ----  -------------
            1      S  b8dffed3            1     -     O  init
            -     NR         -            0     -     X  ldap
    """

    @classmethod
    def parse(cls, output: str) -> ShowProcessesResult:
        """Parse 'show processes' output.

        Args:
            output: Raw CLI output from 'show processes' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        processes: dict[str, ProcessEntry] = {}

        for line in output.splitlines():
            match = _RUNNING_PATTERN.match(line)
            if match:
                name = match.group("process")
                entry = ProcessEntry(
                    state=match.group("state"),
                    type=match.group("type"),
                    start_cnt=int(match.group("start_cnt")),
                    pid=int(match.group("pid")),
                    pc=match.group("pc"),
                )
                tty = match.group("tty")
                if tty != "-":
                    entry["tty"] = int(tty)
                processes[name] = entry
                continue

            match = _NOT_RUNNING_PATTERN.match(line)
            if match:
                name = match.group("process")
                entry = ProcessEntry(
                    state=match.group("state"),
                    type=match.group("type"),
                    start_cnt=int(match.group("start_cnt")),
                )
                tty = match.group("tty")
                if tty != "-":
                    entry["tty"] = int(tty)
                processes[name] = entry

        if not processes:
            msg = "No process entries found in output"
            raise ValueError(msg)

        return cast(ShowProcessesResult, {"processes": processes})
