"""Parser for 'show processes cpu' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ProcessEntry(TypedDict):
    """Schema for a single process entry."""

    runtime_ms: int
    invoked: int
    usecs: int
    five_sec: float
    one_min: float
    five_min: float
    tty: NotRequired[str]


class ShowProcessesCpuResult(TypedDict):
    """Schema for 'show processes cpu' parsed output."""

    cpu_utilization_five_sec: int
    cpu_utilization_one_min: int
    cpu_utilization_five_min: int
    interrupt_percentage: int
    processes: dict[str, ProcessEntry]


@register(OS.CISCO_NXOS, "show processes cpu")
class ShowProcessesCpuParser(BaseParser[ShowProcessesCpuResult]):
    """Parser for 'show processes cpu' command on NX-OS.

    Example output:
        CPU utilization for five seconds: 15%/1%; one minute: 12%; five minutes: 10%
        PID    Runtime(ms)  Invoked   uSecs  5Sec    1Min    5Min    TTY  Process
            1         6170      1011      6   0.00%   0.00%  0.00%   -    init
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _SUMMARY_PATTERN = re.compile(
        r"CPU\s+utilization\s+for\s+five\s+seconds:\s+(?P<five_sec>\d+)%"
        r"/(?P<interrupt>\d+)%;\s+"
        r"one\s+minute:\s+(?P<one_min>\d+)%;\s+"
        r"five\s+minutes:\s+(?P<five_min>\d+)%"
    )

    _PROCESS_PATTERN = re.compile(
        r"^(?P<pid>\d+)\s+"
        r"(?P<runtime>\d+)\s+"
        r"(?P<invoked>\d+)\s+"
        r"(?P<usecs>\d+)\s+"
        r"(?P<five_sec>\d+\.\d+)%\s+"
        r"(?P<one_min>\d+\.\d+)%\s+"
        r"(?P<five_min>\d+\.\d+)%\s+"
        r"(?P<tty>\S+)\s+"
        r"(?P<process>.+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowProcessesCpuResult:
        """Parse 'show processes cpu' output on NX-OS.

        Args:
            output: Raw CLI output from 'show processes cpu' command.

        Returns:
            Parsed CPU utilization data and process entries.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        summary_found = False
        cpu_five_sec = 0
        cpu_one_min = 0
        cpu_five_min = 0
        interrupt_pct = 0
        processes: dict[str, ProcessEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            summary_match = cls._SUMMARY_PATTERN.search(line)
            if summary_match:
                cpu_five_sec = int(summary_match.group("five_sec"))
                interrupt_pct = int(summary_match.group("interrupt"))
                cpu_one_min = int(summary_match.group("one_min"))
                cpu_five_min = int(summary_match.group("five_min"))
                summary_found = True
                continue

            process_match = cls._PROCESS_PATTERN.match(line)
            if process_match:
                name = process_match.group("process").strip()
                entry: ProcessEntry = {
                    "runtime_ms": int(process_match.group("runtime")),
                    "invoked": int(process_match.group("invoked")),
                    "usecs": int(process_match.group("usecs")),
                    "five_sec": float(process_match.group("five_sec")),
                    "one_min": float(process_match.group("one_min")),
                    "five_min": float(process_match.group("five_min")),
                }

                tty = process_match.group("tty")
                if tty != "-":
                    entry["tty"] = tty

                pid = process_match.group("pid")
                processes[f"{pid}/{name}"] = entry

        if not summary_found:
            msg = "No CPU utilization summary found in output"
            raise ValueError(msg)

        return ShowProcessesCpuResult(
            cpu_utilization_five_sec=cpu_five_sec,
            cpu_utilization_one_min=cpu_one_min,
            cpu_utilization_five_min=cpu_five_min,
            interrupt_percentage=interrupt_pct,
            processes=processes,
        )
