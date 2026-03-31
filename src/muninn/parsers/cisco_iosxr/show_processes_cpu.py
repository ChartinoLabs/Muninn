"""Parser for 'show processes cpu' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ProcessCpuEntry(TypedDict):
    """Schema for a single process CPU entry."""

    pid: int
    one_minute: float
    five_minutes: float
    fifteen_minutes: float


class ShowProcessesCpuResult(TypedDict):
    """Schema for 'show processes cpu' parsed output on IOS-XR."""

    cpu_utilization_one_minute: int
    cpu_utilization_five_minutes: int
    cpu_utilization_fifteen_minutes: int
    processes: dict[str, ProcessCpuEntry]


@register(OS.CISCO_IOSXR, "show processes cpu")
class ShowProcessesCpuParser(BaseParser[ShowProcessesCpuResult]):
    """Parser for 'show processes cpu' command on Cisco IOS-XR.

    Parses the CPU utilization summary line and per-process CPU usage table.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _SUMMARY_PATTERN = re.compile(
        r"CPU utilization for one minute:\s*(?P<one>\d+)%;\s*"
        r"five minutes:\s*(?P<five>\d+)%;\s*"
        r"fifteen minutes:\s*(?P<fifteen>\d+)%"
    )

    _PROCESS_PATTERN = re.compile(
        r"^(?P<pid>\d+)\s+"
        r"(?P<one>\d+)%\s+"
        r"(?P<five>\d+)%\s+"
        r"(?P<fifteen>\d+)%\s+"
        r"(?P<name>\S+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowProcessesCpuResult:
        """Parse 'show processes cpu' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed CPU utilization summary and per-process details.

        Raises:
            ValueError: If the CPU summary line cannot be found.
        """
        cpu_one = 0
        cpu_five = 0
        cpu_fifteen = 0
        summary_found = False
        processes: dict[str, ProcessCpuEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if not summary_found:
                match = cls._SUMMARY_PATTERN.search(stripped)
                if match:
                    cpu_one = int(match.group("one"))
                    cpu_five = int(match.group("five"))
                    cpu_fifteen = int(match.group("fifteen"))
                    summary_found = True
                    continue

            match = cls._PROCESS_PATTERN.match(stripped)
            if match:
                name = match.group("name")
                processes[name] = ProcessCpuEntry(
                    pid=int(match.group("pid")),
                    one_minute=float(match.group("one")),
                    five_minutes=float(match.group("five")),
                    fifteen_minutes=float(match.group("fifteen")),
                )

        if not summary_found:
            msg = "CPU utilization summary line not found in output"
            raise ValueError(msg)

        return ShowProcessesCpuResult(
            cpu_utilization_one_minute=cpu_one,
            cpu_utilization_five_minutes=cpu_five,
            cpu_utilization_fifteen_minutes=cpu_fifteen,
            processes=processes,
        )
