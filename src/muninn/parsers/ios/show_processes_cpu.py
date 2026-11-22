"""Parser for 'show processes cpu' command on IOS/IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# --- Summary line ---
# "CPU utilization for five seconds: 1%/0%; one minute: 2%; five minutes: 3%"
_CPU_UTIL_RE = re.compile(
    r"CPU utilization for five seconds:\s*(\d+)%/(\d+)%;"
    r"\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%"
)

# --- Optional "Load for five secs" line ---
# "Load for five secs: 1%/0%; one minute: 2%; five minutes: 3%"
_LOAD_RE = re.compile(
    r"Load for five secs:\s*(\d+)%/(\d+)%;"
    r"\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%"
)

# --- Optional time source line ---
# "Time source is NTP, 19:10:39.512 EST Mon Oct 17 2016"
_TIME_SOURCE_RE = re.compile(r"Time source is (\S+),\s*(.+?)\s*$")

# --- Process table row ---
# " PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process"
# "   1          15        1016         14  0.00%  0.00%  0.00%   0 Chunk Manager"
_PROCESS_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)"
    r"\s+(\d+\.\d+)%\s+(\d+\.\d+)%\s+(\d+\.\d+)%"
    r"\s+(\d+)\s+(.+?)\s*$"
)


class ProcessEntry(TypedDict):
    """Schema for a single process entry."""

    pid: int
    runtime_ms: int
    invoked: int
    usecs: int
    cpu_five_sec: float
    cpu_one_min: float
    cpu_five_min: float
    tty: int
    process: str


class ShowProcessesCpuResult(TypedDict):
    """Schema for 'show processes cpu' parsed output."""

    cpu_util_five_sec: int
    cpu_util_five_sec_interrupt: int
    cpu_util_one_min: int
    cpu_util_five_min: int
    load_five_sec: NotRequired[int]
    load_five_sec_interrupt: NotRequired[int]
    load_one_min: NotRequired[int]
    load_five_min: NotRequired[int]
    time_source: NotRequired[str]
    time: NotRequired[str]
    processes: dict[str, ProcessEntry]


def _parse_summary(lines: list[str], result: dict) -> None:
    """Parse the CPU utilization summary and optional load/time headers."""
    for line in lines:
        m = _CPU_UTIL_RE.search(line)
        if m:
            result["cpu_util_five_sec"] = int(m.group(1))
            result["cpu_util_five_sec_interrupt"] = int(m.group(2))
            result["cpu_util_one_min"] = int(m.group(3))
            result["cpu_util_five_min"] = int(m.group(4))
            continue

        m = _LOAD_RE.search(line)
        if m:
            result["load_five_sec"] = int(m.group(1))
            result["load_five_sec_interrupt"] = int(m.group(2))
            result["load_one_min"] = int(m.group(3))
            result["load_five_min"] = int(m.group(4))
            continue

        m = _TIME_SOURCE_RE.search(line)
        if m:
            result["time_source"] = m.group(1)
            result["time"] = m.group(2)


def _parse_processes(lines: list[str]) -> dict[str, ProcessEntry]:
    """Parse the process table rows into a dict keyed by PID string."""
    processes: dict[str, ProcessEntry] = {}
    for line in lines:
        m = _PROCESS_RE.match(line)
        if m:
            pid = int(m.group(1))
            processes[str(pid)] = {
                "pid": pid,
                "runtime_ms": int(m.group(2)),
                "invoked": int(m.group(3)),
                "usecs": int(m.group(4)),
                "cpu_five_sec": float(m.group(5)),
                "cpu_one_min": float(m.group(6)),
                "cpu_five_min": float(m.group(7)),
                "tty": int(m.group(8)),
                "process": m.group(9),
            }
    return processes


@register(OS.CISCO_IOS, "show processes cpu")
@register(OS.CISCO_IOSXE, "show processes cpu")
class ShowProcessesCpuParser(BaseParser["ShowProcessesCpuResult"]):
    """Parser for 'show processes cpu' on IOS/IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowProcessesCpuResult:
        """Parse 'show processes cpu' output."""
        lines = output.splitlines()
        result: dict = {}

        _parse_summary(lines, result)
        result["processes"] = _parse_processes(lines)

        return cast(ShowProcessesCpuResult, result)
