"""Parser for 'show processes cpu sorted' command on IOS/IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# --- Summary line ---
# "CPU utilization for five seconds: 77%/2%; one minute: 44%; five minutes: 39%"
_CPU_UTIL_RE = re.compile(
    r"CPU utilization for five seconds:\s*(\d+)%/(\d+)%;"
    r"\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%"
)

# --- Optional "Load for five secs" line ---
_LOAD_RE = re.compile(
    r"Load for five secs:\s*(\d+)%/(\d+)%;"
    r"\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%"
)

# --- Optional time source line ---
_TIME_SOURCE_RE = re.compile(r"Time source is (\S+),\s*(.+?)\s*$")

# --- Column header line ---
# " PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process"
_HEADER_RE = re.compile(r"^\s*PID\s+Runtime")

# --- Process table row ---
# " 193        3594        1241       2896 40.00%  5.08%  1.08%   2 SSH Process"
# The trailing process name may be empty when the entire name wraps to the
# next line; capture greedily and allow empty.
_PROCESS_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)"
    r"\s+(\d+\.\d+)%\s+(\d+\.\d+)%\s+(\d+\.\d+)%"
    r"\s+(\d+)\s*(.*)$"
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


class ShowProcessesCpuSortedResult(TypedDict):
    """Schema for 'show processes cpu sorted' parsed output."""

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


def _is_summary_or_header(line: str) -> bool:
    """Return True if the line is a header/summary, not a process row."""
    if _HEADER_RE.match(line):
        return True
    if _CPU_UTIL_RE.search(line):
        return True
    if _LOAD_RE.search(line):
        return True
    return bool(_TIME_SOURCE_RE.search(line))


def _parse_processes(lines: list[str]) -> dict[str, ProcessEntry]:
    """Parse process rows, joining wrapped process-name continuation lines.

    IOS terminal-width wrapping splits long process names across two lines.
    A continuation line is any non-empty line that does not match the
    process-row regex and is not a known header/summary line.
    """
    processes: dict[str, ProcessEntry] = {}
    last_pid: str | None = None

    for line in lines:
        m = _PROCESS_RE.match(line)
        if m:
            pid = int(m.group(1))
            key = str(pid)
            processes[key] = {
                "pid": pid,
                "runtime_ms": int(m.group(2)),
                "invoked": int(m.group(3)),
                "usecs": int(m.group(4)),
                "cpu_five_sec": float(m.group(5)),
                "cpu_one_min": float(m.group(6)),
                "cpu_five_min": float(m.group(7)),
                "tty": int(m.group(8)),
                "process": m.group(9).rstrip(),
            }
            last_pid = key
            continue

        # Continuation candidate: non-empty, not a header/summary.
        stripped = line.strip()
        if not stripped or last_pid is None:
            continue
        if _is_summary_or_header(line):
            continue

        existing = processes[last_pid]["process"]
        processes[last_pid]["process"] = (
            (existing + " " + stripped).strip() if existing else stripped
        )

    return processes


@register(OS.CISCO_IOS, "show processes cpu sorted")
@register(OS.CISCO_IOSXE, "show processes cpu sorted")
class ShowProcessesCpuSortedParser(BaseParser[ShowProcessesCpuSortedResult]):
    """Parser for 'show processes cpu sorted' on IOS/IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowProcessesCpuSortedResult:
        """Parse 'show processes cpu sorted' output."""
        lines = output.splitlines()
        result: dict = {}

        _parse_summary(lines, result)
        result["processes"] = _parse_processes(lines)

        # Validate required summary fields.
        for required in (
            "cpu_util_five_sec",
            "cpu_util_five_sec_interrupt",
            "cpu_util_one_min",
            "cpu_util_five_min",
        ):
            if required not in result:
                msg = f"Missing required field: {required}"
                raise ValueError(msg)

        return cast(ShowProcessesCpuSortedResult, result)
