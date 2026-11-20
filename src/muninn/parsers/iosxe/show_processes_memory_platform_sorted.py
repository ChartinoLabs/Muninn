"""Parser for 'show processes memory platform sorted' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class SystemMemory(TypedDict):
    """Schema for the system memory summary header."""

    total_kb: int
    used_kb: int
    free_kb: int
    lowest_kb: NotRequired[int]


class ProcessEntry(TypedDict):
    """Schema for a single process row in the platform memory table."""

    text_kb: int
    data_kb: int
    stack_kb: int
    dynamic_kb: int
    rss_kb: int
    name: str


class ShowProcessesMemoryPlatformSortedResult(TypedDict):
    """Schema for 'show processes memory platform sorted' parsed output."""

    system_memory: SystemMemory
    processes: dict[str, ProcessEntry]


# System memory header line, e.g.:
# "System memory: 15985428K total, 3152816K used, 12832612K free,"
_SYSTEM_MEMORY_RE = re.compile(
    r"^System memory:\s+(?P<total>\d+)K\s+total,\s+"
    r"(?P<used>\d+)K\s+used,\s+"
    r"(?P<free>\d+)K\s+free"
)

# Lowest watermark line, e.g.: "Lowest: 12762084K"
_LOWEST_RE = re.compile(r"^Lowest:\s+(?P<lowest>\d+)K\s*$")

# Table header line, e.g.:
# "   Pid    Text       Data   Stack    Dynamic        RSS              Name"
_TABLE_HEADER_RE = re.compile(
    r"^\s*Pid\s+Text\s+Data\s+Stack\s+Dynamic\s+RSS\s+Name\s*$"
)

# Process table row: PID Text Data Stack Dynamic RSS Name
# Name may contain spaces, dots, slashes, etc. and may be truncated with a
# trailing period (e.g. "rollback_timer.").
_PROCESS_RE = re.compile(
    r"^\s*(?P<pid>\d+)"
    r"\s+(?P<text>\d+)"
    r"\s+(?P<data>\d+)"
    r"\s+(?P<stack>\d+)"
    r"\s+(?P<dynamic>\d+)"
    r"\s+(?P<rss>\d+)"
    r"\s+(?P<name>\S.*?)\s*$"
)


def _try_system_memory_line(line: str, system_memory: dict[str, int]) -> bool:
    """Update system_memory from a header line. Returns True if matched."""
    sys_match = _SYSTEM_MEMORY_RE.match(line)
    if sys_match:
        system_memory["total_kb"] = int(sys_match.group("total"))
        system_memory["used_kb"] = int(sys_match.group("used"))
        system_memory["free_kb"] = int(sys_match.group("free"))
        return True

    lowest_match = _LOWEST_RE.match(line)
    if lowest_match:
        system_memory["lowest_kb"] = int(lowest_match.group("lowest"))
        return True

    return False


def _try_process_line(line: str, processes: dict[str, ProcessEntry]) -> bool:
    """Insert a process entry parsed from line. Returns True if matched."""
    proc_match = _PROCESS_RE.match(line)
    if not proc_match:
        return False

    processes[proc_match.group("pid")] = {
        "text_kb": int(proc_match.group("text")),
        "data_kb": int(proc_match.group("data")),
        "stack_kb": int(proc_match.group("stack")),
        "dynamic_kb": int(proc_match.group("dynamic")),
        "rss_kb": int(proc_match.group("rss")),
        "name": proc_match.group("name"),
    }
    return True


@register(OS.CISCO_IOSXE, "show processes memory platform sorted")
class ShowProcessesMemoryPlatformSortedParser(
    BaseParser[ShowProcessesMemoryPlatformSortedResult]
):
    """Parser for 'show processes memory platform sorted' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.PLATFORM, ParserTag.SYSTEM}
    )

    @classmethod
    def parse(cls, output: str) -> ShowProcessesMemoryPlatformSortedResult:
        """Parse 'show processes memory platform sorted' output."""
        system_memory: dict[str, int] = {}
        processes: dict[str, ProcessEntry] = {}
        in_table = False

        for line in output.splitlines():
            if not line.strip():
                continue
            if SEPARATOR_DASH_RE.match(line):
                continue
            if _TABLE_HEADER_RE.match(line):
                in_table = True
                continue

            if in_table:
                _try_process_line(line, processes)
            else:
                _try_system_memory_line(line, system_memory)

        for required in ("total_kb", "used_kb", "free_kb"):
            if required not in system_memory:
                msg = f"Missing required system memory field: {required}"
                raise ValueError(msg)

        result: dict[str, object] = {
            "system_memory": system_memory,
            "processes": processes,
        }
        return cast(ShowProcessesMemoryPlatformSortedResult, result)
