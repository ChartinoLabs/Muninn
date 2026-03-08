"""Parser for 'show processes memory sorted' command on IOS."""

import re
from typing import NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PoolSummary(TypedDict):
    """Schema for a memory pool summary."""

    total: int
    used: int
    free: int


class ProcessAttributes(TypedDict):
    """Schema for a single process memory entry."""

    tty: int
    allocated: int
    freed: int
    holding: int
    getbufs: int
    retbufs: int


class ShowProcessesMemorySortedResult(TypedDict):
    """Schema for 'show processes memory sorted' parsed output.

    Top-level keys include dynamically named pool summaries
    (e.g., processor_pool, io_pool, lsmpi_io_pool)
    and a processes dict keyed by PID string.
    """

    processes: NotRequired[dict[str, dict[str, ProcessAttributes]]]


# Pool summary line: "Processor Pool Total: X Used: Y Free: Z"
_POOL_RE = re.compile(
    r"^\s*(.+?)\s+Pool\s+Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)\s*$"
)

# Process table row: PID TTY Allocated Freed Holding Getbufs Retbufs Process
_PROCESS_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$"
)

# Header line to skip
_HEADER_RE = re.compile(r"^\s*PID\s+TTY\s+Allocated\s+Freed\s+Holding")


def _normalize_pool_name(raw_name: str) -> str:
    """Convert a pool name to a snake_case key.

    Examples:
        "Processor" -> "processor_pool"
        "I/O" -> "io_pool"
        "lsmpi_io" -> "lsmpi_io_pool"
    """
    name = raw_name.strip()
    name = name.replace("/", "")
    name = re.sub(r"\s+", "_", name.lower())
    return f"{name}_pool"


def _parse_pool_lines(lines: list[str]) -> dict[str, PoolSummary]:
    """Parse pool summary lines from the output."""
    pools: dict[str, PoolSummary] = {}
    for line in lines:
        m = _POOL_RE.match(line)
        if m:
            key = _normalize_pool_name(m.group(1))
            pools[key] = {
                "total": int(m.group(2)),
                "used": int(m.group(3)),
                "free": int(m.group(4)),
            }
    return pools


def _parse_process_lines(
    lines: list[str],
) -> dict[str, dict[str, ProcessAttributes]]:
    """Parse process table lines from the output."""
    processes: dict[str, dict[str, ProcessAttributes]] = {}
    for line in lines:
        m = _PROCESS_RE.match(line)
        if not m:
            continue
        pid = m.group(1)
        process_name = m.group(8)
        entry: ProcessAttributes = {
            "tty": int(m.group(2)),
            "allocated": int(m.group(3)),
            "freed": int(m.group(4)),
            "holding": int(m.group(5)),
            "getbufs": int(m.group(6)),
            "retbufs": int(m.group(7)),
        }
        if pid not in processes:
            processes[pid] = {}
        processes[pid][process_name] = entry
    return processes


@register(OS.CISCO_IOS, "show processes memory sorted")
class ShowProcessesMemorySortedParser(
    BaseParser["ShowProcessesMemorySortedResult"],
):
    """Parser for 'show processes memory sorted' command.

    Example output:
        Processor Pool Total:  919638648 Used:  236752096 Free:  682886552
         PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process
           0   0  209299480   13474544  178205704          0          0 *Init*
    """

    @classmethod
    def parse(cls, output: str) -> ShowProcessesMemorySortedResult:
        """Parse 'show processes memory sorted' output.

        Args:
            output: Raw CLI output from 'show processes memory sorted' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()

        pool_lines: list[str] = []
        process_lines: list[str] = []
        in_table = False

        for line in lines:
            if not line.strip():
                continue
            if _HEADER_RE.match(line):
                in_table = True
                continue
            if not in_table and _POOL_RE.match(line):
                pool_lines.append(line)
            elif in_table:
                process_lines.append(line)

        result: dict[str, object] = {}

        pools = _parse_pool_lines(pool_lines)
        for key, value in pools.items():
            result[key] = value

        processes = _parse_process_lines(process_lines)
        if processes:
            result["processes"] = processes

        return cast("ShowProcessesMemorySortedResult", result)
