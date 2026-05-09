"""Parser for 'show system processes summary' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ProcessCounts(TypedDict):
    """Schema for thread/process state counts."""

    total: int
    running: int
    sleeping: int
    zombie: int
    waiting: int


class CpuUsage(TypedDict):
    """Schema for CPU usage percentages."""

    user: float
    nice: float
    system: float
    interrupt: float
    idle: float


class MemoryUsage(TypedDict):
    """Schema for memory usage."""

    active_mb: int
    inactive_mb: int
    wired_mb: int
    buffer_mb: int
    free_mb: int


class SwapUsage(TypedDict):
    """Schema for swap usage."""

    total_mb: int
    free_mb: int


class ShowSystemProcessesSummaryResult(TypedDict):
    """Schema for 'show system processes summary' parsed output.

    Captures CPU load averages, memory/swap usage, and process state
    counts from Juniper Junos devices.
    """

    last_pid: int
    load_average_1min: float
    load_average_5min: float
    load_average_15min: float
    uptime: str
    current_time: str
    processes: ProcessCounts
    cpu: CpuUsage
    memory: MemoryUsage
    swap: SwapUsage


_MEM_UNIT_MULTIPLIERS: dict[str, int] = {
    "K": 1,
    "M": 1,
    "G": 1024,
    "T": 1024 * 1024,
}


def _parse_mem_value_mb(value_str: str) -> int:
    """Convert a memory string like '3977M', '14G', '504K' to megabytes.

    Values in KB are rounded down to 0 MB for sub-megabyte quantities.
    """
    unit = value_str[-1].upper()
    numeric = int(value_str[:-1])
    multiplier = _MEM_UNIT_MULTIPLIERS.get(unit)
    if multiplier is None:
        msg = f"Unknown memory unit: {unit!r}"
        raise ValueError(msg)
    if unit == "K":
        return numeric // 1024
    return numeric * multiplier


@register(OS.JUNIPER_JUNOS, "show system processes summary")
class ShowSystemProcessesSummaryParser(
    BaseParser[ShowSystemProcessesSummaryResult],
):
    """Parser for 'show system processes summary' command on Juniper Junos.

    Parses the summary header (load averages, CPU, memory, swap, and
    process state counts). Individual process lines are not included.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _HEADER_PATTERN = re.compile(
        r"last pid:\s*(?P<last_pid>\d+);\s*"
        r"load averages:\s*(?P<load1>[\d.]+),\s*"
        r"(?P<load5>[\d.]+),\s*(?P<load15>[\d.]+)\s+"
        r"up\s+(?P<uptime>\S+)\s+"
        r"(?P<current_time>\d{2}:\d{2}:\d{2})",
    )

    _THREADS_PATTERN = re.compile(
        r"(?P<total>\d+)\s+threads:\s+"
        r"(?P<running>\d+)\s+running,\s+"
        r"(?P<sleeping>\d+)\s+sleeping,\s+"
        r"(?P<zombie>\d+)\s+zombie,\s+"
        r"(?P<waiting>\d+)\s+waiting",
    )

    _CPU_PATTERN = re.compile(
        r"CPU:\s+"
        r"(?P<user>[\d.]+)%\s+user,\s+"
        r"(?P<nice>[\d.]+)%\s+nice,\s+"
        r"(?P<system>[\d.]+)%\s+system,\s+"
        r"(?P<interrupt>[\d.]+)%\s+interrupt,\s+"
        r"(?P<idle>[\d.]+)%\s+idle",
    )

    _MEM_PATTERN = re.compile(
        r"Mem:\s+"
        r"(?P<active>\d+[KMGT])\s+Active,\s+"
        r"(?P<inactive>\d+[KMGT])\s+Inact,\s+"
        r"(?P<wired>\d+[KMGT])\s+Wired,\s+"
        r"(?P<buffer>\d+[KMGT])\s+Buf,\s+"
        r"(?P<free>\d+[KMGT])\s+Free",
    )

    _SWAP_PATTERN = re.compile(
        r"Swap:\s+"
        r"(?P<total>\d+[KMGT])\s+Total,\s+"
        r"(?P<free>\d+[KMGT])\s+Free",
    )

    _MatchStr = re.Match[str]

    @classmethod
    def _match_all_sections(
        cls, output: str
    ) -> tuple[_MatchStr, _MatchStr, _MatchStr, _MatchStr, _MatchStr]:
        """Match all required sections, raising ValueError if any are missing."""
        patterns: dict[str, re.Pattern[str]] = {
            "header (load averages)": cls._HEADER_PATTERN,
            "thread counts": cls._THREADS_PATTERN,
            "CPU usage": cls._CPU_PATTERN,
            "memory usage": cls._MEM_PATTERN,
            "swap usage": cls._SWAP_PATTERN,
        }
        matches: dict[str, re.Match[str] | None] = {
            name: pat.search(output) for name, pat in patterns.items()
        }
        missing = [name for name, m in matches.items() if m is None]
        if missing:
            msg = f"Could not parse: {', '.join(missing)}"
            raise ValueError(msg)

        # All values are guaranteed non-None after the missing check
        vals = [m for m in matches.values() if m is not None]
        return (vals[0], vals[1], vals[2], vals[3], vals[4])

    @staticmethod
    def _build_memory(m: re.Match[str]) -> MemoryUsage:
        return MemoryUsage(
            active_mb=_parse_mem_value_mb(m.group("active")),
            inactive_mb=_parse_mem_value_mb(m.group("inactive")),
            wired_mb=_parse_mem_value_mb(m.group("wired")),
            buffer_mb=_parse_mem_value_mb(m.group("buffer")),
            free_mb=_parse_mem_value_mb(m.group("free")),
        )

    @classmethod
    def parse(cls, output: str) -> ShowSystemProcessesSummaryResult:
        """Parse 'show system processes summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed process summary information.

        Raises:
            ValueError: If required sections cannot be parsed.
        """
        header, threads, cpu, mem, swap = cls._match_all_sections(output)

        return ShowSystemProcessesSummaryResult(
            last_pid=int(header.group("last_pid")),
            load_average_1min=float(header.group("load1")),
            load_average_5min=float(header.group("load5")),
            load_average_15min=float(header.group("load15")),
            uptime=header.group("uptime"),
            current_time=header.group("current_time"),
            processes=ProcessCounts(
                total=int(threads.group("total")),
                running=int(threads.group("running")),
                sleeping=int(threads.group("sleeping")),
                zombie=int(threads.group("zombie")),
                waiting=int(threads.group("waiting")),
            ),
            cpu=CpuUsage(
                user=float(cpu.group("user")),
                nice=float(cpu.group("nice")),
                system=float(cpu.group("system")),
                interrupt=float(cpu.group("interrupt")),
                idle=float(cpu.group("idle")),
            ),
            memory=cls._build_memory(mem),
            swap=SwapUsage(
                total_mb=_parse_mem_value_mb(swap.group("total")),
                free_mb=_parse_mem_value_mb(swap.group("free")),
            ),
        )
