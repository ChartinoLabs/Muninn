"""Parser for 'show system processes brief' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ProcessStates(TypedDict):
    """Counts of processes by state."""

    total: int
    running: int
    sleeping: int
    zombie: int
    waiting: int


class CpuUsage(TypedDict):
    """CPU usage percentages."""

    user: float
    nice: float
    system: float
    interrupt: float
    idle: float


class MemoryStats(TypedDict):
    """Physical memory statistics in megabytes."""

    active_mb: int
    inactive_mb: int
    wired_mb: int
    buf_mb: int
    free_mb: int


class SwapStats(TypedDict):
    """Swap space statistics in megabytes."""

    total_mb: int
    free_mb: int


class ShowSystemProcessesBriefResult(TypedDict):
    """Schema for 'show system processes brief' parsed output.

    Captures system-level resource utilization: last PID, load averages,
    uptime, process state counts, CPU percentages, memory, and swap.
    """

    last_pid: int
    load_avg_1min: float
    load_avg_5min: float
    load_avg_15min: float
    uptime: str
    time: str
    processes: ProcessStates
    cpu: CpuUsage
    memory: MemoryStats
    swap: SwapStats


def _parse_size_mb(value: str) -> int:
    """Convert a size string like '3532M' or '33G' to integer megabytes."""
    value = value.strip()
    if value.endswith("G"):
        return int(float(value[:-1]) * 1024)
    if value.endswith("M"):
        return int(float(value[:-1]))
    if value.endswith("K"):
        return max(1, int(float(value[:-1]) / 1024))
    return int(value)


@register(OS.JUNIPER_JUNOS, "show system processes brief")
class ShowSystemProcessesBriefParser(
    BaseParser[ShowSystemProcessesBriefResult],
):
    """Parser for 'show system processes brief' command on Juniper Junos.

    Parses system resource summary including load averages, process counts,
    CPU usage, memory, and swap statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _HEADER_PATTERN = re.compile(
        r"last pid:\s*(?P<last_pid>\d+);\s*"
        r"load averages:\s*(?P<load1>[\d.]+),\s*"
        r"(?P<load5>[\d.]+),\s*(?P<load15>[\d.]+)\s+"
        r"up\s+(?P<uptime>\S+)\s+"
        r"(?P<time>\S+)"
    )

    _PROCESS_PATTERN = re.compile(
        r"(?P<total>\d+)\s+processes:\s*"
        r"(?P<running>\d+)\s+running,\s*"
        r"(?P<sleeping>\d+)\s+sleeping,\s*"
        r"(?P<zombie>\d+)\s+zombie,\s*"
        r"(?P<waiting>\d+)\s+waiting"
    )

    _CPU_PATTERN = re.compile(
        r"CPU:\s*(?P<user>[\d.]+)%\s+user,\s*"
        r"(?P<nice>[\d.]+)%\s+nice,\s*"
        r"(?P<system>[\d.]+)%\s+system,\s*"
        r"(?P<interrupt>[\d.]+)%\s+interrupt,\s*"
        r"(?P<idle>[\d.]+)%\s+idle"
    )

    _MEM_PATTERN = re.compile(
        r"Mem:\s*(?P<active>\S+)\s+Active,\s*"
        r"(?P<inactive>\S+)\s+Inact,\s*"
        r"(?P<wired>\S+)\s+Wired,\s*"
        r"(?P<buf>\S+)\s+Buf,\s*"
        r"(?P<free>\S+)\s+Free"
    )

    _SWAP_PATTERN = re.compile(
        r"Swap:\s*(?P<total>\S+)\s+Total,\s*"
        r"(?P<free>\S+)\s+Free"
    )

    @classmethod
    def parse(cls, output: str) -> ShowSystemProcessesBriefResult:
        """Parse 'show system processes brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed system process summary.

        Raises:
            ValueError: If required sections cannot be parsed.
        """
        header_match = cls._HEADER_PATTERN.search(output)
        if not header_match:
            msg = "Could not parse header line (last pid / load averages)"
            raise ValueError(msg)

        process_match = cls._PROCESS_PATTERN.search(output)
        if not process_match:
            msg = "Could not parse process counts line"
            raise ValueError(msg)

        cpu_match = cls._CPU_PATTERN.search(output)
        if not cpu_match:
            msg = "Could not parse CPU usage line"
            raise ValueError(msg)

        mem_match = cls._MEM_PATTERN.search(output)
        if not mem_match:
            msg = "Could not parse memory statistics line"
            raise ValueError(msg)

        swap_match = cls._SWAP_PATTERN.search(output)
        if not swap_match:
            msg = "Could not parse swap statistics line"
            raise ValueError(msg)

        return ShowSystemProcessesBriefResult(
            last_pid=int(header_match.group("last_pid")),
            load_avg_1min=float(header_match.group("load1")),
            load_avg_5min=float(header_match.group("load5")),
            load_avg_15min=float(header_match.group("load15")),
            uptime=header_match.group("uptime"),
            time=header_match.group("time"),
            processes=ProcessStates(
                total=int(process_match.group("total")),
                running=int(process_match.group("running")),
                sleeping=int(process_match.group("sleeping")),
                zombie=int(process_match.group("zombie")),
                waiting=int(process_match.group("waiting")),
            ),
            cpu=CpuUsage(
                user=float(cpu_match.group("user")),
                nice=float(cpu_match.group("nice")),
                system=float(cpu_match.group("system")),
                interrupt=float(cpu_match.group("interrupt")),
                idle=float(cpu_match.group("idle")),
            ),
            memory=MemoryStats(
                active_mb=_parse_size_mb(mem_match.group("active")),
                inactive_mb=_parse_size_mb(mem_match.group("inactive")),
                wired_mb=_parse_size_mb(mem_match.group("wired")),
                buf_mb=_parse_size_mb(mem_match.group("buf")),
                free_mb=_parse_size_mb(mem_match.group("free")),
            ),
            swap=SwapStats(
                total_mb=_parse_size_mb(swap_match.group("total")),
                free_mb=_parse_size_mb(swap_match.group("free")),
            ),
        )
