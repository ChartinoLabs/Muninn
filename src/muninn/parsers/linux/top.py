"""Parser for 'top' command on Linux."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TasksSummary(TypedDict):
    """Schema for tasks summary line."""

    total: int
    running: int
    sleeping: int
    stopped: int
    zombie: int


class CpuSummary(TypedDict):
    """Schema for CPU usage percentages."""

    user: float
    system: float
    nice: float
    idle: float
    io_wait: float
    hardware_irq: float
    software_irq: float
    steal: float


class MemorySummary(TypedDict):
    """Schema for memory usage in MiB."""

    total: float
    free: float
    used: float
    buff_cache: float


class SwapSummary(TypedDict):
    """Schema for swap usage in MiB."""

    total: float
    free: float
    used: float
    avail_mem: float


class ProcessEntry(TypedDict):
    """Schema for a single process entry."""

    user: str
    priority: str
    nice: int
    virtual_mem: str
    resident_mem: int
    shared_mem: int
    status: str
    cpu_percent: float
    mem_percent: float
    time: str
    command: str


class TopResult(TypedDict):
    """Schema for 'top' parsed output."""

    current_time: str
    uptime: str
    users: int
    load_avg_1: float
    load_avg_5: float
    load_avg_15: float
    tasks: TasksSummary
    cpu: CpuSummary
    memory: MemorySummary
    swap: SwapSummary
    processes: dict[str, ProcessEntry]


# -- Header TypedDict for intermediate parsing --


class _HeaderInfo(TypedDict):
    current_time: str
    uptime: str
    users: int
    load_avg_1: float
    load_avg_5: float
    load_avg_15: float


# -- Regex patterns --

# top - 12:33:53 up  2:11,  5 users,  load average: 0.12, 0.40, 0.66
_HEADER_RE = re.compile(
    r"top\s+-\s+(?P<time>\S+)\s+up\s+(?P<uptime>.+?),\s+"
    r"(?P<users>\d+)\s+users?,\s+"
    r"load average:\s*(?P<la1>[\d.]+),\s*(?P<la5>[\d.]+),\s*(?P<la15>[\d.]+)"
)

# Tasks: 200 total,   1 running, 189 sleeping,   5 stopped,   5 zombie
_TASKS_RE = re.compile(
    r"Tasks:\s*(?P<total>\d+)\s+total,\s*"
    r"(?P<running>\d+)\s+running,\s*"
    r"(?P<sleeping>\d+)\s+sleeping,\s*"
    r"(?P<stopped>\d+)\s+stopped,\s*"
    r"(?P<zombie>\d+)\s+zombie"
)

# %Cpu(s): 12.5 us, 12.5 sy,  0.0 ni, 62.5 id, 12.5 wa,  0.0 hi,  0.0 si,  0.0 st
_CPU_RE = re.compile(
    r"%Cpu\(s\):\s*(?P<us>[\d.]+)\s+us,\s*"
    r"(?P<sy>[\d.]+)\s+sy,\s*"
    r"(?P<ni>[\d.]+)\s+ni,\s*"
    r"(?P<id>[\d.]+)\s+id,\s*"
    r"(?P<wa>[\d.]+)\s+wa,\s*"
    r"(?P<hi>[\d.]+)\s+hi,\s*"
    r"(?P<si>[\d.]+)\s+si,\s*"
    r"(?P<st>[\d.]+)\s+st"
)

# MiB Mem :   7809.9 total,   4753.7 free,   2052.9 used,   1126.5 buff/cache
_MEM_RE = re.compile(
    r"MiB Mem\s*:\s*(?P<total>[\d.]+)\s+total,\s*"
    r"(?P<free>[\d.]+)\s+free,\s*"
    r"(?P<used>[\d.]+)\s+used,\s*"
    r"(?P<buff_cache>[\d.]+)\s+buff/cache"
)

# MiB Swap:    512.0 total,    512.0 free,      0.0 used.   5757.0 avail Mem
_SWAP_RE = re.compile(
    r"MiB Swap\s*:\s*(?P<total>[\d.]+)\s+total,\s*"
    r"(?P<free>[\d.]+)\s+free,\s*"
    r"(?P<used>[\d.]+)\s+used\.\s*"
    r"(?P<avail>[\d.]+)\s+avail\s+Mem"
)

# Process line: fields are positional based on the column header
# PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND
_PROCESS_RE = re.compile(
    r"^\s*(?P<pid>\d+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<pr>\S+)\s+"
    r"(?P<ni>-?\d+)\s+"
    r"(?P<virt>\S+)\s+"
    r"(?P<res>\d+)\s+"
    r"(?P<shr>\d+)\s+"
    r"(?P<status>[A-Z])\s+"
    r"(?P<cpu>[\d.]+)\s+"
    r"(?P<mem>[\d.]+)\s+"
    r"(?P<time>\S+)\s+"
    r"(?P<command>.+)$"
)


# -- Line-level parsers --


def _parse_header(line: str) -> _HeaderInfo | None:
    """Parse the top header line with uptime and load averages."""
    match = _HEADER_RE.search(line)
    if not match:
        return None
    return _HeaderInfo(
        current_time=match.group("time"),
        uptime=match.group("uptime").strip(),
        users=int(match.group("users")),
        load_avg_1=float(match.group("la1")),
        load_avg_5=float(match.group("la5")),
        load_avg_15=float(match.group("la15")),
    )


def _parse_tasks(line: str) -> TasksSummary | None:
    """Parse the tasks summary line."""
    match = _TASKS_RE.search(line)
    if not match:
        return None
    return TasksSummary(
        total=int(match.group("total")),
        running=int(match.group("running")),
        sleeping=int(match.group("sleeping")),
        stopped=int(match.group("stopped")),
        zombie=int(match.group("zombie")),
    )


def _parse_cpu(line: str) -> CpuSummary | None:
    """Parse the CPU summary line."""
    match = _CPU_RE.search(line)
    if not match:
        return None
    return CpuSummary(
        user=float(match.group("us")),
        system=float(match.group("sy")),
        nice=float(match.group("ni")),
        idle=float(match.group("id")),
        io_wait=float(match.group("wa")),
        hardware_irq=float(match.group("hi")),
        software_irq=float(match.group("si")),
        steal=float(match.group("st")),
    )


def _parse_memory(line: str) -> MemorySummary | None:
    """Parse the memory summary line."""
    match = _MEM_RE.search(line)
    if not match:
        return None
    return MemorySummary(
        total=float(match.group("total")),
        free=float(match.group("free")),
        used=float(match.group("used")),
        buff_cache=float(match.group("buff_cache")),
    )


def _parse_swap(line: str) -> SwapSummary | None:
    """Parse the swap summary line."""
    match = _SWAP_RE.search(line)
    if not match:
        return None
    return SwapSummary(
        total=float(match.group("total")),
        free=float(match.group("free")),
        used=float(match.group("used")),
        avail_mem=float(match.group("avail")),
    )


def _parse_process(line: str) -> tuple[str, ProcessEntry] | None:
    """Parse a single process line into (pid, ProcessEntry)."""
    match = _PROCESS_RE.match(line)
    if not match:
        return None
    pid = match.group("pid")
    return pid, ProcessEntry(
        user=match.group("user"),
        priority=match.group("pr"),
        nice=int(match.group("ni")),
        virtual_mem=match.group("virt"),
        resident_mem=int(match.group("res")),
        shared_mem=int(match.group("shr")),
        status=match.group("status"),
        cpu_percent=float(match.group("cpu")),
        mem_percent=float(match.group("mem")),
        time=match.group("time"),
        command=match.group("command").strip(),
    )


# -- Stateful parser --


@dataclass
class _ParseState:
    """Mutable accumulator for the line-by-line parsing loop."""

    header: _HeaderInfo | None = None
    tasks: TasksSummary | None = None
    cpu: CpuSummary | None = None
    memory: MemorySummary | None = None
    swap: SwapSummary | None = None
    processes: dict[str, ProcessEntry] = field(default_factory=dict)

    def _try_summary(self, line: str) -> bool:
        """Attempt to parse the next missing summary section. Returns True on match."""
        if self.header is None:
            self.header = _parse_header(line)
            return self.header is not None
        if self.tasks is None:
            self.tasks = _parse_tasks(line)
            return self.tasks is not None
        if self.cpu is None:
            self.cpu = _parse_cpu(line)
            return self.cpu is not None
        if self.memory is None:
            self.memory = _parse_memory(line)
            return self.memory is not None
        if self.swap is None:
            self.swap = _parse_swap(line)
            return self.swap is not None
        return False

    def handle_line(self, line: str) -> None:
        """Dispatch a single line to the appropriate sub-parser."""
        if self._try_summary(line):
            return
        proc = _parse_process(line)
        if proc is not None:
            pid, entry = proc
            self.processes[pid] = entry

    def validate(self) -> None:
        """Raise ValueError if any required summary section is missing."""
        if self.header is None:
            msg = "No top header line found in output"
            raise ValueError(msg)
        if self.tasks is None:
            msg = "No tasks summary found in output"
            raise ValueError(msg)
        if self.cpu is None:
            msg = "No CPU summary found in output"
            raise ValueError(msg)
        if self.memory is None:
            msg = "No memory summary found in output"
            raise ValueError(msg)
        if self.swap is None:
            msg = "No swap summary found in output"
            raise ValueError(msg)

    def to_result(self) -> TopResult:
        """Build the final TopResult after validation.

        Raises:
            ValueError: If any required summary section is missing.
        """
        self.validate()
        # validate() guarantees these are non-None; re-check for the type checker
        header = self.header
        tasks = self.tasks
        cpu = self.cpu
        memory = self.memory
        swap = self.swap
        if (
            header is None
            or tasks is None
            or cpu is None
            or memory is None
            or swap is None
        ):
            msg = "Required section missing after validation"
            raise ValueError(msg)
        return TopResult(
            current_time=header["current_time"],
            uptime=header["uptime"],
            users=header["users"],
            load_avg_1=header["load_avg_1"],
            load_avg_5=header["load_avg_5"],
            load_avg_15=header["load_avg_15"],
            tasks=tasks,
            cpu=cpu,
            memory=memory,
            swap=swap,
            processes=self.processes,
        )


@register(OS.LINUX, "top")
class TopParser(BaseParser[TopResult]):
    """Parser for 'top' command on Linux.

    Parses the summary header (uptime, load averages, tasks, CPU%,
    memory/swap) and the process list.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> TopResult:
        """Parse 'top' output on Linux.

        Args:
            output: Raw CLI output from the top command.

        Returns:
            Structured dict with system summary and process list.

        Raises:
            ValueError: If required sections cannot be parsed.
        """
        state = _ParseState()
        for line in output.splitlines():
            state.handle_line(line)
        return state.to_result()
