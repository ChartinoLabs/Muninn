"""Parser for 'docker stats --no-stream' command on Linux."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ContainerStatsEntry(TypedDict):
    """Schema for a single container's resource usage."""

    container_id: str
    cpu_percent: float
    mem_usage: str
    mem_limit: str
    mem_percent: float
    net_rx: str
    net_tx: str
    block_read: str
    block_write: str
    pids: int


DockerStatsResult = dict[str, ContainerStatsEntry]

# Pattern to parse each data row of docker stats output.
# Example: a3f78cb32a8e  foo-bar  0.06%  55.69MiB / 1.025GiB  ...
_ROW_PATTERN = re.compile(
    r"^(?P<container_id>\S+)\s+"
    r"(?P<name>\S+)\s+"
    r"(?P<cpu_pct>[\d.]+)%\s+"
    r"(?P<mem_usage>\S+)\s*/\s*(?P<mem_limit>\S+)\s+"
    r"(?P<mem_pct>[\d.]+)%\s+"
    r"(?P<net_rx>\S+)\s*/\s*(?P<net_tx>\S+)\s+"
    r"(?P<block_read>\S+)\s*/\s*(?P<block_write>\S+)\s+"
    r"(?P<pids>\d+)\s*$"
)


@register(OS.LINUX, "docker stats --no-stream")
class DockerStatsParser(BaseParser[DockerStatsResult]):
    """Parser for 'docker stats --no-stream' command on Linux.

    Returns a dict keyed by container name, each value containing
    CPU, memory, network I/O, block I/O, and PID count.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> DockerStatsResult:
        """Parse 'docker stats --no-stream' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of container stats keyed by container name.

        Raises:
            ValueError: If no container stats can be parsed.
        """
        result: dict[str, ContainerStatsEntry] = {}

        for line in output.splitlines():
            match = _ROW_PATTERN.match(line.strip())
            if not match:
                continue

            name = match.group("name")
            result[name] = ContainerStatsEntry(
                container_id=match.group("container_id"),
                cpu_percent=float(match.group("cpu_pct")),
                mem_usage=match.group("mem_usage"),
                mem_limit=match.group("mem_limit"),
                mem_percent=float(match.group("mem_pct")),
                net_rx=match.group("net_rx"),
                net_tx=match.group("net_tx"),
                block_read=match.group("block_read"),
                block_write=match.group("block_write"),
                pids=int(match.group("pids")),
            )

        if not result:
            msg = "No container stats found in output"
            raise ValueError(msg)

        return result
