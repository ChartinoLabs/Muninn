"""Parser for 'debug swm status' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PartitionEntry(TypedDict):
    """Schema for a single partition entry."""

    state: str
    version: str


# Top-level result keyed by partition name.
DebugSwmStatusResult = dict[str, PartitionEntry]


_HEADER_SEPARATOR = re.compile(r"^-{3,}$")
_PARTITION_LINE = re.compile(
    r"^(?P<partition>\S+)\s+(?P<state>\S+)\s+(?P<version>\S+)$"
)


def _extract_table_lines(output: str) -> list[str]:
    """Return only the data lines after the dash separator."""
    lines = output.splitlines()
    for idx, line in enumerate(lines):
        if _HEADER_SEPARATOR.match(line.strip()):
            return [ln.strip() for ln in lines[idx + 1 :] if ln.strip()]
    return []


@register(OS.PALOALTO_PANOS, "debug swm status")
class DebugSwmStatusParser(BaseParser[DebugSwmStatusResult]):
    """Parser for 'debug swm status' on Palo Alto PAN-OS.

    Parses the software manager partition table into a dict-of-dicts
    keyed by partition name (e.g. ``sysroot0``, ``sysroot1``, ``maint``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> DebugSwmStatusResult:
        """Parse 'debug swm status' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict of partition entries keyed by partition name.

        Raises:
            ValueError: If no partition entries are found.
        """
        result: DebugSwmStatusResult = {}

        for line in _extract_table_lines(output):
            match = _PARTITION_LINE.match(line)
            if match:
                result[match.group("partition")] = PartitionEntry(
                    state=match.group("state"),
                    version=match.group("version"),
                )

        if not result:
            msg = "No partition entries found in output"
            raise ValueError(msg)

        return result
