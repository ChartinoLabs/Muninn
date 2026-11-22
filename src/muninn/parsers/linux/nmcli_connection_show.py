"""Parser for 'nmcli connection show' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NmcliConnectionEntry(TypedDict):
    """Schema for a single NetworkManager connection entry."""

    uuid: str
    type: str
    device: NotRequired[str]


NmcliConnectionShowResult = dict[str, NmcliConnectionEntry]

# The header line defines column positions; data lines are fixed-width.
_HEADER_RE = re.compile(r"^NAME\s+UUID\s+TYPE\s+DEVICE")

_NO_DEVICE_SENTINEL = "--"


def _find_header(lines: list[str]) -> tuple[str, int]:
    """Locate the header line and return (header_text, index).

    Raises:
        ValueError: If no header line is found.
    """
    for i, line in enumerate(lines):
        if _HEADER_RE.match(line):
            return line, i
    msg = "No header line found in nmcli connection show output"
    raise ValueError(msg)


def _column_offsets(header: str) -> tuple[int, int, int]:
    """Return (uuid_start, type_start, device_start) column offsets from the header."""
    return header.index("UUID"), header.index("TYPE"), header.index("DEVICE")


def _parse_line(
    line: str,
    uuid_col: int,
    type_col: int,
    device_col: int,
) -> tuple[str, NmcliConnectionEntry] | None:
    """Parse a single data line into (name, entry), or None if the line is empty."""
    if not line.strip():
        return None

    name = line[:uuid_col].strip()
    uuid = line[uuid_col:type_col].strip()
    if not name or not uuid:
        return None

    conn_type = line[type_col:device_col].strip()
    device = line[device_col:].strip()

    entry = NmcliConnectionEntry(uuid=uuid, type=conn_type)
    if device and device != _NO_DEVICE_SENTINEL:
        entry["device"] = device

    return name, entry


@register(OS.LINUX, "nmcli connection show")
class NmcliConnectionShowParser(BaseParser[NmcliConnectionShowResult]):
    """Parser for 'nmcli connection show' command on Linux.

    Parses the summary table of NetworkManager connections, returning
    a dict keyed by connection name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    @classmethod
    def parse(cls, output: str) -> NmcliConnectionShowResult:
        """Parse 'nmcli connection show' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of connection entries keyed by connection name.

        Raises:
            ValueError: If no connections can be parsed.
        """
        lines = output.splitlines()
        header, header_index = _find_header(lines)
        uuid_col, type_col, device_col = _column_offsets(header)

        result: dict[str, NmcliConnectionEntry] = {}
        for line in lines[header_index + 1 :]:
            parsed = _parse_line(line, uuid_col, type_col, device_col)
            if parsed is not None:
                result[parsed[0]] = parsed[1]

        if not result:
            msg = "No connections found in output"
            raise ValueError(msg)

        return result
