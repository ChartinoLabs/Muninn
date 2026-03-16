"""Parser for 'show interface link' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Column header labels used to detect output variant
_HEADER_UP_TIME = "Up Time"
_HEADER_DOWN_SINCE = "Down Since"

# Header line pattern matches both variants:
#   Port  Name  Down Time  Up Time
#   Port  Name  Down Time  Down Since
_HEADER_RE = re.compile(r"^\s*Port\s+Name\s+Down\s+Time\s+(Up\s+Time|Down\s+Since)\s*$")

# "Down Since" timestamp at end of line: "08:07:10  Mon Feb 14 2022"
_SINCE_TAIL_RE = re.compile(
    r"\s{2,}(\d{2}:\d{2}:\d{2}\s+\w{3}\s+\w{3}\s+\d{1,2}\s+\d{4})\s*$"
)


class InterfaceLinkEntry(TypedDict):
    """Schema for a single interface link entry."""

    down_time: str
    name: NotRequired[str]
    up_time: NotRequired[str]
    down_since: NotRequired[str]


class ShowInterfaceLinkResult(TypedDict):
    """Schema for 'show interface link' parsed output."""

    interfaces: dict[str, InterfaceLinkEntry]


def _find_header(lines: list[str]) -> tuple[int, str]:
    """Find the header line and determine output variant.

    Returns:
        Tuple of (header_line_index, variant) where variant is
        'up_time' or 'down_since'.

    Raises:
        ValueError: If no header line found.
    """
    for i, line in enumerate(lines):
        m = _HEADER_RE.match(line)
        if m:
            variant = "up_time" if _HEADER_UP_TIME in m.group(1) else "down_since"
            return i, variant

    msg = "No header line found in 'show interface link' output"
    raise ValueError(msg)


def _detect_columns(header_line: str) -> tuple[int, int, int]:
    """Detect column start positions from the header line.

    Returns:
        Tuple of (name_col, down_time_col, last_col) where last_col is
        the start of either 'Up Time' or 'Down Since'.
    """
    name_col = header_line.index("Name")
    down_col = header_line.index("Down Time")
    for label in (_HEADER_UP_TIME, _HEADER_DOWN_SINCE):
        idx = header_line.find(label)
        if idx >= 0:
            return name_col, down_col, idx

    msg = "Cannot detect column positions in header"
    raise ValueError(msg)


def _parse_up_time_line(
    line: str,
    name_col: int,
    down_col: int,
    last_col: int,
) -> tuple[str, InterfaceLinkEntry] | None:
    """Parse a data line from the 'Up Time' variant using column positions.

    The Up Time variant uses compact time formats (e.g., 30w6d, 00:00:00)
    that fit within the fixed-width columns, so column slicing works reliably.
    """
    if not line.strip():
        return None

    port_raw = line[:name_col].strip()
    if not port_raw:
        return None

    name_raw = line[name_col:down_col].strip() if len(line) > name_col else ""
    down_time_raw = line[down_col:last_col].strip() if len(line) > down_col else ""
    up_time_raw = line[last_col:].strip() if len(line) > last_col else ""

    if not down_time_raw:
        return None

    port = canonical_interface_name(port_raw, os=OS.CISCO_IOS)
    entry: InterfaceLinkEntry = {"down_time": down_time_raw}

    if name_raw:
        entry["name"] = name_raw
    if up_time_raw:
        entry["up_time"] = up_time_raw

    return port, entry


def _parse_down_since_line(
    line: str,
    name_col: int,
    down_col: int,
) -> tuple[str, InterfaceLinkEntry] | None:
    """Parse a data line from the 'Down Since' variant.

    The Down Since variant uses verbose time formats (e.g.,
    "37 weeks, 3 days, 5 hours, 52 minutes 18 secs") that overflow
    column boundaries. The "Down Since" timestamp at the end of the
    line is extracted via regex, and the remaining text between the
    name column end and the timestamp is treated as down_time.
    """
    if not line.strip():
        return None

    port_raw = line[:name_col].strip()
    if not port_raw:
        return None

    name_raw = line[name_col:down_col].strip() if len(line) > name_col else ""

    # Extract optional "Down Since" timestamp from end of line
    since_match = _SINCE_TAIL_RE.search(line)
    if since_match:
        down_since_val = since_match.group(1)
        # Down time is everything between down_col and the since timestamp
        down_time_raw = line[down_col : since_match.start()].strip()
    else:
        down_since_val = None
        down_time_raw = line[down_col:].strip()

    if not down_time_raw:
        return None

    port = canonical_interface_name(port_raw, os=OS.CISCO_IOS)
    entry: InterfaceLinkEntry = {"down_time": down_time_raw}

    if name_raw:
        entry["name"] = name_raw
    if down_since_val:
        entry["down_since"] = down_since_val

    return port, entry


@register(OS.CISCO_IOS, "show interface link")
class ShowInterfaceLinkParser(BaseParser[ShowInterfaceLinkResult]):
    """Parser for 'show interface link' on IOS."""

    tags: ClassVar[frozenset[str]] = frozenset({"interfaces"})

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceLinkResult:
        """Parse 'show interface link' output.

        Supports both the 'Up Time' and 'Down Since' output variants.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface link data keyed by canonical interface name.

        Raises:
            ValueError: If no header or no data found.
        """
        lines = output.splitlines()
        header_idx, variant = _find_header(lines)
        name_col, down_col, last_col = _detect_columns(lines[header_idx])

        interfaces: dict[str, InterfaceLinkEntry] = {}

        for line in lines[header_idx + 1 :]:
            if variant == "up_time":
                result = _parse_up_time_line(line, name_col, down_col, last_col)
            else:
                result = _parse_down_since_line(line, name_col, down_col)

            if result is not None:
                port, entry = result
                interfaces[port] = entry

        if not interfaces:
            msg = "No interface link entries found in output"
            raise ValueError(msg)

        return {"interfaces": interfaces}
