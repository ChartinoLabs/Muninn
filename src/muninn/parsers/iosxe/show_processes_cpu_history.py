"""Parser for 'show processes cpu history' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Section label patterns to identify chart type
_SECTION_LABEL_RE = re.compile(r"CPU% per (second|minute|hour)")

# Scale row pattern (e.g., "  100", "   90", "   10")
_SCALE_RE = re.compile(r"^\s+(\d{2,3})\s*$")

# Scale row with graph content (e.g. "   10 **#*#")
_SCALE_GRAPH_RE = re.compile(r"^\s+(\d{2,3})\s(.+)$")

# X-axis ruler line
_RULER_RE = re.compile(r"^\s+0\.{4}5\.{4}1")

_PERIOD_TO_KEY = {"second": "per_second", "minute": "per_minute", "hour": "per_hour"}
_PERIOD_SLOTS = {"second": 60, "minute": 60, "hour": 72}


class HistorySection(TypedDict):
    """Schema for a single CPU history chart section."""

    period: str
    samples: int
    average: list[int]
    maximum: NotRequired[list[int]]


class ShowProcessesCpuHistoryResult(TypedDict):
    """Schema for 'show processes cpu history' parsed output."""

    per_second: NotRequired[HistorySection]
    per_minute: NotRequired[HistorySection]
    per_hour: NotRequired[HistorySection]


def _has_digits_before_col(line: str, col: int) -> bool:
    """Check if a line has digit characters before the given column."""
    for i in range(min(col, len(line))):
        if line[i].isdigit():
            return True
    return False


def _digit_start_col(lines: list[str], graph_start_col: int) -> int:
    """Determine the effective start column for digit lines."""
    for line in lines:
        if line.strip() and _has_digits_before_col(line, graph_start_col):
            return 0
    return graph_start_col


def _decode_digit_lines(
    lines: list[str],
    graph_start_col: int,
    num_slots: int,
) -> list[int]:
    """Decode stacked digit lines into integer values.

    Each column represents one time slot. The topmost line holds
    the most-significant digit, the bottom line holds the units.
    """
    if not lines:
        return [0] * num_slots

    start_col = _digit_start_col(lines, graph_start_col)
    values = [0] * num_slots
    num_lines = len(lines)

    for line_idx, line in enumerate(lines):
        multiplier = 10 ** (num_lines - 1 - line_idx)
        for slot in range(num_slots):
            col = start_col + slot
            if col < len(line) and line[col].isdigit():
                values[slot] += int(line[col]) * multiplier

    return values


def _decode_graph_bars(
    section_lines: list[str],
    first_scale_idx: int,
    ruler_idx: int,
    graph_start_col: int,
    num_slots: int,
) -> list[int]:
    """Decode maximum values from '*' graph bar characters.

    For each slot, returns the highest scale level at which a '*'
    character appears.
    """
    values = [0] * num_slots
    for i in range(first_scale_idx, ruler_idx):
        m = _SCALE_GRAPH_RE.match(section_lines[i])
        if not m:
            continue
        scale_val = int(m.group(1))
        for slot in range(num_slots):
            col = graph_start_col + slot
            if col < len(section_lines[i]) and section_lines[i][col] == "*":
                values[slot] = max(values[slot], scale_val)
    return values


def _clamp_max_to_avg(maximum: list[int], average: list[int]) -> None:
    """Ensure maximum[i] >= average[i] for all slots.

    Graph bars may be truncated at line boundaries while digit
    lines extend further.
    """
    for i in range(len(maximum)):
        if maximum[i] < average[i]:
            maximum[i] = average[i]


def _find_ruler_index(section_lines: list[str]) -> int:
    """Find the ruler line index within a section."""
    for i, line in enumerate(section_lines):
        if _RULER_RE.match(line):
            return i
    return -1


def _extract_period(section_lines: list[str], ruler_idx: int) -> str:
    """Extract period name from section label."""
    for line in section_lines[ruler_idx:]:
        m = _SECTION_LABEL_RE.search(line)
        if m:
            return m.group(1)
    return ""


def _find_first_scale(section_lines: list[str], ruler_idx: int) -> int:
    """Find the first scale row above the ruler."""
    for i in range(ruler_idx):
        if _SCALE_RE.match(section_lines[i]):
            return i
        if _SCALE_GRAPH_RE.match(section_lines[i]):
            return i
    return -1


def _has_max_legend(section_lines: list[str], ruler_idx: int) -> bool:
    """Check whether this section has a max/average legend."""
    for line in section_lines[ruler_idx:]:
        if "* = maximum" in line:
            return True
    return False


def _collect_digit_lines(section_lines: list[str], first_scale_idx: int) -> list[str]:
    """Collect all non-blank lines above the first scale row."""
    return [
        section_lines[i] for i in range(first_scale_idx) if section_lines[i].strip()
    ]


def _parse_section(section_lines: list[str]) -> HistorySection | None:
    """Parse a single chart section from its raw lines."""
    ruler_idx = _find_ruler_index(section_lines)
    if ruler_idx < 0:
        return None

    ruler_line = section_lines[ruler_idx]
    graph_start_col = len(ruler_line) - len(ruler_line.lstrip())

    period = _extract_period(section_lines, ruler_idx)
    if not period:
        return None

    num_slots = _PERIOD_SLOTS.get(period, 60)
    first_scale_idx = _find_first_scale(section_lines, ruler_idx)
    if first_scale_idx < 0:
        return None

    digit_lines = _collect_digit_lines(section_lines, first_scale_idx)
    average = _decode_digit_lines(digit_lines, graph_start_col, num_slots)

    if not _has_max_legend(section_lines, ruler_idx):
        return cast(
            HistorySection,
            {"period": period, "samples": num_slots, "average": average},
        )

    maximum = _decode_graph_bars(
        section_lines, first_scale_idx, ruler_idx, graph_start_col, num_slots
    )
    _clamp_max_to_avg(maximum, average)
    return cast(
        HistorySection,
        {
            "period": period,
            "samples": num_slots,
            "average": average,
            "maximum": maximum,
        },
    )


def _skip_trailing_blanks(lines: list[str], pos: int) -> int:
    """Advance past trailing blank lines."""
    while pos < len(lines) and not lines[pos].strip():
        pos += 1
    return pos


def _find_section_end(lines: list[str], ruler_pos: int) -> int:
    """Find the end boundary of a section given its ruler."""
    end = ruler_pos + 1
    # Skip position-labels line
    if end < len(lines):
        end += 1
    # Skip CPU% label line
    if end < len(lines) and _SECTION_LABEL_RE.search(lines[end]):
        end += 1
    # Skip optional legend line
    if end < len(lines) and "* = maximum" in lines[end]:
        end += 1
    return _skip_trailing_blanks(lines, end)


def _split_into_sections(lines: list[str]) -> list[list[str]]:
    """Split output into individual chart sections."""
    ruler_indices = [i for i, ln in enumerate(lines) if _RULER_RE.match(ln)]

    if not ruler_indices:
        return []

    sections: list[list[str]] = []
    for idx, ruler_pos in enumerate(ruler_indices):
        start = 0 if idx == 0 else _find_section_end(lines, ruler_indices[idx - 1])
        end = _find_section_end(lines, ruler_pos)
        sections.append(lines[start:end])
    return sections


@register(OS.CISCO_IOSXE, "show processes cpu history")
class ShowProcessesCpuHistoryParser(
    BaseParser["ShowProcessesCpuHistoryResult"],
):
    """Parser for 'show processes cpu history' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowProcessesCpuHistoryResult:
        """Parse 'show processes cpu history' output."""
        result: dict = {}
        for section_lines in _split_into_sections(output.splitlines()):
            parsed = _parse_section(section_lines)
            if parsed is not None:
                key = _PERIOD_TO_KEY.get(parsed["period"])
                if key:
                    result[key] = parsed
        return cast(ShowProcessesCpuHistoryResult, result)
