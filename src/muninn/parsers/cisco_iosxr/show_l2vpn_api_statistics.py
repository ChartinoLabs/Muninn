"""Parser for 'show l2vpn api-statistics' on Cisco IOS-XR.

This is a parameterized parser that handles all 217+ variants of the
show l2vpn api-statistics command family. The output structure is identical
across all subsystem/mode/api_name combinations — only the header and API
name change.
"""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class CallDetailEntry(TypedDict):
    """Schema for a timestamped call detail block.

    Attributes:
        timestamp: The timestamp string or "Never" /
            "Not enough information".
        bulk: The bulk count, if present.
        time_ms: The time in ms, if present. None when "-".
        result_code: The hex result code (e.g., "0x0").
        result_text: Human-readable result text.
        info: The info line text, or None if "None available".
    """

    timestamp: str
    bulk: NotRequired[int]
    time_ms: NotRequired[float | None]
    result_code: NotRequired[str]
    result_text: NotRequired[str]
    info: NotRequired[str | None]


class ShowL2vpnApiStatisticsResult(TypedDict):
    """Schema for 'show l2vpn api-statistics' parsed output.

    Attributes:
        subsystem: The API subsystem name (e.g., "SysDB", "IM").
        api_name: The specific API name (e.g., "sysdb_bind").
        mode: The call mode — "async" or "sync".
        calls_all: Total number of calls.
        calls_ok: Number of successful calls.
        calls_fail: Number of failed calls.
        size_min: Minimum bulk size.
        size_max: Maximum bulk size.
        size_avg: Average bulk size.
        avg_time_all_ms: Avg time for all calls in ms, or None.
        avg_time_ok_ms: Avg time for OK calls in ms, or None.
        avg_time_fail_ms: Avg time for failed calls in ms, or None.
        last_success: Last successful call detail.
        last_bulk_fail: Last bulk failure detail.
        last_indv_fail: Last individual failure detail.
        last_long_call: Last long call detail.
        longest_call: Longest call detail.
        smallest_bulk: Smallest bulk detail.
        largest_bulk: Largest bulk detail.
    """

    subsystem: str
    api_name: str
    mode: str
    calls_all: int
    calls_ok: int
    calls_fail: int
    size_min: int
    size_max: int
    size_avg: int
    avg_time_all_ms: float | None
    avg_time_ok_ms: float | None
    avg_time_fail_ms: float | None
    last_success: CallDetailEntry
    last_bulk_fail: CallDetailEntry
    last_indv_fail: CallDetailEntry
    last_long_call: CallDetailEntry
    longest_call: CallDetailEntry
    smallest_bulk: CallDetailEntry
    largest_bulk: CallDetailEntry


# Header line: "SysDB API stats" or "IM API stats" etc.
_SUBSYSTEM_RE = re.compile(r"^(?P<subsystem>\S+)\s+API\s+stats\s*$")

# API name and mode: "sysdb_bind (async):" or "im_bind (sync):"
_API_NAME_RE = re.compile(r"^(?P<api_name>\S+)\s+\((?P<mode>async|sync)\):\s*$")

# Calls: "  Calls (All/OK/Fail):     10/10/0"
_CALLS_RE = re.compile(
    r"^\s+Calls\s+\(All/OK/Fail\):\s+"
    r"(?P<all>\d+)/(?P<ok>\d+)/(?P<fail>\d+)\s*$"
)

# Size: "  Size (Min/Max/Avg):      1/2/1"
_SIZE_RE = re.compile(
    r"^\s+Size\s+\(Min/Max/Avg\):\s+"
    r"(?P<min>\d+)/(?P<max>\d+)/(?P<avg>\d+)\s*$"
)

# Avg time: "  Avg time (All/OK/Fail):  0.5/0.5/- ms"
_AVG_TIME_RE = re.compile(
    r"^\s+Avg\s+time\s+\(All/OK/Fail\):\s+"
    r"(?P<all>[0-9.]+|-)/(?P<ok>[0-9.]+|-)/(?P<fail>[0-9.]+|-)"
    r"\s+ms\s*$"
)

# Detail timestamp header (Last success, Longest call, etc.)
_DETAIL_RE = re.compile(
    r"^\s+(?P<label>"
    r"Last\s+success|Last\s+bulk\s+fail|Last\s+indv\s+fail|"
    r"Last\s+long\s+call|Longest\s+call|"
    r"Smallest\s+bulk|Largest\s+bulk"
    r")\s+:\s+(?P<rest>.+)$"
)

# Timestamp with (bulk=N, time=N ms)
_TS_INFO_RE = re.compile(
    r"^(?P<ts>.+?)\s+"
    r"\(bulk=(?P<bulk>\d+),\s+time=(?P<time>[0-9.]+|-)\s+ms\)\s*$"
)

# Result line: "    Result:          code 0x0: Success"
_RESULT_RE = re.compile(
    r"^\s+Result:\s+code\s+(?P<code>0x[0-9a-fA-F]+):\s+(?P<text>.+)$"
)

# Info line: "    Info:            ..."
_INFO_RE = re.compile(r"^\s+Info:\s+(?P<info>.+)$")

# Map normalized label to result dict key
_LABEL_TO_KEY: dict[str, str] = {
    "Last success": "last_success",
    "Last bulk fail": "last_bulk_fail",
    "Last indv fail": "last_indv_fail",
    "Last long call": "last_long_call",
    "Longest call": "longest_call",
    "Smallest bulk": "smallest_bulk",
    "Largest bulk": "largest_bulk",
}

_ALL_DETAIL_KEYS = tuple(_LABEL_TO_KEY.values())

# Command registration pattern (split for readability)
_CMD_PATTERN = (
    r"show l2vpn api-statistics (?P<subsystem>\S+) "
    r"detail (?P<mode>\S+) api (?P<api_name>\S+)"
)


def _parse_time(raw: str) -> float | None:
    """Parse a time value string, returning None for '-'."""
    if raw == "-":
        return None
    return float(raw)


def _normalize_label(label: str) -> str:
    """Normalize a label by collapsing whitespace."""
    return re.sub(r"\s+", " ", label.strip())


def _parse_detail_rest(rest: str) -> CallDetailEntry:
    """Parse the value portion of a detail header line.

    Args:
        rest: Text after the ": " on a detail line.

    Returns:
        A CallDetailEntry with at minimum a timestamp field.
    """
    ts_match = _TS_INFO_RE.match(rest)
    if ts_match:
        return {
            "timestamp": ts_match.group("ts").strip(),
            "bulk": int(ts_match.group("bulk")),
            "time_ms": _parse_time(ts_match.group("time")),
        }
    return {"timestamp": rest}


def _parse_counters(
    lines: list[str],
) -> tuple[
    str | None,
    str | None,
    str | None,
    int,
    int,
    int,
    int,
    int,
    int,
    float | None,
    float | None,
    float | None,
]:
    """Parse header, API name, and counter lines.

    Returns:
        Tuple of (subsystem, api_name, mode, calls_all, calls_ok,
        calls_fail, size_min, size_max, size_avg, avg_all,
        avg_ok, avg_fail).
    """
    subsystem: str | None = None
    api_name: str | None = None
    mode: str | None = None
    calls_all = calls_ok = calls_fail = 0
    size_min = size_max = size_avg = 0
    avg_all: float | None = None
    avg_ok: float | None = None
    avg_fail: float | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        m = _SUBSYSTEM_RE.match(stripped)
        if m:
            subsystem = m.group("subsystem")
            continue

        m = _API_NAME_RE.match(stripped)
        if m:
            api_name = m.group("api_name")
            mode = m.group("mode")
            continue

        m = _CALLS_RE.match(line)
        if m:
            calls_all = int(m.group("all"))
            calls_ok = int(m.group("ok"))
            calls_fail = int(m.group("fail"))
            continue

        m = _SIZE_RE.match(line)
        if m:
            size_min = int(m.group("min"))
            size_max = int(m.group("max"))
            size_avg = int(m.group("avg"))
            continue

        m = _AVG_TIME_RE.match(line)
        if m:
            avg_all = _parse_time(m.group("all"))
            avg_ok = _parse_time(m.group("ok"))
            avg_fail = _parse_time(m.group("fail"))
            continue

    return (
        subsystem,
        api_name,
        mode,
        calls_all,
        calls_ok,
        calls_fail,
        size_min,
        size_max,
        size_avg,
        avg_all,
        avg_ok,
        avg_fail,
    )


def _parse_details(lines: list[str]) -> dict[str, CallDetailEntry]:
    """Parse detail entry blocks from output lines.

    Args:
        lines: All output lines.

    Returns:
        Dict mapping detail key names to their parsed entries.
    """
    entries: dict[str, CallDetailEntry] = {}
    current_key: str | None = None

    for line in lines:
        # Detail header
        m = _DETAIL_RE.match(line)
        if m:
            label = _normalize_label(m.group("label"))
            key = _LABEL_TO_KEY.get(label)
            if key:
                current_key = key
                entries[key] = _parse_detail_rest(m.group("rest").strip())
            continue

        # Result sub-line
        m = _RESULT_RE.match(line)
        if m and current_key and current_key in entries:
            entries[current_key]["result_code"] = m.group("code")
            entries[current_key]["result_text"] = m.group("text").strip()
            continue

        # Info sub-line
        m = _INFO_RE.match(line)
        if m and current_key and current_key in entries:
            info_text = m.group("info").strip()
            entries[current_key]["info"] = (
                None if info_text == "None available" else info_text
            )
            continue

    return entries


@register(OS.CISCO_IOSXR, _CMD_PATTERN)
class ShowL2vpnApiStatisticsParser(
    BaseParser["ShowL2vpnApiStatisticsResult"],
):
    """Parser for 'show l2vpn api-statistics' on Cisco IOS-XR.

    Parses L2VPN API statistics including call counters, timing,
    and detailed per-event entries. This single parameterized parser
    handles all 217+ command variants.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> "ShowL2vpnApiStatisticsResult":
        """Parse 'show l2vpn api-statistics' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed API statistics data.

        Raises:
            ValueError: If required data is not found in output.
        """
        lines = output.splitlines()

        (
            subsystem,
            api_name,
            mode,
            calls_all,
            calls_ok,
            calls_fail,
            size_min,
            size_max,
            size_avg,
            avg_all,
            avg_ok,
            avg_fail,
        ) = _parse_counters(lines)

        if subsystem is None or api_name is None:
            msg = "No L2VPN API statistics data found in output"
            raise ValueError(msg)

        detail_entries = _parse_details(lines)

        # Fill missing detail keys with default "Never" entry
        for dk in _ALL_DETAIL_KEYS:
            if dk not in detail_entries:
                detail_entries[dk] = {"timestamp": "Never"}

        # Filter None values from detail entries
        def _clean(d: dict) -> dict:
            return {k: v for k, v in d.items() if v is not None}

        result: dict = {
            "subsystem": subsystem,
            "api_name": api_name,
            "mode": mode or "async",
            "calls_all": calls_all,
            "calls_ok": calls_ok,
            "calls_fail": calls_fail,
            "size_min": size_min,
            "size_max": size_max,
            "size_avg": size_avg,
            "last_success": _clean(detail_entries["last_success"]),
            "last_bulk_fail": _clean(detail_entries["last_bulk_fail"]),
            "last_indv_fail": _clean(detail_entries["last_indv_fail"]),
            "last_long_call": _clean(detail_entries["last_long_call"]),
            "longest_call": _clean(detail_entries["longest_call"]),
            "smallest_bulk": _clean(detail_entries["smallest_bulk"]),
            "largest_bulk": _clean(detail_entries["largest_bulk"]),
        }
        if avg_all is not None:
            result["avg_time_all_ms"] = avg_all
        if avg_ok is not None:
            result["avg_time_ok_ms"] = avg_ok
        if avg_fail is not None:
            result["avg_time_fail_ms"] = avg_fail
        return result
