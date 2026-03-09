"""Parser for 'show platform packet-trace all' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class TimestampEntry(TypedDict):
    """Schema for packet timestamp information."""

    start_ns: int
    start_utc: str
    stop_ns: int
    stop_utc: str


class PacketTraceEntry(TypedDict):
    """Schema for a single packet trace entry."""

    cbug_id: int
    input: str
    output: str
    state: str
    timestamp: TimestampEntry
    punt_cause: NotRequired[str]


class ShowPlatformPacketTraceAllResult(TypedDict):
    """Schema for 'show platform packet-trace all' parsed output."""

    packets: dict[str, PacketTraceEntry]


_PACKET_HEADER_RE = re.compile(
    r"^Packet:\s+(?P<packet_num>\d+)\s+CBUG\s+ID:\s+(?P<cbug_id>\d+)\s*$"
)
_INPUT_RE = re.compile(r"^\s+Input\s+:\s+(?P<input>\S+)\s*$")
_OUTPUT_RE = re.compile(r"^\s+Output\s+:\s+(?P<output>\S+)\s*$")
_STATE_RE = re.compile(r"^\s+State\s+:\s+(?P<state_line>.+)$")
_PUNT_DETAIL_RE = re.compile(
    r"^(?P<state>\S+)\s+(?P<punt_code>\d+)\s+\((?P<punt_cause>[^)]+)\)\s*$"
)
_TIMESTAMP_START_RE = re.compile(
    r"^\s+Start\s+:\s+(?P<ns>\d+)\s+ns\s+\((?P<utc>[^)]+)\)\s*$"
)
_TIMESTAMP_STOP_RE = re.compile(
    r"^\s+Stop\s+:\s+(?P<ns>\d+)\s+ns\s+\((?P<utc>[^)]+)\)\s*$"
)

# Interface names that should NOT be canonicalized (internal/injector interfaces)
_INTERNAL_INTERFACE_RE = re.compile(r"^(?:internal|INJ)\b", re.I)

# Section boundary markers that end summary parsing
_SECTION_END_MARKERS = {"Path Trace", ""}


def _normalize_interface(name: str) -> str:
    """Canonicalize interface names, leaving internal interfaces unchanged."""
    if _INTERNAL_INTERFACE_RE.match(name):
        return name
    return canonical_interface_name(name, os=OS.CISCO_IOSXE)


def _new_accumulator(packet_num: str, cbug_id: int) -> dict:
    """Create a fresh accumulator for collecting packet summary fields."""
    return {
        "packet_num": packet_num,
        "cbug_id": cbug_id,
        "input": None,
        "output": None,
        "state": None,
        "punt_cause": None,
        "start_ns": None,
        "start_utc": None,
        "stop_ns": None,
        "stop_utc": None,
    }


def _apply_summary_line(acc: dict, line: str) -> None:
    """Match a summary-section line and update the accumulator in place."""
    if match := _INPUT_RE.match(line):
        acc["input"] = _normalize_interface(match.group("input"))
    elif match := _OUTPUT_RE.match(line):
        acc["output"] = _normalize_interface(match.group("output"))
    elif match := _STATE_RE.match(line):
        _parse_state(acc, match.group("state_line").strip())
    elif match := _TIMESTAMP_START_RE.match(line):
        acc["start_ns"] = int(match.group("ns"))
        acc["start_utc"] = match.group("utc")
    elif match := _TIMESTAMP_STOP_RE.match(line):
        acc["stop_ns"] = int(match.group("ns"))
        acc["stop_utc"] = match.group("utc")


def _parse_state(acc: dict, state_line: str) -> None:
    """Parse state text, extracting punt cause when present."""
    punt_match = _PUNT_DETAIL_RE.match(state_line)
    if punt_match:
        acc["state"] = punt_match.group("state")
        acc["punt_cause"] = punt_match.group("punt_cause")
    else:
        acc["state"] = state_line.split()[0]


def _flush_accumulator(
    packets: dict[str, PacketTraceEntry],
    acc: dict,
) -> None:
    """Validate accumulated fields and add the packet entry."""
    if acc["input"] is None or acc["output"] is None or acc["state"] is None:
        msg = f"Incomplete summary data for packet {acc['packet_num']}"
        raise ValueError(msg)
    if any(acc[k] is None for k in ("start_ns", "start_utc", "stop_ns", "stop_utc")):
        msg = f"Incomplete timestamp data for packet {acc['packet_num']}"
        raise ValueError(msg)

    entry: PacketTraceEntry = {
        "cbug_id": acc["cbug_id"],
        "input": acc["input"],
        "output": acc["output"],
        "state": acc["state"],
        "timestamp": {
            "start_ns": acc["start_ns"],
            "start_utc": acc["start_utc"],
            "stop_ns": acc["stop_ns"],
            "stop_utc": acc["stop_utc"],
        },
    }
    if acc["punt_cause"] is not None:
        entry["punt_cause"] = acc["punt_cause"]

    packets[acc["packet_num"]] = entry


def _is_section_boundary(stripped: str) -> bool:
    """Check if a stripped line marks a section boundary."""
    return (
        stripped in _SECTION_END_MARKERS
        or stripped.startswith("IOSd Path Flow:")
        or stripped == "Path Trace"
    )


def _parse_packets(output: str) -> dict[str, PacketTraceEntry]:
    """Parse all packet trace entries from raw output.

    Args:
        output: Raw CLI output.

    Returns:
        Dict of packet entries keyed by packet number.
    """
    packets: dict[str, PacketTraceEntry] = {}
    acc: dict | None = None
    in_summary = False

    for line in output.splitlines():
        header_match = _PACKET_HEADER_RE.match(line)
        if header_match:
            if acc is not None:
                _flush_accumulator(packets, acc)
            acc = _new_accumulator(
                header_match.group("packet_num"),
                int(header_match.group("cbug_id")),
            )
            in_summary = False
            continue

        if acc is None:
            continue

        stripped = line.strip()
        if stripped == "Summary":
            in_summary = True
        elif _is_section_boundary(stripped):
            in_summary = False
        elif in_summary and stripped != "Timestamp":
            _apply_summary_line(acc, line)

    if acc is not None:
        _flush_accumulator(packets, acc)

    return packets


@register(OS.CISCO_IOSXE, "show platform packet-trace all")
class ShowPlatformPacketTraceAllParser(
    BaseParser[ShowPlatformPacketTraceAllResult],
):
    """Parser for 'show platform packet-trace all' command.

    Example output::

        Packet: 0           CBUG ID: 104
        Summary
          Input     : INJ.2
          Output    : GigabitEthernet1
          State     : FWD
          Timestamp
            Start   : 19591545483878568 ns (07/27/2021 09:34:27.497712 UTC)
            Stop    : 19591545483897048 ns (07/27/2021 09:34:27.497731 UTC)
    """

    @classmethod
    def parse(cls, output: str) -> ShowPlatformPacketTraceAllResult:
        """Parse 'show platform packet-trace all' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed packet trace data keyed by packet number.

        Raises:
            ValueError: If no packet trace entries are found.
        """
        packets = _parse_packets(output)
        if not packets:
            msg = "No packet trace entries found in output"
            raise ValueError(msg)

        return ShowPlatformPacketTraceAllResult(packets=packets)
