"""Parser for 'show logging onboard rp active environment detail' on IOS-XE."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class HardwareInfo(TypedDict):
    """Schema for hardware identification fields."""

    vid: str
    pid: str
    tan: str
    serial_no: str


class SummaryEntry(TypedDict):
    """Schema for a single environment summary entry."""

    date: str
    time: str
    ins_count: int
    rem_count: int
    hardware: NotRequired[HardwareInfo]


class ContinuousEntry(TypedDict):
    """Schema for a single environment continuous entry."""

    date: str
    time: str
    device_name: str
    ios_version: str
    fw_version: int
    bios_version: str
    ram_kb: int
    event: str
    hardware: NotRequired[HardwareInfo]


class ShowLoggingOnboardRpActiveEnvironmentDetailResult(TypedDict):
    """Schema for 'show logging onboard rp active environment detail' output."""

    summary: dict[str, SummaryEntry]
    continuous: dict[str, ContinuousEntry]


# Section headers
_SUMMARY_HEADER = re.compile(r"^ENVIRONMENT\s+SUMMARY\s+INFORMATION$")
_CONTINUOUS_HEADER = re.compile(r"^ENVIRONMENT\s+CONTINUOUS\s+INFORMATION$")

# Separator lines: ----...
_SEPARATOR = re.compile(r"^-{3,}$")

# Column header lines to skip
_COLUMN_HEADER = re.compile(r"^(?:MM/DD/YYYY|VID)\s+", re.IGNORECASE)

# Summary data row: 04/04/2023 10:36:47 27         0
_SUMMARY_ROW = re.compile(
    r"^(?P<date>\d{2}/\d{2}/\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<ins_count>\d+)\s+"
    r"(?P<rem_count>\d+)\s*$"
)

# Continuous data row:
# 03/30/2023 02:32:41 obfl0:             17.06.04    386204  17.10.1r 0       Ins
_CONTINUOUS_ROW = re.compile(
    r"^(?P<date>\d{2}/\d{2}/\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<device_name>\S+?):\s+"
    r"(?P<ios_version>\S+)\s+"
    r"(?P<fw_version>\d+)\s+"
    r"(?P<bios_version>\S+)\s+"
    r"(?P<ram_kb>\d+)\s+"
    r"(?P<event>\S+)\s*$"
)

# Hardware info row (indented):  V01 C9407-FAN    C1   FXS222800XL
_HARDWARE_ROW = re.compile(
    r"^(?P<vid>\S+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<tan>\S+)\s+"
    r"(?P<serial_no>\S+)\s*$"
)

# Section identifiers
_SECTION_SUMMARY = "summary"
_SECTION_CONTINUOUS = "continuous"


def _make_unique_key(base_key: str, existing: dict[str, Any]) -> str:
    """Generate a unique key by appending a numeric suffix if needed."""
    if base_key not in existing:
        return base_key
    counter = 2
    while f"{base_key}_{counter}" in existing:
        counter += 1
    return f"{base_key}_{counter}"


def _parse_hardware(line: str) -> HardwareInfo | None:
    """Attempt to parse a hardware info line."""
    match = _HARDWARE_ROW.match(line)
    if not match:
        return None
    return HardwareInfo(
        vid=match.group("vid"),
        pid=match.group("pid"),
        tan=match.group("tan"),
        serial_no=match.group("serial_no"),
    )


def _is_skip_line(line: str) -> bool:
    """Check if a line is a header, separator, or otherwise non-data."""
    if not line:
        return True
    if _SEPARATOR.match(line):
        return True
    if _COLUMN_HEADER.match(line):
        return True
    return False


@register(OS.CISCO_IOSXE, "show logging onboard rp active environment detail")
class ShowLoggingOnboardRpActiveEnvironmentDetailParser(
    BaseParser[ShowLoggingOnboardRpActiveEnvironmentDetailResult],
):
    """Parser for 'show logging onboard rp active environment detail'.

    Parses OBFL (Onboard Failure Logging) environment detail output that
    contains summary and continuous information about hardware insertion
    and removal events.

    Example output::

        ENVIRONMENT SUMMARY INFORMATION
        ----------------------------------------------------------------
        MM/DD/YYYY HH:MM:SS   Ins count    Rem count
                            VID PID              TAN          Serial No
        ----------------------------------------------------------------
        04/04/2023 10:36:47 27         0
                            V01 C9407-FAN        C1   FXS222800XL

        ENVIRONMENT CONTINUOUS INFORMATION
        ----------------------------------------------------------------
        MM/DD/YYYY HH:MM:SS Device Name    IOS Version F/W Ver BIOSVer RAM(KB) Event
                            VID PID              TAN          Serial No
        ----------------------------------------------------------------
        03/30/2023 02:32:41 obfl0:         17.06.04    386204  17.10.1r 0   Ins
                            V01 C9407-FAN        C1   FXS222800XL
    """

    tags: ClassVar[frozenset[str]] = frozenset({"environment", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowLoggingOnboardRpActiveEnvironmentDetailResult:
        """Parse 'show logging onboard rp active environment detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed environment detail data with summary and continuous sections,
            keyed by timestamp.

        Raises:
            ValueError: If no environment data is found in the output.
        """
        summary: dict[str, SummaryEntry] = {}
        continuous: dict[str, ContinuousEntry] = {}
        current_section: str | None = None
        last_summary_key: str | None = None
        last_continuous_key: str | None = None

        for line in output.splitlines():
            stripped = line.strip()

            if _SUMMARY_HEADER.match(stripped):
                current_section = _SECTION_SUMMARY
                continue

            if _CONTINUOUS_HEADER.match(stripped):
                current_section = _SECTION_CONTINUOUS
                continue

            if _is_skip_line(stripped):
                continue

            if current_section == _SECTION_SUMMARY:
                last_summary_key = _process_summary_line(
                    stripped, summary, last_summary_key
                )
            elif current_section == _SECTION_CONTINUOUS:
                last_continuous_key = _process_continuous_line(
                    stripped, continuous, last_continuous_key
                )

        if not summary and not continuous:
            msg = "No environment data found in output"
            raise ValueError(msg)

        return ShowLoggingOnboardRpActiveEnvironmentDetailResult(
            summary=summary,
            continuous=continuous,
        )


def _process_summary_line(
    line: str,
    summary: dict[str, SummaryEntry],
    last_key: str | None,
) -> str | None:
    """Process a line in the summary section. Returns the current entry key."""
    match = _SUMMARY_ROW.match(line)
    if match:
        date = match.group("date")
        time = match.group("time")
        base_key = f"{date} {time}"
        key = _make_unique_key(base_key, summary)
        summary[key] = SummaryEntry(
            date=date,
            time=time,
            ins_count=int(match.group("ins_count")),
            rem_count=int(match.group("rem_count")),
        )
        return key

    hw = _parse_hardware(line)
    if hw and last_key and last_key in summary:
        summary[last_key]["hardware"] = hw

    return last_key


def _process_continuous_line(
    line: str,
    continuous: dict[str, ContinuousEntry],
    last_key: str | None,
) -> str | None:
    """Process a line in the continuous section. Returns the current entry key."""
    match = _CONTINUOUS_ROW.match(line)
    if match:
        date = match.group("date")
        time = match.group("time")
        base_key = f"{date} {time}"
        key = _make_unique_key(base_key, continuous)
        continuous[key] = ContinuousEntry(
            date=date,
            time=time,
            device_name=match.group("device_name"),
            ios_version=match.group("ios_version"),
            fw_version=int(match.group("fw_version")),
            bios_version=match.group("bios_version"),
            ram_kb=int(match.group("ram_kb")),
            event=match.group("event"),
        )
        return key

    hw = _parse_hardware(line)
    if hw and last_key and last_key in continuous:
        continuous[last_key]["hardware"] = hw

    return last_key
