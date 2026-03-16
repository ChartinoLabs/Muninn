"""Parser for 'show logging onboard rp active counter detail' command on IOS-XE."""

import re
from collections.abc import Mapping
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class CounterSummaryEntry(TypedDict):
    """Schema for a single counter summary entry."""

    error_type: int
    pid: str
    tan: str
    serial_number: str
    count: int
    vid: NotRequired[str]


class CounterContinuousDeviceInfo(TypedDict):
    """Schema for device info in a continuous counter log entry."""

    devname: str
    slot: int
    error_type: int
    count: int
    vid: str
    pid: str
    tan: str
    serial_number: str


class ShowLoggingOnboardRpActiveCounterDetailResult(TypedDict):
    """Schema for 'show logging onboard rp active counter detail' parsed output."""

    summary: dict[str, CounterSummaryEntry]
    continuous: dict[str, CounterContinuousDeviceInfo]


# Section headers
_SUMMARY_HEADER = re.compile(r"^COUNTER\s+SUMMARY\s+INFORMATION$")
_CONTINUOUS_HEADER = re.compile(r"^COUNTER\s+LOGGING\s+CONTINUOUS\s+INFORMATION$")
_SEPARATOR = re.compile(r"^-{3,}$")

# Summary row with VID present:
# 1,V02,C9400-SUP-1XL       ,A0  ,JAE22350LQR,20
_SUMMARY_ROW_WITH_VID = re.compile(
    r"^(?P<error_type>\d+)"
    r",(?P<vid>\w+)"
    r",(?P<pid>[\w-]+)\s*"
    r",(?P<tan>\w+)\s*"
    r",(?P<sno>\w+)"
    r",(?P<count>\d+)$"
)

# Summary row without VID:
# 1,,C9400-SUP-1XL       ,A0  ,JAE22350LQR,20
_SUMMARY_ROW_NO_VID = re.compile(
    r"^(?P<error_type>\d+)"
    r",,"
    r"(?P<pid>[\w-]+)\s*"
    r",(?P<tan>\w+)\s*"
    r",(?P<sno>\w+)"
    r",(?P<count>\d+)$"
)

# "No historical data" placeholder in summary section
_NO_HISTORICAL_DATA = re.compile(r"^No\s+historical\s+data$")

# Continuous data row:
#  03/02/2023 03:08:48 obfl0:                4      1     20
_CONTINUOUS_ROW = re.compile(
    r"^\s*(?P<date>\d{2}/\d{2}/\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<devname>\w+):\s+"
    r"(?P<slot>\d+)\s+"
    r"(?P<typ>\d+)\s+"
    r"(?P<count>\d+)\s*$"
)

# Continuous VID/PID/TAN/Serial row:
#  V02   C9400-SUP-1XL        A0           JAE22350LQR
_CONTINUOUS_DETAIL = re.compile(
    r"^\s*(?P<vid>\w+)\s+"
    r"(?P<pid>[\w-]+)\s+"
    r"(?P<tan>\w+)\s+"
    r"(?P<serial_no>\w+)\s*$"
)


def _is_skip_line(line: str) -> bool:
    """Check if line should be skipped (headers, separators, column labels)."""
    if not line:
        return True
    if _SEPARATOR.match(line):
        return True
    if line.startswith("ERROR TYPE"):
        return True
    if line.startswith("MM/DD/YYYY"):
        return True
    if line.startswith("VID"):
        return True
    if line.strip().startswith("SNO"):
        return True
    return False


def _make_unique_key(base_key: str, existing: Mapping[str, object]) -> str:
    """Generate a unique key by appending a numeric suffix if needed."""
    if base_key not in existing:
        return base_key
    suffix = 2
    while f"{base_key}_{suffix}" in existing:
        suffix += 1
    return f"{base_key}_{suffix}"


def _parse_summary_match(
    match: re.Match[str],
    summary: dict[str, CounterSummaryEntry],
    has_vid: bool,
) -> None:
    """Build and store a summary entry from a regex match."""
    sno = match.group("sno")
    error_type = int(match.group("error_type"))
    key = _make_unique_key(f"{error_type}_{sno}", summary)
    entry = CounterSummaryEntry(
        error_type=error_type,
        pid=match.group("pid").strip(),
        tan=match.group("tan").strip(),
        serial_number=sno,
        count=int(match.group("count")),
    )
    if has_vid:
        entry["vid"] = match.group("vid")
    summary[key] = entry


@register(OS.CISCO_IOSXE, "show logging onboard rp active counter detail")
class ShowLoggingOnboardRpActiveCounterDetailParser(
    BaseParser[ShowLoggingOnboardRpActiveCounterDetailResult],
):
    """Parser for 'show logging onboard rp active counter detail' command.

    Parses OBFL counter detail output into summary and continuous sections.

    Example output::

        COUNTER SUMMARY INFORMATION
        ----------------------------------------------------------------
        ERROR TYPE | VID  |     PID    |      TAN    SNO         |  COUNT
        ----------------------------------------------------------------
        1,V02,C9400-SUP-1XL       ,A0  ,JAE22350LQR,20
        ----------------------------------------------------------------
        COUNTER LOGGING CONTINUOUS INFORMATION
        ----------------------------------------------------------------
        MM/DD/YYYY HH:MM:SS | DEVNAME   | SLOT | TYP | COUNT
         VID | PID           | TAN      | S.NO
        ----------------------------------------------------------------
         03/02/2023 03:08:48 obfl0:       4      1     20
         V02   C9400-SUP-1XL   A0         JAE22350LQR
    """

    @classmethod
    def parse(cls, output: str) -> ShowLoggingOnboardRpActiveCounterDetailResult:
        """Parse 'show logging onboard rp active counter detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed counter detail data with summary and continuous sections.

        Raises:
            ValueError: If no counter data is found in output.
        """
        summary: dict[str, CounterSummaryEntry] = {}
        continuous: dict[str, CounterContinuousDeviceInfo] = {}

        section: str | None = None
        pending_continuous_key: str | None = None
        pending_entry: dict[str, object] | None = None

        for line in output.splitlines():
            stripped = line.strip()

            if _is_skip_line(stripped):
                continue

            # Detect section transitions
            if _SUMMARY_HEADER.match(stripped):
                section = "summary"
                continue
            if _CONTINUOUS_HEADER.match(stripped):
                section = "continuous"
                continue

            if section == "summary":
                _process_summary_line(stripped, summary)
            elif section == "continuous":
                pending_continuous_key, pending_entry = _process_continuous_line(
                    stripped, continuous, pending_continuous_key, pending_entry
                )

        if not summary and not continuous:
            msg = "No counter data found in output"
            raise ValueError(msg)

        return ShowLoggingOnboardRpActiveCounterDetailResult(
            summary=summary,
            continuous=continuous,
        )


def _process_summary_line(
    line: str,
    summary: dict[str, CounterSummaryEntry],
) -> None:
    """Process a line within the summary section."""
    if _NO_HISTORICAL_DATA.match(line):
        return

    match = _SUMMARY_ROW_WITH_VID.match(line)
    if match:
        _parse_summary_match(match, summary, has_vid=True)
        return

    match = _SUMMARY_ROW_NO_VID.match(line)
    if match:
        _parse_summary_match(match, summary, has_vid=False)


def _process_continuous_line(
    line: str,
    continuous: dict[str, CounterContinuousDeviceInfo],
    pending_key: str | None,
    pending_entry: dict[str, object] | None,
) -> tuple[str | None, dict[str, object] | None]:
    """Process a line within the continuous section.

    Returns updated pending key and entry for two-line record pairing.
    """
    match = _CONTINUOUS_ROW.match(line)
    if match:
        date = match.group("date")
        time = match.group("time")
        key = _make_unique_key(f"{date}_{time}", continuous)
        entry: dict[str, object] = {
            "devname": match.group("devname"),
            "slot": int(match.group("slot")),
            "error_type": int(match.group("typ")),
            "count": int(match.group("count")),
        }
        return key, entry

    match = _CONTINUOUS_DETAIL.match(line)
    if match and pending_key is not None and pending_entry is not None:
        continuous[pending_key] = CounterContinuousDeviceInfo(
            devname=str(pending_entry["devname"]),
            slot=int(str(pending_entry["slot"])),
            error_type=int(str(pending_entry["error_type"])),
            count=int(str(pending_entry["count"])),
            vid=match.group("vid"),
            pid=match.group("pid"),
            tan=match.group("tan"),
            serial_number=match.group("serial_no"),
        )
        return None, None

    return pending_key, pending_entry
