"""Parser for 'show ntp status' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowNtpStatusResult(TypedDict):
    """Schema for 'show ntp status' parsed output.

    Captures NTP daemon status information including synchronization state,
    stratum, reference clock, and timing statistics from Juniper Junos devices.
    """

    status: str
    leap: str
    sync: str
    events: int
    event_description: str
    version: str
    processor: str
    system: str
    leap_indicator: int
    stratum: int
    precision: int
    rootdelay: float
    rootdispersion: float
    peer: int
    refid: str
    reftime: str
    poll: int
    clock: str
    state: int
    offset: float
    frequency: float
    jitter: float
    stability: float


# Pattern for the first status line:
# status=0644 leap_none, sync_ntp, 4 events, event_peer/strat_chg,
_STATUS_LINE_PATTERN = re.compile(
    r"status=(?P<status>\w+)\s+"
    r"(?P<leap>leap_\w+),\s+"
    r"(?P<sync>sync_\w+),\s+"
    r"(?P<events>\d+)\s+events?,\s+"
    r"(?P<event_description>\S+?)(?:,\s*)?$",
)

# Pattern for key=value pairs in the remaining lines
_KV_PATTERN = re.compile(
    r'(?P<key>\w+)=(?:"(?P<qval>[^"]+)"|(?P<val>[^,]+?))\s*(?:,|$)',
)


@register(OS.JUNIPER_JUNOS, "show ntp status")
class ShowNtpStatusParser(BaseParser[ShowNtpStatusResult]):
    """Parser for 'show ntp status' command on Juniper Junos.

    Parses NTP daemon status output including synchronization source,
    stratum, reference ID, and timing statistics (offset, jitter, etc.).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    # Fields that should be parsed as integers
    _INT_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"stratum", "precision", "peer", "poll", "state", "events"}
    )

    # Fields that should be parsed as floats
    _FLOAT_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"rootdelay", "rootdispersion", "offset", "frequency", "jitter", "stability"}
    )

    @classmethod
    def _parse_status_line(cls, line: str) -> dict[str, object] | None:
        """Parse the first status line into its components."""
        match = _STATUS_LINE_PATTERN.search(line)
        if not match:
            return None
        return {
            "status": match.group("status"),
            "leap": match.group("leap"),
            "sync": match.group("sync"),
            "events": int(match.group("events")),
            "event_description": match.group("event_description"),
        }

    @classmethod
    def _coerce_value(cls, key: str, raw: str) -> object:
        """Coerce a raw string value to the appropriate Python type."""
        stripped = raw.strip()
        if key in cls._INT_FIELDS:
            return int(stripped)
        if key in cls._FLOAT_FIELDS:
            return float(stripped)
        return stripped

    @classmethod
    def _parse_kv_line(cls, line: str, result: dict[str, object]) -> None:
        """Extract key=value pairs from a line and update result."""
        # Special handling for reftime and clock which contain embedded spaces
        # e.g. reftime=df981acf.bfa97435  Thu, Nov 15 2018 11:18:23.748
        # e.g. clock=df981ae8.eb6e7ee8  Thu, Nov 15 2018 11:18:48.919
        for time_key in ("reftime", "clock"):
            pattern = re.compile(
                rf"{time_key}=(?P<val>[0-9a-fA-F]+\.[0-9a-fA-F]+\s+\S+,\s+\S+\s+\d+\s+\d+\s+[\d:.]+)"
            )
            match = pattern.search(line)
            if match:
                result[time_key] = match.group("val").strip()
                # Remove the matched portion to avoid re-parsing
                line = line[: match.start()] + line[match.end() :]

        # Special handling for leap= (rename to leap_indicator to avoid
        # collision with the "leap" field from the status line)
        leap_match = re.search(r"leap=(\d+)", line)
        if leap_match:
            result["leap_indicator"] = int(leap_match.group(1))
            line = line[: leap_match.start()] + line[leap_match.end() :]

        for match in _KV_PATTERN.finditer(line):
            key = match.group("key")
            quoted = match.group("qval")
            val = quoted if quoted is not None else match.group("val")

            # Skip keys already handled specially
            if key in ("reftime", "clock", "leap"):
                continue

            result[key] = cls._coerce_value(key, val)

    # Prompt pattern (e.g. "root@junos_vmx1> show ntp status")
    _PROMPT_PATTERN = re.compile(r".*>.*show ntp status")

    _REQUIRED_FIELDS: ClassVar[tuple[str, ...]] = (
        "status",
        "stratum",
        "refid",
    )

    @classmethod
    def _is_content_line(cls, stripped: str) -> bool:
        """Return True if the line contains parseable content."""
        if not stripped:
            return False
        return not cls._PROMPT_PATTERN.match(stripped)

    @classmethod
    def _validate(cls, result: dict[str, object], status_parsed: bool) -> None:
        """Validate that all required fields were parsed."""
        if not status_parsed:
            msg = "No NTP status line found in output"
            raise ValueError(msg)
        missing = [f for f in cls._REQUIRED_FIELDS if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

    @classmethod
    def parse(cls, output: str) -> ShowNtpStatusResult:
        """Parse 'show ntp status' output on Juniper Junos.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed NTP status information.

        Raises:
            ValueError: If the status line cannot be parsed.
        """
        result: dict[str, object] = {}
        status_parsed = False

        for line in output.splitlines():
            stripped = line.strip()
            if not cls._is_content_line(stripped):
                continue

            if not status_parsed:
                status_data = cls._parse_status_line(stripped)
                if status_data:
                    result.update(status_data)
                    status_parsed = True
                    continue

            cls._parse_kv_line(stripped, result)

        cls._validate(result, status_parsed)
        return ShowNtpStatusResult(**result)  # type: ignore[typeddict-item]
