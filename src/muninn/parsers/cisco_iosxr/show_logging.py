"""Parser for 'show logging' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LogEntry(TypedDict):
    """Schema for a single syslog message entry."""

    node: str
    timestamp: str
    process: str
    pid: int
    message: str


class ShowLoggingResult(TypedDict):
    """Schema for 'show logging' parsed output on IOS-XR."""

    # Global syslog state
    syslog_logging_enabled: bool
    messages_dropped: int
    flushes: int
    overruns: int

    # Console logging
    console_logging_enabled: bool
    console_logging_level: NotRequired[str]
    console_logging_messages_logged: NotRequired[int]

    # Monitor logging
    monitor_logging_level: str
    monitor_logging_messages_logged: int

    # Trap logging
    trap_logging_level: str
    trap_logging_messages_logged: int

    # Buffer logging
    buffer_logging_level: str
    buffer_logging_messages_logged: int
    buffer_size_bytes: int

    # Log entries from the buffer
    log_entries: list[LogEntry]


@register(OS.CISCO_IOSXR, "show logging")
class ShowLoggingParser(BaseParser[ShowLoggingResult]):
    """Parser for 'show logging' command on Cisco IOS-XR.

    Parses logging configuration (console, monitor, trap, buffer levels)
    and syslog message entries from the log buffer.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LOGGING})

    # Syslog logging: enabled (0 messages dropped, 0 flushes, 0 overruns)
    _SYSLOG_STATUS = re.compile(
        r"Syslog logging:\s+(?P<state>\S+)\s+"
        r"\((?P<dropped>\d+)\s+messages?\s+dropped,\s+"
        r"(?P<flushes>\d+)\s+flushes?,\s+"
        r"(?P<overruns>\d+)\s+overruns?\)",
    )

    # Console logging: Disabled
    # Console logging: level warnings, 42 messages logged
    _CONSOLE_LOGGING = re.compile(
        r"Console logging:\s+"
        r"(?:(?P<disabled>Disabled)|level\s+(?P<level>\S+),\s+"
        r"(?P<count>\d+)\s+messages?\s+logged)",
        re.I,
    )

    # Monitor logging: level debugging, 0 messages logged
    _MONITOR_LOGGING = re.compile(
        r"Monitor logging:\s+level\s+(?P<level>\S+),\s+"
        r"(?P<count>\d+)\s+messages?\s+logged",
        re.I,
    )

    # Trap logging: level informational, 0 messages logged
    _TRAP_LOGGING = re.compile(
        r"Trap logging:\s+level\s+(?P<level>\S+),\s+"
        r"(?P<count>\d+)\s+messages?\s+logged",
        re.I,
    )

    # Buffer logging: level debugging, 114 messages logged
    _BUFFER_LOGGING = re.compile(
        r"Buffer logging:\s+level\s+(?P<level>\S+),\s+"
        r"(?P<count>\d+)\s+messages?\s+logged",
        re.I,
    )

    # Log Buffer (2097152 bytes):
    _BUFFER_SIZE = re.compile(
        r"Log Buffer\s+\((?P<size>\d+)\s+bytes\)",
    )

    # Log entry: RP/0/RP0/CPU0:Sep 25 23:24:28.852 UTC: spp[113]: message text
    # Also handles admin node format: 0/RP0/ADMIN0:Sep 25 ...
    _LOG_ENTRY = re.compile(
        r"^(?P<node>\S+?):(?P<timestamp>\w+\s+\d+\s+[\d:.]+\s+\S+):\s+"
        r"(?P<process>[^\[]+)\[(?P<pid>\d+)\]:\s+(?P<message>.+)$",
    )

    @classmethod
    def _parse_config_line(cls, line: str, result: dict[str, object]) -> bool:
        """Parse logging config lines (syslog, console, monitor, trap, buffer)."""
        if match := cls._SYSLOG_STATUS.search(line):
            result["syslog_logging_enabled"] = match.group("state").lower() == "enabled"
            result["messages_dropped"] = int(match.group("dropped"))
            result["flushes"] = int(match.group("flushes"))
            result["overruns"] = int(match.group("overruns"))
            return True

        if match := cls._CONSOLE_LOGGING.search(line):
            if match.group("disabled"):
                result["console_logging_enabled"] = False
            else:
                result["console_logging_enabled"] = True
                result["console_logging_level"] = match.group("level")
                result["console_logging_messages_logged"] = int(match.group("count"))
            return True

        if match := cls._MONITOR_LOGGING.search(line):
            result["monitor_logging_level"] = match.group("level")
            result["monitor_logging_messages_logged"] = int(match.group("count"))
            return True

        if match := cls._TRAP_LOGGING.search(line):
            result["trap_logging_level"] = match.group("level")
            result["trap_logging_messages_logged"] = int(match.group("count"))
            return True

        if match := cls._BUFFER_LOGGING.search(line):
            result["buffer_logging_level"] = match.group("level")
            result["buffer_logging_messages_logged"] = int(match.group("count"))
            return True

        if match := cls._BUFFER_SIZE.search(line):
            result["buffer_size_bytes"] = int(match.group("size"))
            return True

        return False

    @classmethod
    def _parse_log_entry(cls, line: str) -> LogEntry | None:
        """Parse a single syslog buffer entry line, returning None if not matched."""
        if match := cls._LOG_ENTRY.match(line):
            return LogEntry(
                node=match.group("node"),
                timestamp=match.group("timestamp"),
                process=match.group("process"),
                pid=int(match.group("pid")),
                message=match.group("message"),
            )
        return None

    @classmethod
    def parse(cls, output: str) -> ShowLoggingResult:
        """Parse 'show logging' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed logging configuration and log entries.

        Raises:
            ValueError: If required syslog status line cannot be parsed.
        """
        result: dict[str, object] = {}
        log_entries: list[LogEntry] = []

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if cls._parse_config_line(stripped, result):
                continue

            entry = cls._parse_log_entry(stripped)
            if entry is not None:
                log_entries.append(entry)

        # Validate required fields
        if "syslog_logging_enabled" not in result:
            msg = "Could not parse syslog logging status from output"
            raise ValueError(msg)

        result["log_entries"] = log_entries

        return result  # type: ignore[return-value]
