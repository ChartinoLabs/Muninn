"""Parser for 'show logging' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class SyslogEntry(TypedDict):
    """Schema for syslog status."""

    enabled: bool
    messages_dropped: int
    messages_rate_limited: int
    flushes: int
    overruns: int
    xml_disabled: bool
    filtering_disabled: bool


class LoggingSectionEntry(TypedDict):
    """Schema for a logging section (console, monitor, buffer)."""

    enabled: NotRequired[bool]
    level: NotRequired[str]
    messages_logged: NotRequired[int]
    xml_disabled: NotRequired[bool]
    filtering_disabled: NotRequired[bool]


class ExceptionLoggingEntry(TypedDict):
    """Schema for exception logging."""

    size_bytes: int


class PersistentLoggingEntry(TypedDict):
    """Schema for persistent logging."""

    enabled: bool
    url: NotRequired[str]
    disk_space_bytes: NotRequired[int]
    file_size_bytes: NotRequired[int]
    batch_size_bytes: NotRequired[int]
    threshold_capacity: NotRequired[int]
    immediate: NotRequired[bool]
    protected: NotRequired[bool]
    notify: NotRequired[bool]


class TrapHostEntry(TypedDict):
    """Schema for a trap logging host."""

    protocol: str
    port: int
    audit_disabled: bool
    link_status: str
    message_lines_logged: int
    message_lines_rate_limited: int
    message_lines_dropped_by_md: int
    xml_disabled: bool
    sequence_number_disabled: bool
    filtering_disabled: bool


class TrapLoggingEntry(TypedDict):
    """Schema for trap logging."""

    level: str
    message_lines_logged: int
    hosts: NotRequired[dict[str, TrapHostEntry]]


class SourceInterfaceEntry(TypedDict):
    """Schema for a source interface entry."""

    interface: str
    vrf: NotRequired[str]


class LogMessageEntry(TypedDict):
    """Schema for a parsed log message."""

    sequence_number: NotRequired[int]
    timestamp: str
    timezone: NotRequired[str]
    facility: NotRequired[str]
    severity: NotRequired[int]
    mnemonic: NotRequired[str]
    message: str


class ShowLoggingResult(TypedDict):
    """Schema for 'show logging' parsed output."""

    syslog: SyslogEntry
    console_logging: LoggingSectionEntry
    monitor_logging: LoggingSectionEntry
    buffer_logging: LoggingSectionEntry
    exception_logging: NotRequired[ExceptionLoggingEntry]
    count_and_timestamp_logging: bool
    file_logging: NotRequired[LoggingSectionEntry]
    persistent_logging: NotRequired[PersistentLoggingEntry]
    trap_logging: TrapLoggingEntry
    source_interfaces: NotRequired[list[SourceInterfaceEntry]]
    log_buffer_size_bytes: int
    logs: list[LogMessageEntry]


# --- Regex patterns ---

_SYSLOG_RE = re.compile(
    r"Syslog logging:\s*(enabled|disabled)\s*\("
    r"(\d+)\s*messages?\s*dropped,\s*"
    r"(\d+)\s*messages?\s*rate-limited,\s*"
    r"(\d+)\s*flushes?,\s*"
    r"(\d+)\s*overruns?,\s*"
    r"xml\s*(disabled|enabled),\s*"
    r"filtering\s*(disabled|enabled)\)"
)

_CONSOLE_LEVEL_RE = re.compile(
    r"^\s*Console logging:\s*level\s+(\S+),\s*(\d+)\s*messages?\s*logged,\s*"
    r"xml\s*(disabled|enabled)"
)
_CONSOLE_DISABLED_RE = re.compile(r"^\s*Console logging:\s*disabled")

_SECTION_RE = re.compile(
    r"^\s*(Monitor|Buffer)\s+logging:\s*level\s+(\S+),\s*(\d+)\s*messages?\s*logged,\s*"
    r"xml\s*(disabled|enabled)"
)

_EXCEPTION_RE = re.compile(r"^\s*Exception Logging:\s*size\s*\((\d+)\s*bytes\)")

_COUNT_TS_RE = re.compile(
    r"^\s*Count and timestamp logging messages:\s*(disabled|enabled)"
)

_FILE_LOGGING_RE = re.compile(r"^\s*File logging:\s*(disabled|enabled)")

_PERSISTENT_RE = re.compile(
    r"^\s*Persistent logging:\s*(disabled|enabled)"
    r"(?:,\s*url\s+(\S+))?"
    r"(?:,\s*disk space\s+(\d+)\s*bytes)?"
    r"(?:,\s*file size\s+(\d+)\s*bytes)?"
    r"(?:,\s*batch size\s+(\d+)\s*bytes)?"
)
_PERSISTENT_OPTS_RE = re.compile(
    r"threshold capacity\s+(\d+)|"
    r"\bimmediate\b|"
    r"\bprotected\b|"
    r"\bnotify\b"
)

_TRAP_RE = re.compile(
    r"^\s*Trap logging:\s*level\s+(\S+),\s*(\d+)\s*message\s*lines?\s*logged"
)

_HOST_RE = re.compile(
    r"^\s*Logging to\s+(\S+)\s+\((tcp|udp)\s+port\s+(\d+),\s*"
    r"audit\s+(disabled|enabled)"
)
_HOST_LINK_RE = re.compile(r"^\s*link\s+(up|down)\)")
_HOST_MSG_LOGGED_RE = re.compile(r"^\s*(\d+)\s*message\s*lines?\s*logged")
_HOST_RATE_LIMITED_RE = re.compile(r"^\s*(\d+)\s*message\s*lines?\s*rate-limited")
_HOST_DROPPED_MD_RE = re.compile(r"^\s*(\d+)\s*message\s*lines?\s*dropped-by-MD")
_HOST_XML_RE = re.compile(r"^\s*xml\s*(disabled|enabled)")
_HOST_SEQ_RE = re.compile(r"sequence number\s*(disabled|enabled)")
_HOST_FILTER_RE = re.compile(r"^\s*filtering\s*(disabled|enabled)")

_SOURCE_INTF_HEADER_RE = re.compile(r"^\s*Logging Source-Interface:\s+VRF Name:")
_SOURCE_INTF_RE = re.compile(r"^\s{8}(\S+)(?:\s{2,}(\S+))?\s*$")

_LOG_BUFFER_RE = re.compile(r"^Log Buffer\s*\((\d+)\s*bytes\):")

# Log message: optional seq number, timestamp, optional timezone, message body
_LOG_MSG_RE = re.compile(
    r"^(?:(\d+):\s+)?"  # optional sequence number
    r"(\*?[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+(?:\.\d+)?)"  # timestamp
    r"(?:\s+([A-Z]{1,5}))?"  # optional timezone
    r":\s*(.*)"  # message body
)

_SYSLOG_MSG_RE = re.compile(r"^%([A-Z][A-Z0-9_]*)-(\d)-([A-Z0-9_]+):\s*(.*)")


def _parse_syslog_header(output: str) -> SyslogEntry | None:
    """Parse the syslog header line."""
    m = _SYSLOG_RE.search(output)
    if not m:
        return None
    return {
        "enabled": m.group(1) == "enabled",
        "messages_dropped": int(m.group(2)),
        "messages_rate_limited": int(m.group(3)),
        "flushes": int(m.group(4)),
        "overruns": int(m.group(5)),
        "xml_disabled": m.group(6) == "disabled",
        "filtering_disabled": m.group(7) == "disabled",
    }


def _parse_console(line: str) -> LoggingSectionEntry | None:
    """Parse console logging line."""
    m = _CONSOLE_DISABLED_RE.match(line)
    if m:
        return {"enabled": False}
    m = _CONSOLE_LEVEL_RE.match(line)
    if m:
        return {
            "level": m.group(1),
            "messages_logged": int(m.group(2)),
            "xml_disabled": m.group(3) == "disabled",
        }
    return None


def _parse_section(line: str) -> tuple[str, LoggingSectionEntry] | None:
    """Parse monitor or buffer logging line."""
    m = _SECTION_RE.match(line)
    if not m:
        return None
    name = m.group(1).lower()
    entry: LoggingSectionEntry = {
        "level": m.group(2),
        "messages_logged": int(m.group(3)),
        "xml_disabled": m.group(4) == "disabled",
    }
    return name, entry


def _apply_persistent_groups(m: re.Match[str], entry: PersistentLoggingEntry) -> None:
    """Apply regex groups from persistent logging match to entry."""
    group_fields: list[tuple[int, str]] = [
        (2, "url"),
        (3, "disk_space_bytes"),
        (4, "file_size_bytes"),
        (5, "batch_size_bytes"),
    ]
    for group_idx, field in group_fields:
        val = m.group(group_idx)
        if val:
            entry[field] = int(val) if field != "url" else val  # type: ignore[literal-required]


def _apply_persistent_flags(line: str, entry: PersistentLoggingEntry) -> None:
    """Apply optional flag fields from persistent logging line."""
    for opt_m in _PERSISTENT_OPTS_RE.finditer(line):
        if opt_m.group(1):
            entry["threshold_capacity"] = int(opt_m.group(1))
        token = opt_m.group(0).strip()
        if token == "immediate":
            entry["immediate"] = True
        elif token == "protected":
            entry["protected"] = True
        elif token == "notify":
            entry["notify"] = True


def _parse_persistent(line: str) -> PersistentLoggingEntry:
    """Parse persistent logging line."""
    m = _PERSISTENT_RE.match(line)
    if not m:
        return {"enabled": False}
    entry: PersistentLoggingEntry = {"enabled": m.group(1) == "enabled"}
    if not entry["enabled"]:
        return entry
    _apply_persistent_groups(m, entry)
    _apply_persistent_flags(line, entry)
    return entry


def _parse_trap_hosts(lines: list[str], start_idx: int) -> dict[str, TrapHostEntry]:
    """Parse trap logging host entries starting from a given index."""
    hosts: dict[str, TrapHostEntry] = {}
    current_host: TrapHostEntry | None = None
    current_ip: str | None = None
    i = start_idx

    while i < len(lines):
        line = lines[i]
        # Stop if we hit source interface header or log buffer
        if _SOURCE_INTF_HEADER_RE.match(line) or _LOG_BUFFER_RE.match(line):
            break

        m = _HOST_RE.match(line)
        if m:
            current_ip = m.group(1)
            current_host = {
                "protocol": m.group(2),
                "port": int(m.group(3)),
                "audit_disabled": m.group(4) == "disabled",
                "link_status": "up",
                "message_lines_logged": 0,
                "message_lines_rate_limited": 0,
                "message_lines_dropped_by_md": 0,
                "xml_disabled": True,
                "sequence_number_disabled": True,
                "filtering_disabled": True,
            }
            hosts[current_ip] = current_host
            # Check for link status on same or next line
            link_m = _HOST_LINK_RE.search(line)
            if link_m:
                current_host["link_status"] = link_m.group(1)
            i += 1
            continue

        if current_host is not None:
            _apply_host_detail(line, current_host)

        i += 1

    return hosts


def _apply_host_detail(line: str, host: TrapHostEntry) -> None:
    """Apply a detail line to a trap host entry."""
    link_m = _HOST_LINK_RE.search(line)
    if link_m:
        host["link_status"] = link_m.group(1)
        return
    m = _HOST_MSG_LOGGED_RE.match(line)
    if m:
        host["message_lines_logged"] = int(m.group(1))
        return
    m = _HOST_RATE_LIMITED_RE.match(line)
    if m:
        host["message_lines_rate_limited"] = int(m.group(1))
        return
    m = _HOST_DROPPED_MD_RE.match(line)
    if m:
        host["message_lines_dropped_by_md"] = int(m.group(1))
        return
    m = _HOST_XML_RE.match(line)
    if m:
        host["xml_disabled"] = m.group(1) == "disabled"
        seq_m = _HOST_SEQ_RE.search(line)
        if seq_m:
            host["sequence_number_disabled"] = seq_m.group(1) == "disabled"
        return
    m = _HOST_FILTER_RE.match(line)
    if m:
        host["filtering_disabled"] = m.group(1) == "disabled"


def _parse_source_interfaces(
    lines: list[str], start_idx: int
) -> list[SourceInterfaceEntry]:
    """Parse source interface to VRF mappings."""
    interfaces: list[SourceInterfaceEntry] = []
    i = start_idx + 1  # skip header line
    while i < len(lines):
        line = lines[i]
        if _LOG_BUFFER_RE.match(line):
            break
        if not line.strip():
            i += 1
            continue
        m = _SOURCE_INTF_RE.match(line)
        if m:
            entry: SourceInterfaceEntry = {"interface": m.group(1)}
            if m.group(2):
                entry["vrf"] = m.group(2)
            interfaces.append(entry)
        else:
            break
        i += 1
    return interfaces


def _parse_log_message(line: str) -> LogMessageEntry | None:
    """Parse a single log message line."""
    m = _LOG_MSG_RE.match(line)
    if not m:
        return None
    entry: LogMessageEntry = {
        "timestamp": m.group(2),
        "message": m.group(4),
    }
    if m.group(1):
        entry["sequence_number"] = int(m.group(1))
    if m.group(3):
        entry["timezone"] = m.group(3)

    # Try to parse syslog facility/severity/mnemonic from message body
    syslog_m = _SYSLOG_MSG_RE.match(m.group(4))
    if syslog_m:
        entry["facility"] = syslog_m.group(1)
        entry["severity"] = int(syslog_m.group(2))
        entry["mnemonic"] = syslog_m.group(3)
        entry["message"] = (
            f"%{syslog_m.group(1)}-{syslog_m.group(2)}-{syslog_m.group(3)}: "
            f"{syslog_m.group(4)}"
        )
    return entry


def _try_simple_config_line(line: str, result: dict) -> bool:
    """Try to parse simple single-line config fields. Returns True if matched."""
    console = _parse_console(line)
    if console is not None:
        result["console_logging"] = console
        return True

    m = _EXCEPTION_RE.match(line)
    if m:
        result["exception_logging"] = {"size_bytes": int(m.group(1))}
        return True

    m = _COUNT_TS_RE.match(line)
    if m:
        result["count_and_timestamp_logging"] = m.group(1) == "enabled"
        return True

    m = _FILE_LOGGING_RE.match(line)
    if m:
        result["file_logging"] = {"enabled": m.group(1) == "enabled"}
        return True

    m = _PERSISTENT_RE.match(line)
    if m:
        result["persistent_logging"] = _parse_persistent(line)
        return True

    return False


def _parse_config_section(lines: list[str]) -> dict:
    """Parse the configuration section of show logging output."""
    result: dict = {}

    for i, line in enumerate(lines):
        if _try_simple_config_line(line, result):
            continue

        # Monitor/Buffer logging
        section = _parse_section(line)
        if section is not None:
            name, entry = section
            if i + 1 < len(lines) and "filtering" in lines[i + 1]:
                filt_line = lines[i + 1].strip()
                entry["filtering_disabled"] = "filtering disabled" in filt_line
            result[f"{name}_logging"] = entry
            continue

        # Trap logging
        m = _TRAP_RE.match(line)
        if m:
            trap: TrapLoggingEntry = {
                "level": m.group(1),
                "message_lines_logged": int(m.group(2)),
            }
            result["trap_logging"] = trap
            hosts = _parse_trap_hosts(lines, i + 1)
            if hosts:
                trap["hosts"] = hosts
            continue

        # Source interfaces
        if _SOURCE_INTF_HEADER_RE.match(line):
            interfaces = _parse_source_interfaces(lines, i)
            if interfaces:
                result["source_interfaces"] = interfaces
            continue

    return result


def _parse_logs(lines: list[str]) -> list[LogMessageEntry]:
    """Parse log messages from the log buffer section."""
    logs: list[LogMessageEntry] = []
    for line in lines:
        if not line.strip():
            continue
        entry = _parse_log_message(line)
        if entry:
            logs.append(entry)
    return logs


@register(OS.CISCO_IOS, "show logging")
@register(OS.CISCO_IOSXE, "show logging")
class ShowLoggingParser(BaseParser[ShowLoggingResult]):
    """Parser for 'show logging' on IOS/IOS-XE."""

    @classmethod
    def parse(cls, output: str) -> ShowLoggingResult:
        """Parse 'show logging' output."""
        lines = output.splitlines()

        # Find log buffer boundary
        buffer_start = -1
        for i, line in enumerate(lines):
            m = _LOG_BUFFER_RE.match(line)
            if m:
                buffer_start = i
                break

        # Parse syslog header
        syslog = _parse_syslog_header(output)
        if syslog is None:
            syslog = {
                "enabled": False,
                "messages_dropped": 0,
                "messages_rate_limited": 0,
                "flushes": 0,
                "overruns": 0,
                "xml_disabled": True,
                "filtering_disabled": True,
            }

        # Split config vs log sections
        if buffer_start >= 0:
            config_lines = lines[:buffer_start]
            log_lines = lines[buffer_start + 1 :]
            # Extract buffer size
            m = _LOG_BUFFER_RE.match(lines[buffer_start])
            log_buffer_size = int(m.group(1)) if m else 0
        else:
            config_lines = lines
            log_lines = []
            log_buffer_size = 0

        config = _parse_config_section(config_lines)
        logs = _parse_logs(log_lines)

        result: ShowLoggingResult = {
            "syslog": syslog,
            "console_logging": config.get("console_logging", {"enabled": False}),
            "monitor_logging": config.get("monitor_logging", {}),
            "buffer_logging": config.get("buffer_logging", {}),
            "count_and_timestamp_logging": config.get(
                "count_and_timestamp_logging", False
            ),
            "trap_logging": config.get(
                "trap_logging",
                {"level": "informational", "message_lines_logged": 0},
            ),
            "log_buffer_size_bytes": log_buffer_size,
            "logs": logs,
        }

        # Add optional fields
        if "exception_logging" in config:
            result["exception_logging"] = config["exception_logging"]
        if "file_logging" in config:
            result["file_logging"] = config["file_logging"]
        if "persistent_logging" in config:
            result["persistent_logging"] = config["persistent_logging"]
        if "source_interfaces" in config:
            result["source_interfaces"] = config["source_interfaces"]

        return result
