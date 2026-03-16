"""Parser for 'show tacacs' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class TacacsServerEntry(TypedDict):
    """Schema for a single TACACS+ server entry."""

    server_port: int
    socket_opens: int
    socket_closes: int
    socket_aborts: int
    socket_errors: int
    socket_timeouts: int
    failed_connect_attempts: int
    total_packets_sent: int
    total_packets_recv: int
    server_name: NotRequired[str]
    server_status: NotRequired[str]
    authc_fail_count: NotRequired[int]
    authz_fail_count: NotRequired[int]


class ShowTacacsResult(TypedDict):
    """Schema for 'show tacacs' parsed output."""

    servers: dict[str, TacacsServerEntry]


# Matches the server block header
_BLOCK_SEPARATOR = re.compile(r"^Tacacs\+\s+Server\s+-\s+\S+", re.IGNORECASE)

# Field patterns mapping regex to (key, should_convert_to_int)
_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str, bool], ...] = (
    (re.compile(r"^\s*Server\s+name:\s+(?P<val>\S+)$"), "server_name", False),
    (re.compile(r"^\s*Server\s+address:\s+(?P<val>\S+)$"), "server_address", False),
    (re.compile(r"^\s*Server\s+port:\s+(?P<val>\d+)$"), "server_port", True),
    (re.compile(r"^\s*Socket\s+opens:\s+(?P<val>\d+)$"), "socket_opens", True),
    (re.compile(r"^\s*Socket\s+closes:\s+(?P<val>\d+)$"), "socket_closes", True),
    (re.compile(r"^\s*Socket\s+aborts:\s+(?P<val>\d+)$"), "socket_aborts", True),
    (re.compile(r"^\s*Socket\s+errors:\s+(?P<val>\d+)$"), "socket_errors", True),
    (re.compile(r"^\s*Socket\s+Timeouts:\s+(?P<val>\d+)$"), "socket_timeouts", True),
    (
        re.compile(r"^\s*Failed\s+Connect\s+Attempts:\s+(?P<val>\d+)$"),
        "failed_connect_attempts",
        True,
    ),
    (
        re.compile(r"^\s*Total\s+Packets\s+Sent:\s+(?P<val>\d+)$"),
        "total_packets_sent",
        True,
    ),
    (
        re.compile(r"^\s*Total\s+Packets\s+Recv:\s+(?P<val>\d+)$"),
        "total_packets_recv",
        True,
    ),
    (re.compile(r"^\s*Server\s+Status:\s+(?P<val>\S+)$"), "server_status", False),
    (
        re.compile(r"^\s*Continous\s+Authc\s+fail\s+count:\s+(?P<val>\d+)$"),
        "authc_fail_count",
        True,
    ),
    (
        re.compile(r"^\s*Continous\s+Authz\s+fail\s+count:\s+(?P<val>\d+)$"),
        "authz_fail_count",
        True,
    ),
)

# Required integer fields present in every server block
_REQUIRED_INT_KEYS = (
    "server_port",
    "socket_opens",
    "socket_closes",
    "socket_aborts",
    "socket_errors",
    "socket_timeouts",
    "failed_connect_attempts",
    "total_packets_sent",
    "total_packets_recv",
)

# Optional fields and their types (str or int)
_OPTIONAL_STR_KEYS = ("server_name", "server_status")
_OPTIONAL_INT_KEYS = ("authc_fail_count", "authz_fail_count")


def _extract_fields(lines: list[str]) -> dict[str, str | int]:
    """Extract all recognized fields from a block of lines."""
    fields: dict[str, str | int] = {}
    for line in lines:
        for pattern, key, is_int in _FIELD_PATTERNS:
            if match := pattern.match(line):
                raw_val = match.group("val")
                fields[key] = int(raw_val) if is_int else raw_val
                break
    return fields


def _build_entry(fields: dict[str, str | int]) -> TacacsServerEntry:
    """Build a TacacsServerEntry from extracted fields."""
    entry = TacacsServerEntry(**{k: int(fields[k]) for k in _REQUIRED_INT_KEYS})  # type: ignore[typeddict-item]
    for key in _OPTIONAL_STR_KEYS:
        if key in fields:
            entry[key] = str(fields[key])  # type: ignore[literal-required]
    for key in _OPTIONAL_INT_KEYS:
        if key in fields:
            entry[key] = int(fields[key])  # type: ignore[literal-required]
    return entry


def _parse_block(lines: list[str]) -> tuple[str, TacacsServerEntry] | None:
    """Parse a single TACACS+ server block into an (address, entry) tuple."""
    fields = _extract_fields(lines)

    if "server_address" not in fields or not all(
        k in fields for k in _REQUIRED_INT_KEYS
    ):
        return None

    address = str(fields["server_address"])
    return address, _build_entry(fields)


@register(OS.CISCO_IOS, "show tacacs")
class ShowTacacsParser(BaseParser[ShowTacacsResult]):
    """Parser for 'show tacacs' command.

    Example output:
        Tacacs+ Server -  public  :
                    Server address: 10.1.1.140
                       Server port: 49
                      Socket opens:     138084
                     Socket closes:     137992
                     Socket aborts:          0
                     Socket errors:          0
                   Socket Timeouts:         59
           Failed Connect Attempts:         52
                Total Packets Sent:     147753
                Total Packets Recv:     147693
    """

    tags: ClassVar[frozenset[str]] = frozenset({"aaa", "security"})

    @classmethod
    def parse(cls, output: str) -> ShowTacacsResult:
        """Parse 'show tacacs' output.

        Args:
            output: Raw CLI output from 'show tacacs' command.

        Returns:
            Parsed TACACS+ server data keyed by server address.

        Raises:
            ValueError: If no TACACS+ server entries found.
        """
        servers: dict[str, TacacsServerEntry] = {}

        # Split output into blocks by server header lines
        blocks: list[list[str]] = []
        current_block: list[str] = []

        for line in output.splitlines():
            if _BLOCK_SEPARATOR.match(line.strip()):
                if current_block:
                    blocks.append(current_block)
                current_block = []
            else:
                current_block.append(line)

        if current_block:
            blocks.append(current_block)

        for block in blocks:
            result = _parse_block(block)
            if result is not None:
                address, entry = result
                servers[address] = entry

        if not servers:
            msg = "No TACACS+ server entries found in output"
            raise ValueError(msg)

        return ShowTacacsResult(servers=servers)
