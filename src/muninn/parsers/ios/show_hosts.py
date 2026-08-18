"""Parser for 'show hosts' command on IOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_VIEW_RE = re.compile(r"^Name lookup view:\s*(?P<view>.+?)\s*$")
_DEFAULT_DOMAIN_RE = re.compile(r"^Default domain is\s+(?P<domain>\S+)\s*$")
_DOMAIN_LIST_RE = re.compile(r"^Domain list:\s*(?P<domains>.+?)\s*$")
_LOOKUP_ENABLED_RE = re.compile(r"^Name/address lookup uses\s+.+?\s*$")
_LOOKUP_DISABLED_RE = re.compile(r"^Name/address lookup is disabled\s*$")
_NAME_SERVERS_RE = re.compile(r"^Name servers are\s+(?P<servers>.+?)\s*$")
_CODES_HEADER_RE = re.compile(r"^Codes:\s")
_TABLE_HEADER_RE = re.compile(r"^Host\s+Port\s+Flags\s+Age\s+Type\s+Address\(es\)\s*$")

# Matches a host table row.
#
# Format observed in the wild::
#
#   google.com               None  (perm, OK) 0   IP   8.8.8.8 8.8.4.4
#   foo.example.org          None  (temp, OK) 12  IP   10.1.1.1
#   bar.example.org          None  (perm, OK) 0   IP   10.2.2.2
#                                                       10.2.2.3
#
# Continuation lines (additional addresses) are detected structurally by
# leading whitespace + lack of any recognized leading construct.
_HOST_ROW_RE = re.compile(
    r"^(?P<host>\S+)\s+"
    r"(?P<port>\S+)\s+"
    r"\((?P<flags>[^)]+)\)\s+"
    r"(?P<age>\d+|-)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<addresses>.+?)\s*$"
)
_CONTINUATION_RE = re.compile(r"^\s+(?P<addresses>\S.*?)\s*$")

_AGE_PLACEHOLDERS = frozenset({"-"})
_PORT_PLACEHOLDERS = frozenset({"-", "None", "NONE", "none"})


class HostEntry(TypedDict):
    """Schema for a single resolved host entry."""

    port: NotRequired[str]
    flags: list[str]
    age: NotRequired[int]
    type: str
    addresses: list[str]


class ShowHostsResult(TypedDict):
    """Schema for 'show hosts' parsed output."""

    name_lookup_view: NotRequired[str]
    default_domain: NotRequired[str]
    domain_list: NotRequired[list[str]]
    domain_lookup_enabled: bool
    name_servers: list[str]
    hosts: dict[str, HostEntry]


def _parse_name_servers(raw: str) -> list[str]:
    """Split a name-server line into individual server addresses.

    IOS prints name servers separated by whitespace or commas. The sentinel
    ``255.255.255.255`` denotes 'no name servers configured' and resolves
    to an empty list.
    """
    cleaned = raw.replace(",", " ")
    servers = [token for token in cleaned.split() if token]
    if servers == ["255.255.255.255"]:
        return []
    return servers


def _parse_domain_list(raw: str) -> list[str]:
    """Split a domain-list line into individual domain entries."""
    cleaned = raw.replace(",", " ")
    return [token for token in cleaned.split() if token]


def _parse_flags(raw: str) -> list[str]:
    """Split a parenthesized flag list into individual flag tokens."""
    return [token.strip() for token in raw.split(",") if token.strip()]


def _parse_age(raw: str) -> int | None:
    """Coerce the age field; placeholders return None."""
    if raw in _AGE_PLACEHOLDERS:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _build_host_entry(match: re.Match[str]) -> tuple[str, HostEntry]:
    """Build a HostEntry from a successful host-row regex match."""
    host = match.group("host")
    addresses = [token for token in match.group("addresses").split() if token]
    entry: HostEntry = {
        "flags": _parse_flags(match.group("flags")),
        "type": match.group("type"),
        "addresses": addresses,
    }

    port = match.group("port")
    if port and port not in _PORT_PLACEHOLDERS:
        entry["port"] = port

    age = _parse_age(match.group("age"))
    if age is not None:
        entry["age"] = age

    return host, entry


class _ParseState:
    """Mutable scratchpad shared across line-handler helpers."""

    __slots__ = (
        "hosts",
        "in_codes_block",
        "in_host_table",
        "last_host",
        "result",
        "saw_any_marker",
    )

    def __init__(self) -> None:
        self.result: dict = {
            "domain_lookup_enabled": False,
            "name_servers": [],
            "hosts": {},
        }
        self.hosts: dict[str, HostEntry] = {}
        self.last_host: str | None = None
        self.in_codes_block = False
        self.in_host_table = False
        self.saw_any_marker = False


def _handle_codes_block(line: str, state: _ParseState) -> bool:
    """Consume codes-legend lines; returns True if consumed."""
    if _CODES_HEADER_RE.match(line):
        state.in_codes_block = True
        state.saw_any_marker = True
        return True
    if state.in_codes_block:
        if line.startswith((" ", "\t")):
            return True
        state.in_codes_block = False
    return False


def _handle_table_header(line: str, state: _ParseState) -> bool:
    """Consume the host-table column header line."""
    if _TABLE_HEADER_RE.match(line):
        state.in_host_table = True
        state.saw_any_marker = True
        return True
    return False


def _try_resolver_state(line: str, result: dict) -> bool:
    """Match a resolver-state line and update ``result`` in place.

    Returns:
        True when the line was consumed by one of the resolver-state
        patterns (view, default domain, domain list, lookup state, name
        servers), False otherwise.
    """
    view_match = _VIEW_RE.match(line)
    if view_match:
        result["name_lookup_view"] = view_match.group("view")
        return True

    domain_match = _DEFAULT_DOMAIN_RE.match(line)
    if domain_match:
        result["default_domain"] = domain_match.group("domain")
        return True

    domain_list_match = _DOMAIN_LIST_RE.match(line)
    if domain_list_match:
        domains = _parse_domain_list(domain_list_match.group("domains"))
        if domains:
            result["domain_list"] = domains
        return True

    if _LOOKUP_ENABLED_RE.match(line):
        result["domain_lookup_enabled"] = True
        return True

    if _LOOKUP_DISABLED_RE.match(line):
        result["domain_lookup_enabled"] = False
        return True

    servers_match = _NAME_SERVERS_RE.match(line)
    if servers_match:
        result["name_servers"] = _parse_name_servers(servers_match.group("servers"))
        return True

    return False


def _try_host_row(
    line: str, hosts: dict[str, HostEntry], last_host: str | None
) -> str | None:
    """Match a host-table row or continuation; update ``hosts`` in place.

    Returns:
        The host name that should be tracked for subsequent continuation
        lines, or ``last_host`` if the line was not consumed.
    """
    host_match = _HOST_ROW_RE.match(line)
    if host_match:
        host, entry = _build_host_entry(host_match)
        hosts[host] = entry
        return host

    cont_match = _CONTINUATION_RE.match(line)
    if cont_match and last_host is not None:
        extra = [token for token in cont_match.group("addresses").split() if token]
        hosts[last_host]["addresses"].extend(extra)

    return last_host


@register(OS.CISCO_IOS, "show hosts")
class ShowHostsParser(BaseParser[ShowHostsResult]):
    r"""Parser for 'show hosts' command on IOS.

    Extracts DNS resolver configuration (view name, default domain, name
    servers, lookup state) and the cached host table.

    Example output::

        Name lookup view: Global
        Default domain is example.com
        Name/address lookup uses domain service
        Name servers are 255.255.255.255

        Codes: UN - unknown, EX - expired, OK - OK, ?? - revalidate
               temp - temporary, perm - permanent
               NA - Not Applicable None - Not defined

        Host                      Port  Flags      Age Type   Address(es)
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowHostsResult:
        """Parse 'show hosts' output.

        Args:
            output: Raw CLI output from 'show hosts' command.

        Returns:
            Parsed DNS resolver state and cached host table.

        Raises:
            ValueError: If the output contains no recognizable resolver
                state line (view, default domain, lookup state, name
                servers, or table header).
        """
        state = _ParseState()

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                state.in_codes_block = False
                continue

            cls._consume_line(line, state)

        if not state.saw_any_marker:
            msg = "No 'show hosts' content recognized in output"
            raise ValueError(msg)

        state.result["hosts"] = state.hosts
        return cast(ShowHostsResult, state.result)

    @staticmethod
    def _consume_line(line: str, state: _ParseState) -> None:
        """Dispatch a single non-empty line to the appropriate handler."""
        if _handle_codes_block(line, state):
            return
        if _handle_table_header(line, state):
            return
        if _try_resolver_state(line, state.result):
            state.saw_any_marker = True
            return
        if state.in_host_table:
            state.last_host = _try_host_row(line, state.hosts, state.last_host)
