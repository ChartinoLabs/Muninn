"""Parser for 'show ip access-lists' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class AclEntry(TypedDict):
    """Schema for a single ACL entry (rule)."""

    action: str
    protocol: str
    source: str
    source_ports: NotRequired[str]
    destination: str
    destination_ports: NotRequired[str]
    fragments: NotRequired[bool]
    log: NotRequired[bool]
    tracked: NotRequired[bool]
    tcp_flags: NotRequired[str]
    ttl: NotRequired[str]


class AccessList(TypedDict):
    """Schema for a single IP access list."""

    readonly: NotRequired[bool]
    statistics_per_entry: NotRequired[bool]
    entries: dict[str, AclEntry]


class ShowIpAccessListsResult(TypedDict):
    """Schema for 'show ip access-lists' parsed output on Arista EOS."""

    access_lists: dict[str, AccessList]


_ACL_HEADER = re.compile(
    r"^IP Access List\s+(?P<name>\S+)"
    r"(?:\s+\[(?P<readonly>readonly)\])?\s*$"
)

_STATISTICS_PER_ENTRY = re.compile(r"^\s+statistics per-entry\s*$")

# ACL entry line: sequence action protocol <rest>
_ACL_ENTRY = re.compile(
    r"^\s+(?P<seq>\d+)\s+(?P<action>permit|deny)\s+(?P<protocol>\S+)\s+"
    r"(?P<rest>.+)$"
)


def _parse_address_and_ports(tokens: list[str]) -> tuple[str, str | None, list[str]]:
    """Parse an address (with optional ports) from a token list.

    Returns (address_str, ports_str_or_none, remaining_tokens).
    """
    if not tokens:
        msg = "Expected address tokens but got empty list"
        raise ValueError(msg)

    # "any"
    if tokens[0] == "any":
        addr = "any"
        tokens = tokens[1:]
    # "host x.x.x.x"
    elif tokens[0] == "host":
        addr = f"host {tokens[1]}"
        tokens = tokens[2:]
    # "x.x.x.x/prefix"
    elif "/" in tokens[0]:
        addr = tokens[0]
        tokens = tokens[1:]
    # "x.x.x.x mask" (shouldn't appear in EOS but handle defensively)
    else:
        addr = tokens[0]
        tokens = tokens[1:]

    # Check for port operator (eq, range, neq, gt, lt)
    ports = None
    if tokens and tokens[0] in ("eq", "range", "neq", "gt", "lt"):
        operator = tokens[0]
        tokens = tokens[1:]
        port_values: list[str] = []
        if operator == "range":
            # range takes exactly two values
            port_values = tokens[:2]
            tokens = tokens[2:]
        else:
            # eq/neq/gt/lt: consume port names until we hit a keyword or address
            while tokens and not _is_address_or_keyword(tokens[0]):
                port_values.append(tokens[0])
                tokens = tokens[1:]
        ports = f"{operator} {' '.join(port_values)}"

    return addr, ports, tokens


# Tokens that signal end of a port list (start of destination or trailing option)
_TRAILING_KEYWORDS = frozenset(
    {
        "any",
        "host",
        "log",
        "fragments",
        "tracked",
        "ack",
        "fin",
        "psh",
        "rst",
        "syn",
        "urg",
        "ttl",
        "established",
    }
)


def _is_address_or_keyword(token: str) -> bool:
    """Return True if token looks like an address start or trailing keyword."""
    if token in _TRAILING_KEYWORDS:
        return True
    # IP address or CIDR
    if re.match(r"^\d+\.\d+\.\d+\.\d+", token):
        return True
    return False


_TCP_FLAG_TOKENS = frozenset(
    {
        "ack",
        "fin",
        "psh",
        "rst",
        "syn",
        "urg",
        "established",
    }
)


_BOOLEAN_OPTIONS = frozenset({"fragments", "log", "tracked"})


def _parse_trailing_options(
    tokens: list[str],
    result: dict[str, object],
) -> None:
    """Parse trailing ACL entry options (flags, log, ttl, etc.) in place."""
    tcp_flags: list[str] = []

    while tokens:
        token = tokens.pop(0)

        if token in _BOOLEAN_OPTIONS:
            result[token] = True
        elif token == "ttl" and tokens and tokens[0] == "eq":  # nosec B105
            tokens.pop(0)  # consume "eq"
            if tokens:
                result["ttl"] = f"eq {tokens.pop(0)}"
        elif token in _TCP_FLAG_TOKENS:
            tcp_flags.append(token)

    if tcp_flags:
        result["tcp_flags"] = " ".join(tcp_flags)


def _parse_acl_entry_rest(protocol: str, rest: str) -> dict[str, object]:
    """Parse the source/destination/options portion of an ACL entry line."""
    tokens = rest.split()
    result: dict[str, object] = {}

    # Parse source
    source, source_ports, tokens = _parse_address_and_ports(tokens)
    result["source"] = source
    if source_ports:
        result["source_ports"] = source_ports

    # Parse destination
    dest, dest_ports, tokens = _parse_address_and_ports(tokens)
    result["destination"] = dest
    if dest_ports:
        result["destination_ports"] = dest_ports

    _parse_trailing_options(tokens, result)

    return result


def _build_acl_entry(action: str, protocol: str, rest: str) -> AclEntry:
    """Build a typed AclEntry from parsed components."""
    parsed = _parse_acl_entry_rest(protocol, rest)
    entry: AclEntry = {
        "action": action,
        "protocol": protocol,
        "source": str(parsed["source"]),
        "destination": str(parsed["destination"]),
    }

    if "source_ports" in parsed:
        entry["source_ports"] = str(parsed["source_ports"])
    if "destination_ports" in parsed:
        entry["destination_ports"] = str(parsed["destination_ports"])
    if "fragments" in parsed:
        entry["fragments"] = bool(parsed["fragments"])
    if "log" in parsed:
        entry["log"] = bool(parsed["log"])
    if "tracked" in parsed:
        entry["tracked"] = bool(parsed["tracked"])
    if "tcp_flags" in parsed:
        entry["tcp_flags"] = str(parsed["tcp_flags"])
    if "ttl" in parsed:
        entry["ttl"] = str(parsed["ttl"])

    return entry


@register(OS.ARISTA_EOS, "show ip access-lists")
class ShowIpAccessListsParser(BaseParser[ShowIpAccessListsResult]):
    """Parser for 'show ip access-lists' command on Arista EOS.

    Parses IP access lists with their entries including action,
    protocol, source/destination addresses, ports, and options.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ACL})

    @classmethod
    def parse(cls, output: str) -> ShowIpAccessListsResult:
        """Parse 'show ip access-lists' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed access lists keyed by ACL name, with entries keyed
            by sequence number.

        Raises:
            ValueError: If no access lists found.
        """
        access_lists: dict[str, AccessList] = {}
        current_acl: AccessList | None = None
        current_name: str | None = None

        for line in output.splitlines():
            # ACL header
            header_match = _ACL_HEADER.match(line)
            if header_match:
                current_name = header_match.group("name")
                current_acl = cast(AccessList, {"entries": {}})
                if header_match.group("readonly"):
                    current_acl["readonly"] = True
                access_lists[current_name] = current_acl
                continue

            if current_acl is None:
                continue

            # Statistics per-entry
            if _STATISTICS_PER_ENTRY.match(line):
                current_acl["statistics_per_entry"] = True
                continue

            # ACL entry
            entry_match = _ACL_ENTRY.match(line)
            if entry_match:
                seq = entry_match.group("seq")
                current_acl["entries"][seq] = _build_acl_entry(
                    entry_match.group("action"),
                    entry_match.group("protocol"),
                    entry_match.group("rest"),
                )

        if not access_lists:
            msg = "No access lists found in output"
            raise ValueError(msg)

        return cast(ShowIpAccessListsResult, {"access_lists": access_lists})
