"""Parser for 'show ip access-lists' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

AddressSpec = dict[str, object]
PortSpec = dict[str, object]
AclParsedFields = dict[str, object]


class AclEntry(TypedDict):
    """Schema for a single ACL entry (ACE)."""

    sequence: int
    action: str
    line: str
    parsed: AclParsedFields


class AccessList(TypedDict):
    """Schema for a single IP access list."""

    entries: dict[str, AclEntry]
    readonly: NotRequired[bool]
    statistics_per_entry: NotRequired[bool]


class ShowIpAccessListsResult(TypedDict):
    """Schema for 'show ip access-lists' parsed output on Arista EOS."""

    access_lists: dict[str, AccessList]


_ACL_HEADER = re.compile(
    r"^IP Access List\s+(?P<name>\S+)(?:\s+\[(?P<readonly>readonly)\])?\s*$"
)

_STATISTICS_PER_ENTRY = re.compile(r"^\s+statistics per-entry\s*$")

_ACL_ENTRY = re.compile(
    r"^\s+(?P<sequence>\d+)\s+(?P<action>permit|deny)\s+(?P<rest>.+)$"
)

_IPV4_ADDRESS_START_RE = re.compile(rf"^{IPV4_ADDRESS}")

_PORT_OPERATORS = frozenset({"eq", "neq", "lt", "gt", "range"})

_TCP_FLAG_TOKENS = frozenset({"ack", "fin", "psh", "rst", "syn", "urg", "established"})

_BOOLEAN_OPTIONS = frozenset({"fragments", "log", "tracked"})

_ADDRESS_KEYWORDS = frozenset({"any", "host"})

_TRAILING_KEYWORDS = _ADDRESS_KEYWORDS | _BOOLEAN_OPTIONS | _TCP_FLAG_TOKENS | {"ttl"}


def _is_address_or_keyword(token: str) -> bool:
    """Return True if token starts a new address or trailing modifier."""
    if token in _TRAILING_KEYWORDS:
        return True
    return bool(_IPV4_ADDRESS_START_RE.match(token))


def _parse_address(tokens: list[str], index: int) -> tuple[AddressSpec, int]:
    """Parse an address specification at ``tokens[index]``."""
    if index >= len(tokens):
        return {"kind": "unknown"}, index

    token = tokens[index]
    if token == "any":  # nosec B105
        return {"kind": "any"}, index + 1
    if token == "host" and index + 1 < len(tokens):  # nosec B105
        return {"kind": "host", "value": tokens[index + 1]}, index + 2
    if "/" in token:
        return {"kind": "prefix", "value": token}, index + 1
    return {"kind": "address", "value": token}, index + 1


def _parse_port_spec(tokens: list[str], index: int) -> tuple[PortSpec | None, int]:
    """Parse a port clause if present, consuming all port values."""
    if index >= len(tokens):
        return None, index

    operator = tokens[index]
    if operator not in _PORT_OPERATORS:
        return None, index

    next_index = index + 1
    if operator == "range":
        ports = tokens[next_index : next_index + 2]
        return {"operator": operator, "ports": ports}, next_index + 2

    ports: list[str] = []
    while next_index < len(tokens) and not _is_address_or_keyword(tokens[next_index]):
        ports.append(tokens[next_index])
        next_index += 1
    return {"operator": operator, "ports": ports}, next_index


def _parse_trailing_modifiers(parsed: AclParsedFields, tokens: list[str]) -> None:
    """Parse trailing ACE modifiers (booleans, TCP flags, ttl) in place."""
    tcp_flags: dict[str, str] = {}
    extras: list[str] = []
    index = 0

    while index < len(tokens):
        token = tokens[index]
        if token in _BOOLEAN_OPTIONS:
            parsed[token] = True
            index += 1
            continue
        if token in _TCP_FLAG_TOKENS:
            tcp_flags[token] = "include"
            index += 1
            continue
        if token == "ttl":  # nosec B105
            index = _consume_ttl(parsed, tokens, index)
            continue
        extras.append(token)
        index += 1

    if tcp_flags:
        parsed["tcp_flags"] = {"flags": tcp_flags}
    if extras:
        parsed["extra"] = extras


def _consume_ttl(parsed: AclParsedFields, tokens: list[str], index: int) -> int:
    """Consume a ``ttl <op> <value>`` clause."""
    if index + 2 < len(tokens) and tokens[index + 1] in _PORT_OPERATORS:
        parsed["ttl"] = {
            "operator": tokens[index + 1],
            "value": int(tokens[index + 2]),
        }
        return index + 3
    if index + 1 < len(tokens):
        parsed["ttl"] = {"value": int(tokens[index + 1])}
        return index + 2
    return index + 1


def _parse_ace_body(rest: str) -> AclParsedFields:
    """Parse the protocol/source/destination/options portion of an ACE."""
    tokens = rest.split()
    if not tokens:
        return {}

    parsed: AclParsedFields = {"protocol": tokens[0]}
    index = 1

    source, index = _parse_address(tokens, index)
    parsed["source"] = source

    source_port, index = _parse_port_spec(tokens, index)
    if source_port is not None:
        parsed["source_port"] = source_port

    destination, index = _parse_address(tokens, index)
    parsed["destination"] = destination

    destination_port, index = _parse_port_spec(tokens, index)
    if destination_port is not None:
        parsed["destination_port"] = destination_port

    _parse_trailing_modifiers(parsed, tokens[index:])
    return parsed


def _build_entry(sequence: int, action: str, rest: str) -> AclEntry:
    """Build a typed AclEntry from a raw ACE line."""
    return {
        "sequence": sequence,
        "action": action,
        "line": f"{action} {rest}",
        "parsed": _parse_ace_body(rest),
    }


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

        for line in output.splitlines():
            header_match = _ACL_HEADER.match(line)
            if header_match:
                current_acl = {"entries": {}}
                if header_match.group("readonly"):
                    current_acl["readonly"] = True
                access_lists[header_match.group("name")] = current_acl
                continue

            if current_acl is None:
                continue

            if _STATISTICS_PER_ENTRY.match(line):
                current_acl["statistics_per_entry"] = True
                continue

            entry_match = _ACL_ENTRY.match(line)
            if entry_match:
                sequence = int(entry_match.group("sequence"))
                current_acl["entries"][str(sequence)] = _build_entry(
                    sequence,
                    entry_match.group("action"),
                    entry_match.group("rest"),
                )

        if not access_lists:
            msg = "No access lists found in output"
            raise ValueError(msg)

        return {"access_lists": access_lists}
