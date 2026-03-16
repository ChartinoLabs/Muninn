"""Parser for 'show ipv6 access-lists' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.ios._acl_common import AclParsedFields, parse_extended_ace_body
from muninn.registry import register


class Ipv6AccessListEntry(TypedDict):
    """Schema for a single IPv6 access control entry (ACE)."""

    sequence: int
    action: str
    line: str
    parsed: AclParsedFields
    matches: NotRequired[int]


class Ipv6AccessList(TypedDict):
    """Schema for a single IPv6 access list."""

    entries: dict[str, Ipv6AccessListEntry]
    per_user: NotRequired[bool]


class ShowIpv6AccessListsResult(TypedDict):
    """Schema for 'show ipv6 access-lists' parsed output."""

    access_lists: dict[str, Ipv6AccessList]


# Header: "IPv6 access list <name>" optionally followed by "(per-user)"
_HEADER_PATTERN = re.compile(
    r"^IPv6\s+(?:Role-based\s+)?access\s+list\s+(?P<name>\S+)"
    r"(?:\s+\((?P<per_user>per-user)\))?$"
)

# Match count embedded in ACE line: (NNN matches) or (NNN match)
_MATCH_COUNT_PATTERN = re.compile(r"\((\d+)\s+matches?\)")

# Sequence number at end of ACE line: sequence <N>
_SEQUENCE_PATTERN = re.compile(r"\s+sequence\s+(\d+)$")


def _parse_ace_line(line: str) -> Ipv6AccessListEntry | None:
    """Parse a single IPv6 ACE line into an entry dict.

    IPv6 ACLs place the sequence number at the end: 'permit ipv6 any any sequence 10'.
    Match counts appear inline: 'permit tcp any any eq bgp (8 matches) sequence 10'.

    Args:
        line: Stripped line from CLI output.

    Returns:
        Parsed ACE entry, or None if line does not match an ACE.
    """
    # Must start with permit or deny
    if not line.startswith(("permit", "deny")):
        return None

    # Extract sequence number from end
    seq_match = _SEQUENCE_PATTERN.search(line)
    if not seq_match:
        return None

    sequence = int(seq_match.group(1))
    rest = line[: seq_match.start()]

    # Extract match count if present
    matches: int | None = None
    match_count_match = _MATCH_COUNT_PATTERN.search(rest)
    if match_count_match:
        matches = int(match_count_match.group(1))
        rest = rest[: match_count_match.start()] + rest[match_count_match.end() :]

    # Clean up whitespace
    rest = " ".join(rest.split())

    # Extract action (first word)
    parts = rest.split(None, 1)
    action = parts[0]

    entry: Ipv6AccessListEntry = {
        "sequence": sequence,
        "action": action,
        "line": rest,
        "parsed": parse_extended_ace_body(rest.split(None, 1)[1], ip_version=6),
    }
    if matches is not None:
        entry["matches"] = matches

    return entry


@register(OS.CISCO_IOS, "show ipv6 access-lists")
class ShowIpv6AccessListsParser(BaseParser[ShowIpv6AccessListsResult]):
    """Parser for 'show ipv6 access-lists' command.

    Example output:
        IPv6 access list inbound
            permit tcp any any eq bgp (8 matches) sequence 10
            permit tcp any any eq telnet (15 matches) sequence 20
            permit udp any any sequence 30
        IPv6 access list Virtual-Access2.1#427819008151 (per-user)
            permit tcp host 2001:DB8:1::32 eq bgp ... sequence 1
    """

    tags: ClassVar[frozenset[str]] = frozenset({"acl", "security"})

    @classmethod
    def parse(cls, output: str) -> ShowIpv6AccessListsResult:
        """Parse 'show ipv6 access-lists' output.

        Args:
            output: Raw CLI output from 'show ipv6 access-lists' command.

        Returns:
            Parsed data with access lists keyed by name.

        Raises:
            ValueError: If no access lists found in output.
        """
        access_lists: dict[str, Ipv6AccessList] = {}
        current_name: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            header_match = _HEADER_PATTERN.match(stripped)
            if header_match:
                current_name = header_match.group("name")
                acl: Ipv6AccessList = {"entries": {}}
                if header_match.group("per_user"):
                    acl["per_user"] = True
                access_lists[current_name] = acl
                continue

            if current_name is None:
                continue

            entry = _parse_ace_line(stripped)
            if entry:
                access_lists[current_name]["entries"][str(entry["sequence"])] = entry

        if not access_lists:
            msg = "No IPv6 access lists found in output"
            raise ValueError(msg)

        return ShowIpv6AccessListsResult(access_lists=access_lists)
