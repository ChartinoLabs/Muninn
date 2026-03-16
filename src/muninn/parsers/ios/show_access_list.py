"""Parser for 'show access-list' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.ios._acl_common import (
    AclParsedFields,
    parse_extended_ace_body,
    parse_standard_ace_body,
)
from muninn.registry import register


class AccessListEntry(TypedDict):
    """Schema for a single access control entry (ACE)."""

    sequence: int
    action: str
    line: str
    parsed: AclParsedFields
    matches: NotRequired[int]


class AccessList(TypedDict):
    """Schema for a single access list."""

    type: str
    entries: dict[str, AccessListEntry]


class ShowAccessListResult(TypedDict):
    """Schema for 'show access-list' parsed output."""

    access_lists: dict[str, AccessList]


# Header pattern: "Extended IP access list <name>" or "Standard IP access list <name>"
_HEADER_PATTERN = re.compile(
    r"^(?P<type>(?:Extended|Standard)\s+IP\s+access\s+list)\s+(?P<name>\S+)$"
)

# ACE pattern: sequence, action, rest of line, optional match count
_ACE_PATTERN = re.compile(
    r"^(?P<sequence>\d+)\s+(?P<action>permit|deny)\s+(?P<rest>.+)$"
)

# Match count at end of line: (NNN matches)
_MATCH_COUNT_PATTERN = re.compile(r"\((\d+)\s+matches?\)$")


def _parse_ace_line(line: str, acl_type: str) -> AccessListEntry | None:
    """Parse a single ACE line into an entry dict.

    Args:
        line: Stripped line from CLI output.
        acl_type: ACL header type used to choose standard or extended parsing.

    Returns:
        Parsed ACE entry, or None if line does not match.
    """
    match = _ACE_PATTERN.match(line)
    if not match:
        return None

    sequence = int(match.group("sequence"))
    action = match.group("action")
    rest = match.group("rest").strip()

    full_line = f"{action} {rest}"

    # Check for match count and strip it from line
    match_count_match = _MATCH_COUNT_PATTERN.search(full_line)
    if match_count_match:
        matches = int(match_count_match.group(1))
        full_line = full_line[: match_count_match.start()].rstrip()
        entry: AccessListEntry = {
            "sequence": sequence,
            "action": action,
            "line": full_line,
            "parsed": _parse_ace_body(full_line, acl_type),
            "matches": matches,
        }
        return entry

    return {
        "sequence": sequence,
        "action": action,
        "line": full_line,
        "parsed": _parse_ace_body(full_line, acl_type),
    }


def _parse_ace_body(full_line: str, acl_type: str) -> AclParsedFields:
    """Parse the body of an ACL line into structured fields."""
    body = full_line.split(None, 1)[1] if " " in full_line else ""
    if acl_type.startswith("Standard"):
        return parse_standard_ace_body(body)
    return parse_extended_ace_body(body, ip_version=4)


@register(OS.CISCO_IOS, "show access-list")
class ShowAccessListParser(BaseParser[ShowAccessListResult]):
    """Parser for 'show access-list' command.

    Example output:
        Extended IP access list 102
            10 permit tcp any host 192.168.1.100 eq ftp
            20 permit tcp any host 192.168.1.100 gt 1024
        Standard IP access list 1
            10 permit 10.1.2.3 log
    """

    tags: ClassVar[frozenset[str]] = frozenset({"acl", "security"})

    @classmethod
    def parse(cls, output: str) -> ShowAccessListResult:
        """Parse 'show access-list' output.

        Args:
            output: Raw CLI output from 'show access-list' command.

        Returns:
            Parsed data with access lists keyed by name.

        Raises:
            ValueError: If no access lists found in output.
        """
        access_lists: dict[str, AccessList] = {}
        current_name: str | None = None
        current_type: str | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            header_match = _HEADER_PATTERN.match(line)
            if header_match:
                current_name = header_match.group("name")
                current_type = header_match.group("type")
                access_lists[current_name] = {
                    "type": current_type,
                    "entries": {},
                }
                continue

            if current_name is None:
                continue

            if current_type is None:
                continue

            entry = _parse_ace_line(line, current_type)
            if entry:
                access_lists[current_name]["entries"][str(entry["sequence"])] = entry

        if not access_lists:
            msg = "No access lists found in output"
            raise ValueError(msg)

        return ShowAccessListResult(access_lists=access_lists)
