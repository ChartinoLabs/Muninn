"""Parser for 'show access-lists' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.ios._acl_common import (
    AclParsedFields,
    parse_extended_ace_body,
    parse_standard_ace_body,
)
from muninn.registry import register
from muninn.tags import ParserTag


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


class ShowAccessListsResult(TypedDict):
    """Schema for 'show access-lists' parsed output."""

    access_lists: dict[str, AccessList]


# Extended/Standard IP ACL header
_IPV4_HEADER_RE = re.compile(
    r"^(?P<type>(?:Extended|Standard)\s+IP\s+access\s+list)"
    r"\s+(?P<name>\S+)$"
)

# IPv6 ACL header
_IPV6_HEADER_RE = re.compile(r"^(?P<type>IPv6\s+access\s+list)\s+(?P<name>\S+)$")

# Extended IP ACE: <seq> <action> <rest>
_IPV4_ACE_RE = re.compile(
    r"^(?P<sequence>\d+)\s+(?P<action>permit|deny)\s+(?P<rest>.+)$"
)

# IPv6 ACE: <action> <rest> sequence <seq>
_IPV6_ACE_RE = re.compile(
    r"^(?P<action>permit|deny)\s+(?P<rest>.+)\s+sequence\s+(?P<sequence>\d+)$"
)

# Match count: (NNN matches) or (NNN match)
_MATCH_COUNT_RE = re.compile(r"\((\d+)\s+matches?\)")


def _parse_ipv4_ace(line: str, acl_type: str) -> AccessListEntry | None:
    """Parse a single IPv4 ACE line."""
    match = _IPV4_ACE_RE.match(line)
    if not match:
        return None

    sequence = int(match.group("sequence"))
    action = match.group("action")
    rest = match.group("rest").strip()

    full_line = f"{action} {rest}"

    # Extract match count if present
    matches: int | None = None
    mc_match = _MATCH_COUNT_RE.search(full_line)
    if mc_match:
        matches = int(mc_match.group(1))
        full_line = (
            full_line[: mc_match.start()] + full_line[mc_match.end() :]
        ).strip()
        full_line = " ".join(full_line.split())

    body = full_line.split(None, 1)[1] if " " in full_line else ""
    if acl_type.startswith("Standard"):
        parsed = parse_standard_ace_body(body)
    else:
        parsed = parse_extended_ace_body(body, ip_version=4)

    entry: dict[str, object] = {
        "sequence": sequence,
        "action": action,
        "line": full_line,
        "parsed": parsed,
    }
    if matches is not None:
        entry["matches"] = matches
    return cast(AccessListEntry, entry)


def _parse_ipv6_ace(line: str) -> AccessListEntry | None:
    """Parse a single IPv6 ACE line."""
    match = _IPV6_ACE_RE.match(line)
    if not match:
        return None

    sequence = int(match.group("sequence"))
    action = match.group("action")
    rest = match.group("rest").strip()

    # Remove match count from rest if present
    matches: int | None = None
    mc_match = _MATCH_COUNT_RE.search(rest)
    if mc_match:
        matches = int(mc_match.group(1))
        rest = (rest[: mc_match.start()] + rest[mc_match.end() :]).strip()
        rest = " ".join(rest.split())

    full_line = f"{action} {rest}"
    # rest already includes the protocol as first token (e.g. "ipv6 any any")
    parsed = parse_extended_ace_body(rest, ip_version=6)

    entry: dict[str, object] = {
        "sequence": sequence,
        "action": action,
        "line": full_line,
        "parsed": parsed,
    }
    if matches is not None:
        entry["matches"] = matches
    return cast(AccessListEntry, entry)


def _try_header(
    stripped: str,
) -> tuple[str, str, bool] | None:
    """Try to match an ACL header line.

    Returns:
        Tuple of (name, type, is_ipv6) if a header was matched, else None.
    """
    header_match = _IPV4_HEADER_RE.match(stripped)
    if header_match:
        return header_match.group("name"), header_match.group("type"), False

    header_match = _IPV6_HEADER_RE.match(stripped)
    if header_match:
        return header_match.group("name"), header_match.group("type"), True

    return None


@register(OS.CISCO_IOSXE, "show access-lists")
class ShowAccessListsParser(BaseParser[ShowAccessListsResult]):
    """Parser for 'show access-lists' on IOS-XE.

    Handles both Extended/Standard IP access lists and IPv6 access lists
    in a single unified output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.ACL, ParserTag.SECURITY}
    )

    @classmethod
    def parse(cls, output: str) -> ShowAccessListsResult:
        """Parse 'show access-lists' output.

        Args:
            output: Raw CLI output from 'show access-lists' command.

        Returns:
            Parsed data with access lists keyed by name.

        Raises:
            ValueError: If no access lists found in output.
        """
        access_lists: dict[str, AccessList] = {}
        current_name: str | None = None
        current_type: str | None = None
        is_ipv6 = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            header = _try_header(stripped)
            if header:
                current_name, current_type, is_ipv6 = header
                access_lists[current_name] = {
                    "type": current_type,
                    "entries": {},
                }
                continue

            if current_name is None or current_type is None:
                continue

            if is_ipv6:
                entry = _parse_ipv6_ace(stripped)
            else:
                entry = _parse_ipv4_ace(stripped, current_type)

            if entry:
                seq_key = str(entry["sequence"])
                access_lists[current_name]["entries"][seq_key] = entry

        if not access_lists:
            msg = "No access lists found in output"
            raise ValueError(msg)

        return cast(ShowAccessListsResult, {"access_lists": access_lists})
