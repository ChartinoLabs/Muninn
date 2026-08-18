"""Parser for 'show snmp community' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SnmpCommunityEntry(TypedDict):
    """Schema for a single SNMP community entry."""

    access: str
    community_view: NotRequired[str]
    access_list: NotRequired[str]
    ipv6_access_list: NotRequired[str]


@register(OS.ARISTA_EOS, "show snmp community")
class ShowSnmpCommunityParser(BaseParser[dict[str, SnmpCommunityEntry]]):
    """Parser for 'show snmp community' command on Arista EOS.

    Returns a dict-of-dicts keyed by community name. Each entry contains
    the access type (read-only/read-write) and optional access list or
    community view fields.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SNMP})

    _COMMUNITY_NAME = re.compile(r"^Community name:\s*(?P<name>\S+)")
    _COMMUNITY_ACCESS = re.compile(r"^Community access:\s*(?P<access>.+)$")
    _COMMUNITY_VIEW = re.compile(r"^Community view:\s*(?P<view>\S+)")
    _ACCESS_LIST = re.compile(r"^Access list:\s*(?P<acl>\S+)")
    _IPV6_ACCESS_LIST = re.compile(r"^IPv6 access list:\s*(?P<acl>\S+)")

    # Maps regex pattern attribute names to the dict key and capture group
    # used when populating a community entry.
    _FIELD_PATTERNS: ClassVar[tuple[tuple[str, str, str], ...]] = (
        ("_COMMUNITY_ACCESS", "access", "access"),
        ("_COMMUNITY_VIEW", "community_view", "view"),
        ("_ACCESS_LIST", "access_list", "acl"),
        ("_IPV6_ACCESS_LIST", "ipv6_access_list", "acl"),
    )

    @classmethod
    def _parse_entry_line(cls, line: str, entry: dict[str, str]) -> bool:
        """Try to match a line against community detail patterns.

        Returns True if the line matched a known field pattern.
        """
        for attr, key, group in cls._FIELD_PATTERNS:
            pattern: re.Pattern[str] = getattr(cls, attr)
            if match := pattern.match(line):
                entry[key] = match.group(group).strip()
                return True
        return False

    @classmethod
    def parse(cls, output: str) -> dict[str, SnmpCommunityEntry]:
        """Parse 'show snmp community' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of community entries keyed by community name.
        """
        result: dict[str, SnmpCommunityEntry] = {}
        current_name: str | None = None
        current_entry: dict[str, str] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := cls._COMMUNITY_NAME.match(stripped):
                if current_name is not None:
                    result[current_name] = cast(SnmpCommunityEntry, current_entry)
                current_name = match.group("name")
                current_entry = {}
                continue

            cls._parse_entry_line(stripped, current_entry)

        # Save last entry
        if current_name is not None:
            result[current_name] = cast(SnmpCommunityEntry, current_entry)

        return result
