"""Parser for 'show snmp community' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SnmpCommunityEntry(TypedDict):
    """Schema for a single SNMP community entry."""

    index: str
    security_name: str
    storage_type: str
    access_list: NotRequired[str]


class ShowSnmpCommunityResult(TypedDict):
    """Schema for 'show snmp community' parsed output."""

    communities: dict[str, SnmpCommunityEntry]


_NAME_PATTERN = re.compile(r"^Community\s+name:\s+(?P<name>\S+)$")
_INDEX_PATTERN = re.compile(r"^Community\s+Index:\s+(?P<index>\S+)$")
_SECURITY_PATTERN = re.compile(r"^Community\s+SecurityName:\s+(?P<security_name>\S+)$")
_STORAGE_PATTERN = re.compile(
    r"^storage-type:\s+(?P<storage_type>\S+)\s+active"
    r"(?:\s+access-list:\s+(?P<access_list>\S+))?$"
)

_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_NAME_PATTERN, "name"),
    (_INDEX_PATTERN, "index"),
    (_SECURITY_PATTERN, "security_name"),
)


def _parse_block(block: str) -> tuple[str, SnmpCommunityEntry] | None:
    """Parse a single community block into a (name, entry) tuple."""
    fields: dict[str, str] = {}
    storage_match: re.Match[str] | None = None

    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        for pattern, field in _FIELD_PATTERNS:
            if match := pattern.match(line):
                fields[field] = match.group(field)
                break
        else:
            storage_match = _STORAGE_PATTERN.match(line)

    if not all(k in fields for k in ("name", "index", "security_name")):
        return None
    if storage_match is None:
        return None

    entry = SnmpCommunityEntry(
        index=fields["index"],
        security_name=fields["security_name"],
        storage_type=storage_match.group("storage_type"),
    )
    access_list = storage_match.group("access_list")
    if access_list:
        entry["access_list"] = access_list
    return fields["name"], entry


@register(OS.CISCO_IOS, "show snmp community")
class ShowSnmpCommunityParser(BaseParser[ShowSnmpCommunityResult]):
    """Parser for 'show snmp community' command.

    Example output:
        Community name: public
        Community Index: cisco1
        Community SecurityName: public
        storage-type: nonvolatile        active
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SNMP})

    @classmethod
    def parse(cls, output: str) -> ShowSnmpCommunityResult:
        """Parse 'show snmp community' output.

        Args:
            output: Raw CLI output from 'show snmp community' command.

        Returns:
            Parsed data keyed by community name.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        communities: dict[str, SnmpCommunityEntry] = {}
        blocks = re.split(r"\n\s*\n", output)

        for block in blocks:
            result = _parse_block(block)
            if result is not None:
                name, entry = result
                communities[name] = entry

        if not communities:
            msg = "No SNMP community entries found in output"
            raise ValueError(msg)

        return ShowSnmpCommunityResult(communities=communities)
