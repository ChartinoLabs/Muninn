"""Parser for 'show snmp user' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SnmpUserEntry(TypedDict):
    """Schema for a single SNMP user entry."""

    engine_id: str
    storage_type: str
    authentication_protocol: str
    privacy_protocol: str
    group_name: str
    access_list: NotRequired[str]


class ShowSnmpUserResult(TypedDict):
    """Schema for 'show snmp user' parsed output."""

    users: dict[str, SnmpUserEntry]


_USER_NAME_PATTERN = re.compile(r"^User\s+name:\s+(?P<user_name>\S+)")
_ENGINE_ID_PATTERN = re.compile(r"^Engine\s+ID:\s+(?P<engine_id>\S+)")
_STORAGE_TYPE_PATTERN = re.compile(
    r"^storage-type:\s+(?P<storage_type>\S+)\s+active"
    r"(?:\s+access-list:\s+(?P<access_list>\S+))?"
)
_AUTH_PROTOCOL_PATTERN = re.compile(
    r"^Authentication\s+Protocol:\s+(?P<auth_protocol>\S+)"
)
_PRIVACY_PROTOCOL_PATTERN = re.compile(
    r"^Privacy\s+Protocol:\s+(?P<privacy_protocol>\S+)"
)
_GROUP_NAME_PATTERN = re.compile(r"^Group-name:\s+(?P<group_name>\S+)")


@register(OS.CISCO_IOS, "show snmp user")
class ShowSnmpUserParser(BaseParser[ShowSnmpUserResult]):
    """Parser for 'show snmp user' command.

    Example output:
        User name: user_snmp1
        Engine ID: 80000009030000451DEC1085
        storage-type: nonvolatile        active
        Authentication Protocol: SHA
        Privacy Protocol: AES128
        Group-name: managerpriv
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SNMP})

    _FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        (_ENGINE_ID_PATTERN, "engine_id"),
        (_STORAGE_TYPE_PATTERN, "storage_type"),
        (_AUTH_PROTOCOL_PATTERN, "authentication_protocol"),
        (_PRIVACY_PROTOCOL_PATTERN, "privacy_protocol"),
        (_GROUP_NAME_PATTERN, "group_name"),
    )

    @classmethod
    def parse(cls, output: str) -> ShowSnmpUserResult:
        """Parse 'show snmp user' output.

        Args:
            output: Raw CLI output from 'show snmp user' command.

        Returns:
            Parsed SNMP user data keyed by user name.

        Raises:
            ValueError: If no SNMP users found in output.
        """
        users: dict[str, SnmpUserEntry] = {}
        current_user: str | None = None
        current_entry: dict[str, str] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            user_match = _USER_NAME_PATTERN.match(line)
            if user_match:
                if current_user and current_entry:
                    users[current_user] = _build_entry(current_entry)
                current_user = user_match.group("user_name")
                current_entry = {}
                continue

            _match_field_patterns(cls._FIELD_PATTERNS, line, current_entry)

        if current_user and current_entry:
            users[current_user] = _build_entry(current_entry)

        if not users:
            msg = "No SNMP users found in output"
            raise ValueError(msg)

        return ShowSnmpUserResult(users=users)


def _match_field_patterns(
    patterns: tuple[tuple[re.Pattern[str], str], ...],
    line: str,
    entry: dict[str, str],
) -> None:
    """Match a line against field patterns and populate entry dict."""
    for pattern, field_name in patterns:
        match = pattern.match(line)
        if not match:
            continue
        if field_name == "storage_type":
            entry["storage_type"] = match.group("storage_type")
            access_list = match.group("access_list")
            if access_list:
                entry["access_list"] = access_list
        else:
            entry[field_name] = match.group(1)
        break


def _build_entry(raw: dict[str, str]) -> SnmpUserEntry:
    """Build a typed SnmpUserEntry from raw parsed fields."""
    entry: SnmpUserEntry = {
        "engine_id": raw.get("engine_id", ""),
        "storage_type": raw.get("storage_type", ""),
        "authentication_protocol": raw.get("authentication_protocol", ""),
        "privacy_protocol": raw.get("privacy_protocol", ""),
        "group_name": raw.get("group_name", ""),
    }
    if "access_list" in raw:
        entry["access_list"] = raw["access_list"]
    return entry
