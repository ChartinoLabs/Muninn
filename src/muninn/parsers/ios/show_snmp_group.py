"""Parser for 'show snmp group' command on IOS."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SnmpGroupEntry(TypedDict):
    """Schema for a single SNMP group entry."""

    group_name: str
    security_model: str
    context_name: NotRequired[str]
    storage_type: str
    read_view: NotRequired[str]
    write_view: NotRequired[str]
    notify_view: NotRequired[str]
    row_status: str
    access_list: NotRequired[str]


class ShowSnmpGroupResult(TypedDict):
    """Schema for 'show snmp group' parsed output."""

    groups: dict[str, dict[str, SnmpGroupEntry]]


_SEPARATOR_PATTERN = re.compile(r"^\s*$")
_GROUPNAME_PATTERN = re.compile(
    r"^groupname:\s*(\S+)\s+security model:(.+)$", re.MULTILINE
)
_CONTEXT_PATTERN = re.compile(r"contextname:\s*(.+?)\s{2,}storage-type:\s*(\S+)")
_READVIEW_PATTERN = re.compile(r"readview\s*:\s*(.+?)\s{2,}writeview:\s*(.*)")
_NOTIFYVIEW_PATTERN = re.compile(r"notifyview:\s*(.*)")
_ROWSTATUS_PATTERN = re.compile(r"row status:\s*(\S+)(?:\s+access-list:\s*(\S+))?")

_NO_VALUE_MARKERS = frozenset(
    {
        "<no context specified>",
        "<no writeview specified>",
        "<no notifyview specified>",
        "<no readview specified>",
    }
)


def _normalize_view(value: str | None) -> str | None:
    """Return None for sentinel/empty view values, stripped string otherwise."""
    if value is None:
        return None
    value = value.strip()
    if not value or value in _NO_VALUE_MARKERS:
        return None
    return value


def _set_optional(entry: SnmpGroupEntry, field: str, value: str | None) -> None:
    """Set an optional field on the entry if the value is not None."""
    if value is not None:
        _d = cast(dict[str, Any], entry)
        _d[field] = value


def _extract_views(text: str) -> tuple[str | None, str | None, str | None]:
    """Extract read, write, and notify views from block text.

    Returns:
        Tuple of (read_view, write_view, notify_view), each None if absent.
    """
    read_view_match = _READVIEW_PATTERN.search(text)
    read_view = _normalize_view(read_view_match.group(1)) if read_view_match else None
    write_view = _normalize_view(read_view_match.group(2)) if read_view_match else None

    notify_match = _NOTIFYVIEW_PATTERN.search(text)
    notify_view = _normalize_view(notify_match.group(1)) if notify_match else None

    return read_view, write_view, notify_view


def _parse_block(lines: list[str]) -> SnmpGroupEntry | None:
    """Parse a single SNMP group block into an entry.

    Args:
        lines: Lines comprising one group block.

    Returns:
        Parsed entry, or None if the block is not a valid group.
    """
    text = "\n".join(lines)

    group_match = _GROUPNAME_PATTERN.search(text)
    if not group_match:
        return None

    context_match = _CONTEXT_PATTERN.search(text)
    row_match = _ROWSTATUS_PATTERN.search(text)
    read_view, write_view, notify_view = _extract_views(text)

    entry: SnmpGroupEntry = {
        "group_name": group_match.group(1),
        "security_model": group_match.group(2).strip(),
        "storage_type": context_match.group(2) if context_match else "unknown",
        "row_status": row_match.group(1) if row_match else "unknown",
    }

    context_name = _normalize_view(context_match.group(1)) if context_match else None
    access_list = row_match.group(2) if row_match and row_match.group(2) else None

    _set_optional(entry, "context_name", context_name)
    _set_optional(entry, "read_view", read_view)
    _set_optional(entry, "write_view", write_view)
    _set_optional(entry, "notify_view", notify_view)
    _set_optional(entry, "access_list", access_list)

    return entry


@register(OS.CISCO_IOS, "show snmp group")
class ShowSnmpGroupParser(BaseParser[ShowSnmpGroupResult]):
    """Parser for 'show snmp group' command.

    Example output:
        groupname: GROUP1                           security model:v3 priv
        contextname: <no context specified>         storage-type: nonvolatile
        readview : g1readview                       writeview: <no writeview specified>
        notifyview: g1notifyview
        row status: active      access-list: snmp-acl-name
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SNMP})

    @classmethod
    def parse(cls, output: str) -> ShowSnmpGroupResult:
        """Parse 'show snmp group' output.

        Args:
            output: Raw CLI output from 'show snmp group' command.

        Returns:
            Parsed data with groups keyed by group name, then security model.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        groups: dict[str, dict[str, SnmpGroupEntry]] = {}
        current_block: list[str] = []

        for line in output.splitlines():
            if _SEPARATOR_PATTERN.match(line) and current_block:
                entry = _parse_block(current_block)
                if entry is not None:
                    group_entries = groups.setdefault(entry["group_name"], {})
                    group_entries[entry["security_model"]] = entry
                current_block = []
            else:
                current_block.append(line)

        # Process the last block
        if current_block:
            entry = _parse_block(current_block)
            if entry is not None:
                group_entries = groups.setdefault(entry["group_name"], {})
                group_entries[entry["security_model"]] = entry

        if not groups:
            msg = "No SNMP group entries found in output"
            raise ValueError(msg)

        return ShowSnmpGroupResult(groups=groups)
