"""Parser for 'show snmp view' command on IOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SubtreeEntry(TypedDict):
    """Schema for a single subtree within an SNMP view."""

    type: str
    storage_type: str
    status: str
    mask: NotRequired[str]


class ViewEntry(TypedDict):
    """Schema for a single SNMP view, keyed by subtree OID/name."""

    subtrees: dict[str, SubtreeEntry]


class ShowSnmpViewResult(TypedDict):
    """Schema for 'show snmp view' parsed output."""

    views: dict[str, ViewEntry]


_NOT_ENABLED_RE = re.compile(r"^%SNMP agent not enabled\s*$")
_ENTRY_RE = re.compile(
    r"^(?P<view>\S+)\s+(?P<subtree>\S+)\s+(?P<mask>\S+)\s+"
    r"(?P<type>included|excluded)\s+(?P<storage>\S+)\s+(?P<status>\S+)\s*$"
)
_MASK_PLACEHOLDERS = frozenset({"-"})


@register(OS.CISCO_IOS, "show snmp view")
class ShowSnmpViewParser(BaseParser[ShowSnmpViewResult]):
    """Parser for 'show snmp view' command on IOS.

    Example output:
        v1default mib-2 - included nonvolatile active
        v1default cisco - included nonvolatile active
        testview iso - included nonvolatile active

    When SNMP is not enabled on the device, the command returns
    ``%SNMP agent not enabled`` and the parser yields an empty ``views`` map.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SNMP})

    @classmethod
    def parse(cls, output: str) -> ShowSnmpViewResult:
        """Parse 'show snmp view' output.

        Args:
            output: Raw CLI output from 'show snmp view' command.

        Returns:
            Parsed SNMP view data keyed by view name then by subtree.

        Raises:
            ValueError: If the output is non-empty but unrecognized.
        """
        views: dict[str, ViewEntry] = {}

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if _NOT_ENABLED_RE.match(line):
                return ShowSnmpViewResult(views={})

            match = _ENTRY_RE.match(line)
            if not match:
                continue

            view_name = match.group("view")
            subtree = match.group("subtree")
            entry: SubtreeEntry = {
                "type": match.group("type"),
                "storage_type": match.group("storage"),
                "status": match.group("status"),
            }
            mask = match.group("mask")
            if mask not in _MASK_PLACEHOLDERS:
                entry["mask"] = mask

            view = views.setdefault(view_name, cast(ViewEntry, {"subtrees": {}}))
            view["subtrees"][subtree] = entry

        if not views:
            msg = "No SNMP view entries found in output"
            raise ValueError(msg)

        return ShowSnmpViewResult(views=views)
