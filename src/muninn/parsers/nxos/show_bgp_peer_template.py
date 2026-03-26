"""Parser for 'show bgp peer-template' command on NX-OS."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PeerTemplateEntry(TypedDict):
    """Schema for a single BGP peer-template entry."""

    remote_as: NotRequired[int]
    inherit_template: NotRequired[str]
    description: NotRequired[str]
    update_source: NotRequired[str]
    disable_connected_check: NotRequired[bool]
    bfd_live_detection: NotRequired[bool]
    ebgp_multihop: NotRequired[int]
    tcp_md5_auth: NotRequired[str]
    passive_only: NotRequired[bool]
    remove_private_as: NotRequired[bool]
    holdtime: NotRequired[int]
    keepalive_interval: NotRequired[int]
    local_as_inactive: NotRequired[bool]
    members: NotRequired[list[str]]


class ShowBgpPeerTemplateResult(TypedDict):
    """Schema for 'show bgp peer-template' parsed output."""

    peer_templates: dict[str, PeerTemplateEntry]


_TEMPLATE_HEADER_RE = re.compile(r"^BGP peer-template is (\S+)")
_REMOTE_AS_RE = re.compile(r"^Remote AS (\d+)")
_INHERIT_RE = re.compile(r"^Inherits session configuration from session-template (\S+)")
_DESCRIPTION_RE = re.compile(r"^Description:\s+(.+)")
_UPDATE_SOURCE_RE = re.compile(r"^Using (\S+) as update source")
_EBGP_MULTIHOP_RE = re.compile(r"^External BGP peer might be upto (\d+) hops away")
_TCP_MD5_RE = re.compile(r"^TCP MD5 authentication is (enabled|disabled)")
_HOLD_KEEP_RE = re.compile(r"^Hold time = (\d+), keepalive interval is (\d+) seconds")
_MEMBERS_RE = re.compile(r"^Members of peer-template \S+:")
_MEMBER_LINE_RE = re.compile(r"^\S+:\s+(\S+)")

_INT_FIELDS = frozenset({"remote_as", "ebgp_multihop"})
_INTERFACE_FIELDS = frozenset({"update_source"})

_STR_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_REMOTE_AS_RE, "remote_as"),
    (_INHERIT_RE, "inherit_template"),
    (_DESCRIPTION_RE, "description"),
    (_UPDATE_SOURCE_RE, "update_source"),
    (_TCP_MD5_RE, "tcp_md5_auth"),
    (_EBGP_MULTIHOP_RE, "ebgp_multihop"),
)

_BOOL_FLAG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^Connected check is disabled"), "disable_connected_check"),
    (re.compile(r"^BFD live-detection is configured"), "bfd_live_detection"),
    (re.compile(r"^Only passive connection setup allowed"), "passive_only"),
    (re.compile(r"^Private AS numbers removed"), "remove_private_as"),
    (re.compile(r"^Neighbor local-as command not active"), "local_as_inactive"),
)


def _convert_field(field: str, value: str) -> str | int:
    """Convert a field value to its appropriate type."""
    if field in _INT_FIELDS:
        return int(value)
    if field in _INTERFACE_FIELDS:
        return canonical_interface_name(value, os=OS.CISCO_NXOS)
    return value


def _apply_str_fields(lines: list[str], entry: PeerTemplateEntry) -> None:
    """Extract string and integer fields using capture-group patterns."""
    _d: dict[str, Any] = entry  # untyped alias for dynamic key assignment
    for pattern, field in _STR_FIELD_PATTERNS:
        for line in lines:
            m = pattern.match(line)
            if m:
                _d[field] = _convert_field(field, m.group(1))
                break


def _apply_bool_flags(lines: list[str], entry: PeerTemplateEntry) -> None:
    """Set boolean flags found in the output lines."""
    _d: dict[str, Any] = entry  # untyped alias for dynamic key assignment
    for line in lines:
        for pattern, field in _BOOL_FLAG_PATTERNS:
            if pattern.match(line):
                _d[field] = True
                break


def _apply_hold_keepalive(lines: list[str], entry: PeerTemplateEntry) -> None:
    """Parse hold time and keepalive interval."""
    for line in lines:
        if m := _HOLD_KEEP_RE.match(line):
            entry["holdtime"] = int(m.group(1))
            entry["keepalive_interval"] = int(m.group(2))
            return


def _collect_members(lines: list[str]) -> list[str]:
    """Collect member addresses from lines after the Members header."""
    members: list[str] = []
    in_members = False
    for line in lines:
        if _MEMBERS_RE.match(line):
            in_members = True
        elif in_members and (m := _MEMBER_LINE_RE.match(line)):
            members.append(m.group(1))
    return members


def _parse_template_block(lines: list[str]) -> PeerTemplateEntry:
    """Parse a single peer-template block into a PeerTemplateEntry."""
    entry: PeerTemplateEntry = {}
    _apply_str_fields(lines, entry)
    _apply_bool_flags(lines, entry)
    _apply_hold_keepalive(lines, entry)
    members = _collect_members(lines)
    if members:
        entry["members"] = members
    return entry


@register(OS.CISCO_NXOS, "show bgp peer-template")
class ShowBgpPeerTemplateParser(BaseParser["ShowBgpPeerTemplateResult"]):
    """Parser for 'show bgp peer-template' command.

    Example output:
        BGP peer-template is PEER
        Remote AS 500
        Inherits session configuration from session-template PEER-SESSION
        Description: DESC
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpPeerTemplateResult:
        """Parse 'show bgp peer-template' output.

        Args:
            output: Raw CLI output from 'show bgp peer-template' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        peer_templates: dict[str, PeerTemplateEntry] = {}
        current_name: str | None = None
        current_lines: list[str] = []

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            m = _TEMPLATE_HEADER_RE.match(line)
            if m:
                if current_name is not None:
                    peer_templates[current_name] = _parse_template_block(current_lines)
                current_name = m.group(1)
                current_lines = []
            elif current_name is not None:
                current_lines.append(line)

        if current_name is not None:
            peer_templates[current_name] = _parse_template_block(current_lines)

        if not peer_templates:
            msg = "No peer-template entries found in output"
            raise ValueError(msg)

        return {"peer_templates": peer_templates}
