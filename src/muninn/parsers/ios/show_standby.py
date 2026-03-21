"""Parser for 'show standby' command on IOS."""

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class TrackEntry(TypedDict):
    """Schema for a tracked object or interface."""

    type: str
    name: str
    state: NotRequired[str]
    decrement: NotRequired[int]


class StandbyGroupEntry(TypedDict):
    """Schema for a single HSRP standby group."""

    interface: str
    group: int
    version: NotRequired[int]
    state: str
    state_changes: int
    last_state_change: str
    virtual_ip: str
    secondary_virtual_ips: NotRequired[list[str]]
    active_virtual_mac: str
    local_virtual_mac: str
    hello_time_sec: int
    hold_time_sec: int
    authentication_type: NotRequired[str]
    authentication_string: NotRequired[str]
    preemption: bool
    preemption_delay_min_sec: NotRequired[int]
    preemption_delay_reload_sec: NotRequired[int]
    active_router: str
    active_router_priority: NotRequired[int]
    active_router_mac: NotRequired[str]
    standby_router: str
    standby_router_priority: NotRequired[int]
    priority: int
    configured_priority: int
    group_name: NotRequired[str]
    tracks: NotRequired[dict[str, dict[str, TrackEntry]]]


class StandbyInterfaceEntry(TypedDict):
    """Schema for HSRP groups under a single interface."""

    groups: dict[str, StandbyGroupEntry]


class ShowStandbyResult(TypedDict):
    """Schema for 'show standby' parsed output."""

    interfaces: dict[str, StandbyInterfaceEntry]


# Block header: "Vlan50 - Group 50 (version 2)" or "Vlan50 - Group 50"
_BLOCK_HEADER_RE = re.compile(
    r"^(?P<interface>\S+)\s+-\s+Group\s+(?P<group>\d+)"
    r"(?:\s+\(version\s+(?P<version>\d+)\))?\s*$"
)

_STATE_RE = re.compile(r"^State\s+is\s+(?P<state>\S+)")
_STATE_CHANGE_RE = re.compile(
    r"^(?P<count>\d+)\s+state\s+changes?,"
    r"\s+last\s+state\s+change\s+(?P<duration>\S+)"
)
_VIRTUAL_IP_RE = re.compile(r"^Virtual\s+IP\s+address\s+is\s+(?P<ip>\S+)")
_SECONDARY_IP_RE = re.compile(r"^Secondary\s+virtual\s+IP\s+address\s+(?P<ip>\S+)")
_ACTIVE_MAC_RE = re.compile(r"^Active\s+virtual\s+MAC\s+address\s+is\s+(?P<mac>\S+)")
_LOCAL_MAC_RE = re.compile(r"^Local\s+virtual\s+MAC\s+address\s+is\s+(?P<mac>\S+)")
_HELLO_HOLD_RE = re.compile(
    r"^Hello\s+time\s+(?P<hello>\d+)\s+sec,\s+hold\s+time\s+(?P<hold>\d+)\s+sec"
)
_AUTH_RE = re.compile(
    r"^Authentication\s+(?P<type>\S+),"
    r"\s+(?:key-chain\s+\"(?P<keychain>[^\"]+)\""
    r"|key-string"
    r"|string\s+\"(?P<string>[^\"]+)\")"
)
_PREEMPT_RE = re.compile(
    r"^Preemption\s+(?P<enabled>enabled|disabled)"
    r"(?:,\s+delay\s+min\s+(?P<min>\d+)\s+secs?)?"
    r"(?:,\s+reload\s+(?P<reload>\d+)\s+secs?)?"
)
_ACTIVE_ROUTER_RE = re.compile(
    r"^Active\s+router\s+is\s+(?P<router>\S+?)(?:,\s+priority\s+(?P<priority>\d+))?"
    r"(?:\s+\(expires\s+in\s+\S+\s+sec\))?\s*$"
)
_ACTIVE_ROUTER_MAC_RE = re.compile(r"^MAC\s+address\s+is\s+(?P<mac>\S+)")
_STANDBY_ROUTER_RE = re.compile(
    r"^Standby\s+router\s+is\s+(?P<router>\S+?)(?:,\s+priority\s+(?P<priority>\d+))?"
    r"(?:\s+\(expires\s+in\s+\S+\s+sec\))?\s*$"
)
_PRIORITY_RE = re.compile(
    r"^Priority\s+(?P<priority>\d+)\s+\(configured\s+(?P<configured>\d+)\)"
)
_GROUP_NAME_RE = re.compile(
    r"^(?:Group\s+name|IP\s+redundancy\s+name)\s+is\s+\"(?P<name>[^\"]+)\""
)
_TRACK_OBJECT_RE = re.compile(
    r"^Track\s+object\s+(?P<name>\S+)"
    r"(?:\s+state\s+(?P<state>\S+))?"
    r"(?:\s+decrement\s+(?P<decrement>\d+))?"
    r"(?:\s+\((?P<note>[^)]+)\))?"
)
_TRACK_INTERFACE_RE = re.compile(
    r"^Track\s+interface\s+(?P<name>\S+)"
    r"\s+state\s+(?P<state>\S+)"
    r"(?:\s+decrement\s+(?P<decrement>\d+))?"
)


def _split_blocks(output: str) -> list[tuple[re.Match[str], list[str]]]:
    """Split output into blocks, each starting with an interface/group header."""
    blocks: list[tuple[re.Match[str], list[str]]] = []
    current_match: re.Match[str] | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        header = _BLOCK_HEADER_RE.match(line.strip())
        if header:
            if current_match is not None:
                blocks.append((current_match, current_lines))
            current_match = header
            current_lines = []
        elif current_match is not None:
            current_lines.append(line)

    if current_match is not None:
        blocks.append((current_match, current_lines))

    return blocks


def _match_track_line(stripped: str) -> TrackEntry | None:
    """Match a single track line and return a TrackEntry or None."""
    match = _TRACK_OBJECT_RE.match(stripped)
    if match:
        entry: TrackEntry = {"type": "object", "name": match.group("name")}
        state = match.group("state")
        note = match.group("note")
        if state:
            entry["state"] = state
        elif note:
            entry["state"] = note
        if match.group("decrement"):
            entry["decrement"] = int(match.group("decrement"))
        return entry

    match = _TRACK_INTERFACE_RE.match(stripped)
    if match:
        iface_entry: TrackEntry = {"type": "interface", "name": match.group("name")}
        if match.group("state"):
            iface_entry["state"] = match.group("state")
        if match.group("decrement"):
            iface_entry["decrement"] = int(match.group("decrement"))
        return iface_entry

    return None


def _parse_block(
    header: re.Match[str], lines: list[str]
) -> tuple[str, str, StandbyGroupEntry]:
    """Parse a single interface/group block into a StandbyGroupEntry."""
    interface = canonical_interface_name(header.group("interface"), os=OS.CISCO_IOS)
    group = header.group("group")

    entry: dict[str, object] = {
        "interface": interface,
        "group": int(group),
    }

    if header.group("version"):
        entry["version"] = int(header.group("version"))

    _extract_fields(lines, entry)

    return interface, group, entry  # type: ignore[return-value]


def _store_group(
    interfaces: dict[str, StandbyInterfaceEntry],
    interface: str,
    group: str,
    entry: StandbyGroupEntry,
) -> None:
    """Store a parsed standby group underneath its interface."""
    interface_entry = interfaces.setdefault(interface, StandbyInterfaceEntry(groups={}))
    interface_entry["groups"][group] = entry


@dataclass
class _FieldContext:
    """Mutable context for collecting list-type fields during parsing."""

    secondary_ips: list[str] = field(default_factory=list)
    tracks: dict[str, dict[str, TrackEntry]] = field(default_factory=dict)


def _extract_fields(lines: list[str], entry: dict[str, object]) -> None:
    """Extract all fields from the body lines of a block."""
    ctx = _FieldContext()
    expect_active_mac = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if _try_simple_fields(stripped, entry):
            expect_active_mac = False
            continue

        if expect_active_mac:
            mac_match = _ACTIVE_ROUTER_MAC_RE.match(stripped)
            if mac_match:
                entry["active_router_mac"] = mac_match.group("mac")
                expect_active_mac = False
                continue

        expect_active_mac = _try_remaining_fields(stripped, entry, ctx)

    if ctx.secondary_ips:
        entry["secondary_virtual_ips"] = ctx.secondary_ips
    if ctx.tracks:
        entry["tracks"] = ctx.tracks


def _try_simple_fields(stripped: str, entry: dict[str, object]) -> bool:
    """Try to match simple single-line fields. Returns True if matched."""
    match = _STATE_RE.match(stripped)
    if match:
        entry["state"] = match.group("state")
        return True

    match = _STATE_CHANGE_RE.match(stripped)
    if match:
        entry["state_changes"] = int(match.group("count"))
        entry["last_state_change"] = match.group("duration")
        return True

    match = _VIRTUAL_IP_RE.match(stripped)
    if match:
        entry["virtual_ip"] = match.group("ip")
        return True

    match = _ACTIVE_MAC_RE.match(stripped)
    if match:
        entry["active_virtual_mac"] = match.group("mac")
        return True

    match = _LOCAL_MAC_RE.match(stripped)
    if match:
        entry["local_virtual_mac"] = match.group("mac")
        return True

    match = _HELLO_HOLD_RE.match(stripped)
    if match:
        entry["hello_time_sec"] = int(match.group("hello"))
        entry["hold_time_sec"] = int(match.group("hold"))
        return True

    return False


def _apply_secondary_ip(
    match: re.Match[str],
    _entry: dict[str, object],
    ctx: _FieldContext,
) -> bool:
    """Handle secondary virtual IP match."""
    ctx.secondary_ips.append(match.group("ip"))
    return False


def _apply_auth(
    match: re.Match[str],
    entry: dict[str, object],
    _ctx: _FieldContext,
) -> bool:
    """Handle authentication match."""
    entry["authentication_type"] = match.group("type")
    auth_str = match.group("keychain") or match.group("string")
    if auth_str:
        entry["authentication_string"] = auth_str
    return False


def _apply_preempt(
    match: re.Match[str],
    entry: dict[str, object],
    _ctx: _FieldContext,
) -> bool:
    """Handle preemption match."""
    entry["preemption"] = match.group("enabled") == "enabled"
    if match.group("min"):
        entry["preemption_delay_min_sec"] = int(match.group("min"))
    if match.group("reload"):
        entry["preemption_delay_reload_sec"] = int(match.group("reload"))
    return False


def _apply_active_router(
    match: re.Match[str],
    entry: dict[str, object],
    _ctx: _FieldContext,
) -> bool:
    """Handle active router match. Returns True to signal MAC line follows."""
    entry["active_router"] = match.group("router")
    if match.group("priority"):
        entry["active_router_priority"] = int(match.group("priority"))
    return True


def _apply_standby_router(
    match: re.Match[str],
    entry: dict[str, object],
    _ctx: _FieldContext,
) -> bool:
    """Handle standby router match."""
    entry["standby_router"] = match.group("router")
    if match.group("priority"):
        entry["standby_router_priority"] = int(match.group("priority"))
    return False


def _apply_priority(
    match: re.Match[str],
    entry: dict[str, object],
    _ctx: _FieldContext,
) -> bool:
    """Handle priority match."""
    entry["priority"] = int(match.group("priority"))
    entry["configured_priority"] = int(match.group("configured"))
    return False


def _apply_group_name(
    match: re.Match[str],
    entry: dict[str, object],
    _ctx: _FieldContext,
) -> bool:
    """Handle group name match."""
    entry["group_name"] = match.group("name")
    return False


# Type alias for handler functions
_Handler = Callable[[re.Match[str], dict[str, object], "_FieldContext"], bool]

# Pattern table: (compiled regex, handler function)
_FIELD_HANDLERS: tuple[tuple[re.Pattern[str], _Handler], ...] = (
    (_SECONDARY_IP_RE, _apply_secondary_ip),
    (_AUTH_RE, _apply_auth),
    (_PREEMPT_RE, _apply_preempt),
    (_ACTIVE_ROUTER_RE, _apply_active_router),
    (_STANDBY_ROUTER_RE, _apply_standby_router),
    (_PRIORITY_RE, _apply_priority),
    (_GROUP_NAME_RE, _apply_group_name),
)


def _try_remaining_fields(
    stripped: str,
    entry: dict[str, object],
    ctx: _FieldContext,
) -> bool:
    """Try remaining field patterns. Returns True if active router matched."""
    for pattern, handler in _FIELD_HANDLERS:
        match = pattern.match(stripped)
        if match:
            return handler(match, entry, ctx)

    track = _match_track_line(stripped)
    if track:
        ctx.tracks.setdefault(track["type"], {})[track["name"]] = track

    return False


@register(OS.CISCO_IOS, "show standby")
class ShowStandbyParser(BaseParser[ShowStandbyResult]):
    """Parser for 'show standby' command.

    Example output:
        Vlan50 - Group 50 (version 2)
          State is Standby
            1 state change, last state change 10w3d
          Virtual IP address is 10.0.52.161
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.FHRP})

    @classmethod
    def parse(cls, output: str) -> ShowStandbyResult:
        """Parse 'show standby' output.

        Args:
            output: Raw CLI output from 'show standby' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        blocks = _split_blocks(output)

        if not blocks:
            msg = "No HSRP standby groups found in output"
            raise ValueError(msg)

        interfaces: dict[str, StandbyInterfaceEntry] = {}
        for header, lines in blocks:
            interface, group, entry = _parse_block(header, lines)
            _store_group(interfaces, interface, group, entry)

        return {"interfaces": interfaces}
