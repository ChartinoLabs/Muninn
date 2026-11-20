"""Parser for 'show standby all' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PreemptionDelay(TypedDict):
    """Schema for preemption delay values."""

    minimum: NotRequired[int]
    reload: NotRequired[int]
    sync: NotRequired[int]


class TrackObjectEntry(TypedDict):
    """Schema for a tracked object."""

    id: int
    state: str


class HsrpGroupEntry(TypedDict):
    """Schema for a single HSRP group entry."""

    state: str
    hello_time: int
    hold_time: int
    preemption: bool
    priority: int
    version: NotRequired[int]
    state_changes: NotRequired[int]
    last_state_change: NotRequired[str]
    track_object: NotRequired[TrackObjectEntry]
    virtual_ip: NotRequired[str]
    active_virtual_mac: NotRequired[str]
    local_virtual_mac: NotRequired[str]
    authentication: NotRequired[str]
    auth_key_chain: NotRequired[str]
    preemption_delay: NotRequired[PreemptionDelay]
    active_router: NotRequired[str]
    standby_router: NotRequired[str]
    configured_priority: NotRequired[int]
    group_name: NotRequired[str]


class HsrpInterfaceEntry(TypedDict):
    """Schema for HSRP groups under a single interface."""

    groups: dict[str, HsrpGroupEntry]


class ShowStandbyAllResult(TypedDict):
    """Schema for 'show standby all' parsed output."""

    interfaces: dict[str, HsrpInterfaceEntry]


_SECTION_HEADER_RE = re.compile(
    r"^(?P<interface>\S+)\s+-\s+Group\s+(?P<group>\d+)"
    r"(?:\s+\(version\s+(?P<version>\d+)\))?\s*$"
)
_STATE_RE = re.compile(r"^\s*State\s+is\s+(?P<state>\S+)")
_STATE_CHANGES_RE = re.compile(
    r"^\s*(?P<count>\d+)\s+state\s+change"
    r"(?:s)?(?:,\s*last\s+state\s+change\s+(?P<last_change>\S+))?"
)
_TRACK_RE = re.compile(r"^\s*Track\s+object\s+(?P<id>\d+)\s+(?P<state>\S+)")
_VIRTUAL_IP_RE = re.compile(r"^\s*Virtual\s+IP\s+address\s+is\s+(?P<ip>\S+)")
_ACTIVE_MAC_RE = re.compile(r"^\s*Active\s+virtual\s+MAC\s+address\s+is\s+(?P<mac>\S+)")
_LOCAL_MAC_RE = re.compile(r"^\s*Local\s+virtual\s+MAC\s+address\s+is\s+(?P<mac>\S+)")
_HELLO_RE = re.compile(
    r"^\s*Hello\s+time\s+(?P<hello>\d+)\s+(?:sec|msec)"
    r",\s+hold\s+time\s+(?P<hold>\d+)\s+(?:sec|msec)"
)
_AUTH_RE = re.compile(
    r"^\s*Authentication\s+(?P<auth_type>\w+)"
    r"(?:,\s+key-(?:chain|string)(?:\s+\"(?P<key_chain>[^\"]+)\")?)?"
)
_PREEMPTION_RE = re.compile(
    r"^\s*Preemption\s+(?P<preempt>enabled|disabled)"
    r"(?:,\s+delay\s+(?P<delays>.+))?"
)
_ACTIVE_ROUTER_RE = re.compile(r"^\s*Active\s+router\s+is\s+(?P<active>.+)")
_STANDBY_ROUTER_RE = re.compile(r"^\s*Standby\s+router\s+is\s+(?P<standby>.+)")
_PRIORITY_RE = re.compile(
    r"^\s*Priority\s+(?P<priority>\d+)"
    r"(?:\s+\((?:configured|default)\s+(?P<configured>\d+)\))?"
)
_GROUP_NAME_RE = re.compile(r"^\s*Group\s+name\s+is\s+\"(?P<name>[^\"]+)\"")

_PREEMPT_DELAY_MIN_RE = re.compile(r"min\s+(?P<min>\d+)")
_PREEMPT_DELAY_RELOAD_RE = re.compile(r"reload\s+(?P<reload>\d+)")
_PREEMPT_DELAY_SYNC_RE = re.compile(r"sync\s+(?P<sync>\d+)")


def _parse_preemption_delays(delay_str: str) -> PreemptionDelay:
    """Parse preemption delay values from the delay portion of the line."""
    delay: PreemptionDelay = {}
    if match := _PREEMPT_DELAY_MIN_RE.search(delay_str):
        delay["minimum"] = int(match.group("min"))
    if match := _PREEMPT_DELAY_RELOAD_RE.search(delay_str):
        delay["reload"] = int(match.group("reload"))
    if match := _PREEMPT_DELAY_SYNC_RE.search(delay_str):
        delay["sync"] = int(match.group("sync"))
    return delay


def _extract_router_address(value: str) -> str | None:
    """Extract router IP or 'local' from active or standby router values."""
    candidate = value.strip()
    if candidate.lower() in {"", "unknown"}:
        return None
    return candidate.split(",", maxsplit=1)[0].strip()


def _handle_state(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle state line."""
    entry["state"] = match.group("state")


def _handle_state_changes(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle state changes line."""
    entry["state_changes"] = int(match.group("count"))
    last_change = match.group("last_change")
    if last_change:
        entry["last_state_change"] = last_change


def _handle_track(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle tracked object line."""
    entry["track_object"] = {
        "id": int(match.group("id")),
        "state": match.group("state").strip("()"),
    }


def _handle_virtual_ip(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle virtual IP line."""
    virtual_ip = match.group("ip")
    if virtual_ip.lower() != "unknown":
        entry["virtual_ip"] = virtual_ip


def _handle_active_mac(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle active MAC line."""
    mac = match.group("mac")
    if mac.lower() != "unknown":
        entry["active_virtual_mac"] = mac


def _handle_local_mac(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle local MAC line."""
    entry["local_virtual_mac"] = match.group("mac")


def _handle_hello(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle hello and hold timers."""
    entry["hello_time"] = int(match.group("hello"))
    entry["hold_time"] = int(match.group("hold"))


def _handle_auth(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle authentication line."""
    entry["authentication"] = match.group("auth_type")
    key_chain = match.group("key_chain")
    if key_chain:
        entry["auth_key_chain"] = key_chain


def _handle_preemption(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle preemption line."""
    entry["preemption"] = match.group("preempt") == "enabled"
    delays = match.group("delays")
    if delays:
        parsed_delays = _parse_preemption_delays(delays)
        if parsed_delays:
            entry["preemption_delay"] = parsed_delays


def _handle_active_router(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle active router line."""
    active_router = _extract_router_address(match.group("active"))
    if active_router is not None:
        entry["active_router"] = active_router


def _handle_standby_router(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle standby router line."""
    standby_router = _extract_router_address(match.group("standby"))
    if standby_router is not None:
        entry["standby_router"] = standby_router


def _handle_priority(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle priority line."""
    entry["priority"] = int(match.group("priority"))
    configured = match.group("configured")
    if configured:
        entry["configured_priority"] = int(configured)


def _handle_group_name(entry: HsrpGroupEntry, match: re.Match[str]) -> None:
    """Handle group name line."""
    entry["group_name"] = match.group("name")


_FieldHandler = Callable[[HsrpGroupEntry, re.Match[str]], None]

_FIELD_HANDLERS: tuple[tuple[re.Pattern[str], _FieldHandler], ...] = (
    (_STATE_RE, _handle_state),
    (_STATE_CHANGES_RE, _handle_state_changes),
    (_TRACK_RE, _handle_track),
    (_VIRTUAL_IP_RE, _handle_virtual_ip),
    (_ACTIVE_MAC_RE, _handle_active_mac),
    (_LOCAL_MAC_RE, _handle_local_mac),
    (_HELLO_RE, _handle_hello),
    (_AUTH_RE, _handle_auth),
    (_PREEMPTION_RE, _handle_preemption),
    (_ACTIVE_ROUTER_RE, _handle_active_router),
    (_STANDBY_ROUTER_RE, _handle_standby_router),
    (_PRIORITY_RE, _handle_priority),
    (_GROUP_NAME_RE, _handle_group_name),
)


def _parse_section_lines(
    interface: str,
    group: str,
    version: int | None,
    lines: list[str],
    interfaces: dict[str, HsrpInterfaceEntry],
) -> None:
    """Parse a single HSRP section into the nested result structure."""
    entry: HsrpGroupEntry = {
        "state": "",
        "hello_time": 0,
        "hold_time": 0,
        "preemption": False,
        "priority": 0,
    }
    if version is not None:
        entry["version"] = version

    for line in lines:
        for pattern, handler in _FIELD_HANDLERS:
            if match := pattern.match(line):
                handler(entry, match)
                break

    interface_entry = interfaces.setdefault(interface, HsrpInterfaceEntry(groups={}))
    interface_entry["groups"][group] = entry


def _split_sections(output: str) -> list[tuple[str, str, int | None, list[str]]]:
    """Split raw output into interface/group sections."""
    sections: list[tuple[str, str, int | None, list[str]]] = []
    current_interface: str | None = None
    current_group: str | None = None
    current_version: int | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        header_match = _SECTION_HEADER_RE.match(line)
        if header_match:
            if current_interface is not None and current_group is not None:
                sections.append(
                    (current_interface, current_group, current_version, current_lines)
                )
            current_interface = canonical_interface_name(
                header_match.group("interface"), os=OS.CISCO_IOSXE
            )
            current_group = header_match.group("group")
            version = header_match.group("version")
            current_version = int(version) if version is not None else None
            current_lines = []
            continue

        if current_interface is not None:
            current_lines.append(line)

    if current_interface is not None and current_group is not None:
        sections.append(
            (current_interface, current_group, current_version, current_lines)
        )

    return sections


@register(OS.CISCO_IOSXE, "show standby all")
class ShowStandbyAllParser(BaseParser[ShowStandbyAllResult]):
    """Parser for 'show standby all' command.

    Example output:
        Port-channel1 - Group 0 (version 2)
          State is Active
          Virtual IP address is 192.168.1.254
          Priority 100 (default 100)
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.FHRP})

    @classmethod
    def parse(cls, output: str) -> ShowStandbyAllResult:
        """Parse 'show standby all' output.

        Args:
            output: Raw CLI output from 'show standby all' command.

        Returns:
            Parsed HSRP data keyed by interface, then group.

        Raises:
            ValueError: If no HSRP groups are found in the output.
        """
        sections = _split_sections(output)
        if not sections:
            msg = "No HSRP groups found in output"
            raise ValueError(msg)

        interfaces: dict[str, HsrpInterfaceEntry] = {}
        for interface, group, version, lines in sections:
            _parse_section_lines(interface, group, version, lines, interfaces)

        return {"interfaces": interfaces}
