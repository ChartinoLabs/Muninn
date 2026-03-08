"""Parser for 'show standby all' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Section header: "Interface - Group N (version V)" or "Interface - Group N"
_SECTION_HEADER_RE = re.compile(
    r"^(?P<interface>\S+)\s+-\s+Group\s+(?P<group>\d+)"
    r"(?:\s+\(version\s+(?P<version>\d+)\))?\s*$"
)

# Individual field patterns for lines within a section
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


class PreemptionDelay(TypedDict):
    """Schema for preemption delay values."""

    minimum: NotRequired[int]
    reload: NotRequired[int]
    sync: NotRequired[int]


class TrackObject(TypedDict):
    """Schema for a tracked object."""

    id: int
    state: str


class HsrpGroupDetail(TypedDict):
    """Schema for a single HSRP group detail entry."""

    interface: str
    group: int
    version: NotRequired[int]
    state: str
    state_changes: NotRequired[int]
    last_state_change: NotRequired[str]
    track_object: NotRequired[TrackObject]
    virtual_ip: NotRequired[str]
    active_virtual_mac: NotRequired[str]
    local_virtual_mac: NotRequired[str]
    hello_time: int
    hold_time: int
    authentication: NotRequired[str]
    auth_key_chain: NotRequired[str]
    preemption: bool
    preemption_delay: NotRequired[PreemptionDelay]
    active_router: NotRequired[str]
    standby_router: NotRequired[str]
    priority: int
    configured_priority: NotRequired[int]
    group_name: NotRequired[str]


class ShowStandbyAllResult(TypedDict):
    """Schema for 'show standby all' parsed output."""

    groups: list[HsrpGroupDetail]


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
    """Extract router IP or 'local' from active/standby router line value."""
    value = value.strip()
    if value.lower() in ("unknown", ""):
        return None
    # Extract IP before any comma (handles "192.168.1.2, priority 100 ...")
    return value.split(",")[0].strip()


def _handle_state(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle state and state-change lines."""
    entry["state"] = match.group("state")


def _handle_state_changes(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle state change count and last change timestamp."""
    entry["state_changes"] = int(match.group("count"))
    if match.group("last_change"):
        entry["last_state_change"] = match.group("last_change")


def _handle_track(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle tracked object line."""
    entry["track_object"] = {
        "id": int(match.group("id")),
        "state": match.group("state").strip("()"),
    }


def _handle_virtual_ip(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle virtual IP address line."""
    vip = match.group("ip")
    if vip.lower() != "unknown":
        entry["virtual_ip"] = vip


def _handle_active_mac(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle active virtual MAC address line."""
    mac = match.group("mac")
    if mac.lower() != "unknown":
        entry["active_virtual_mac"] = mac


def _handle_local_mac(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle local virtual MAC address line."""
    entry["local_virtual_mac"] = match.group("mac")


def _handle_hello(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle hello/hold timer line."""
    entry["hello_time"] = int(match.group("hello"))
    entry["hold_time"] = int(match.group("hold"))


def _handle_auth(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle authentication line."""
    entry["authentication"] = match.group("auth_type")
    if match.group("key_chain"):
        entry["auth_key_chain"] = match.group("key_chain")


def _handle_preemption(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle preemption line with optional delays."""
    entry["preemption"] = match.group("preempt") == "enabled"
    if match.group("delays"):
        delays = _parse_preemption_delays(match.group("delays"))
        if delays:
            entry["preemption_delay"] = delays


def _handle_active_router(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle active router line."""
    addr = _extract_router_address(match.group("active"))
    if addr is not None:
        entry["active_router"] = addr


def _handle_standby_router(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle standby router line."""
    addr = _extract_router_address(match.group("standby"))
    if addr is not None:
        entry["standby_router"] = addr


def _handle_priority(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle priority line."""
    entry["priority"] = int(match.group("priority"))
    if match.group("configured"):
        entry["configured_priority"] = int(match.group("configured"))


def _handle_group_name(entry: HsrpGroupDetail, match: re.Match[str]) -> None:
    """Handle group name line."""
    entry["group_name"] = match.group("name")


# Ordered list of (pattern, handler) tuples for section line matching
_FIELD_HANDLERS: tuple[
    tuple[re.Pattern[str], Callable[[HsrpGroupDetail, re.Match[str]], None]],
    ...,
] = (
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
    group: int,
    version: int | None,
    lines: list[str],
) -> HsrpGroupDetail:
    """Parse the detail lines of a single HSRP group section."""
    entry: HsrpGroupDetail = {
        "interface": interface,
        "group": group,
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

    return entry


def _split_sections(
    output: str,
) -> list[tuple[str, int, int | None, list[str]]]:
    """Split raw output into sections by HSRP group header lines.

    Returns a list of (interface, group, version, detail_lines) tuples.
    """
    sections: list[tuple[str, int, int | None, list[str]]] = []
    current_interface: str | None = None
    current_group: int | None = None
    current_version: int | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        header_match = _SECTION_HEADER_RE.match(line)
        if header_match:
            if current_interface is not None and current_group is not None:
                sections.append(
                    (current_interface, current_group, current_version, current_lines)
                )
            raw_intf = header_match.group("interface")
            current_interface = canonical_interface_name(raw_intf, os=OS.CISCO_IOSXE)
            current_group = int(header_match.group("group"))
            version_str = header_match.group("version")
            current_version = int(version_str) if version_str is not None else None
            current_lines = []
        elif current_interface is not None:
            current_lines.append(line)

    # Flush last section
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
            8 state changes, last state change 1w0d
          Virtual IP address is 192.168.1.254
          Priority 100 (default 100)
    """

    @classmethod
    def parse(cls, output: str) -> ShowStandbyAllResult:
        """Parse 'show standby all' output.

        Args:
            output: Raw CLI output from 'show standby all' command.

        Returns:
            Parsed HSRP group details.

        Raises:
            ValueError: If no HSRP groups are found in the output.
        """
        sections = _split_sections(output)
        groups = [
            _parse_section_lines(intf, grp, ver, lines)
            for intf, grp, ver, lines in sections
        ]

        if not groups:
            msg = "No HSRP groups found in output"
            raise ValueError(msg)

        return {"groups": groups}
