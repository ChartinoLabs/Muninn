"""Parser for 'show vrrp all' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class TrackObjectEntry(TypedDict):
    """Schema for a tracked object."""

    state: str
    decrement: int


class VrrpGroupEntry(TypedDict):
    """Schema for a single VRRP group entry."""

    state: str
    virtual_ip_address: str
    virtual_mac_address: str
    advertisement_interval_secs: float
    preemption: str
    priority: int
    configured_priority: NotRequired[int]
    master_router_ip: NotRequired[str]
    master_router_is_local: NotRequired[bool]
    master_router_priority: NotRequired[int]
    master_advertisement_interval_secs: NotRequired[float]
    master_down_interval_secs: NotRequired[float]
    master_down_expires_secs: NotRequired[float]
    master_advertisement_expires_msec: NotRequired[int]
    track_objects: NotRequired[dict[str, TrackObjectEntry]]
    address_family: NotRequired[str]
    description: NotRequired[str]
    flags: NotRequired[str]
    authentication: NotRequired[str]
    state_duration_secs: NotRequired[float]


class ShowVrrpAllResult(TypedDict):
    """Schema for 'show vrrp all' parsed output."""

    interfaces: dict[str, dict[str, VrrpGroupEntry]]


# Header line: "GigabitEthernet3.420 - Group 10" or with address family
_HEADER_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+-\s+Group\s+(?P<group>\d+)"
    r"(?:\s+-\s+Address-Family\s+(?P<af>\S+))?",
)

_STATE_PATTERN = re.compile(
    r"^State\s+is\s+(?P<state>\S+)",
)

_VIRTUAL_IP_PATTERN = re.compile(
    r"^Virtual\s+IP\s+address\s+is\s+(?P<ip>.+)$",
)

_VIRTUAL_MAC_PATTERN = re.compile(
    r"^Virtual\s+MAC\s+address\s+is\s+(?P<mac>\S+)",
)

_ADV_INTERVAL_PATTERN = re.compile(
    r"^Advertisement\s+interval\s+is\s+(?P<value>[\d.]+)\s+(?P<unit>sec|msec)",
)

_PREEMPTION_PATTERN = re.compile(
    r"^Preemption\s+(?P<preemption>\S+)",
)

_PRIORITY_PATTERN = re.compile(
    r"^Priority\s+is\s+(?P<priority>\d+)"
    r"(?:\s+\(cfgd\s+(?P<configured>\d+)\))?",
)

_TRACK_PATTERN = re.compile(
    r"^Track\s+object\s+(?P<id>\d+)\s+state\s+(?P<state>\S+)"
    r"\s+decrement\s+(?P<dec>\d+)",
)

_MASTER_ROUTER_PATTERN = re.compile(
    r"^Master\s+Router\s+is\s+(?P<ip>\S+?)(?:\s+\((?P<local>local)\))?"
    r",\s+priority\s+is\s+(?P<priority>\S+)",
)

_MASTER_ADV_PATTERN = re.compile(
    r"^Master\s+Advertisement\s+interval\s+is\s+"
    r"(?P<value>[\d.]+)\s+(?P<unit>sec|msec)"
    r"(?:\s+\(expires\s+in\s+(?P<expires>[\d.]+)\s+(?P<exp_unit>sec|msec)\))?",
)

_MASTER_DOWN_PATTERN = re.compile(
    r"^Master\s+Down\s+interval\s+is\s+(?P<value>[\d.]+)\s+(?P<unit>sec|msec)"
    r"(?:\s+\(expires\s+in\s+(?P<expires>[\d.]+)\s+(?P<exp_unit>sec|msec)\))?",
)

_FLAGS_PATTERN = re.compile(r"^FLAGS:\s+(?P<flags>\S+)")

_AUTH_PATTERN = re.compile(r"^Authentication\s+(?P<auth>.+)$")

_DESCRIPTION_PATTERN = re.compile(r'^Description\s+is\s+"(?P<desc>[^"]+)"')

_STATE_DURATION_PATTERN = re.compile(
    r"^State\s+duration\s+"
    r"(?:(?P<mins>\d+)\s+mins?\s+)?"
    r"(?P<secs>[\d.]+)\s+secs?",
)


_FIELD_PARSERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_STATE_PATTERN, "state"),
    (_VIRTUAL_IP_PATTERN, "virtual_ip"),
    (_VIRTUAL_MAC_PATTERN, "virtual_mac"),
    (_ADV_INTERVAL_PATTERN, "adv_interval"),
    (_PREEMPTION_PATTERN, "preemption"),
    (_PRIORITY_PATTERN, "priority"),
    (_TRACK_PATTERN, "track"),
    (_MASTER_ROUTER_PATTERN, "master_router"),
    (_MASTER_ADV_PATTERN, "master_adv"),
    (_MASTER_DOWN_PATTERN, "master_down"),
    (_FLAGS_PATTERN, "flags"),
    (_AUTH_PATTERN, "auth"),
    (_DESCRIPTION_PATTERN, "description"),
    (_STATE_DURATION_PATTERN, "state_duration"),
)


def _interval_to_secs(value: str, unit: str) -> float:
    """Convert an interval value and unit to seconds."""
    num = float(value)
    if unit == "msec":
        return num / 1000.0
    return num


def _apply_state(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply state match."""
    entry["state"] = match.group("state")


def _apply_virtual_ip(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply virtual IP match."""
    entry["virtual_ip_address"] = match.group("ip").strip()


def _apply_virtual_mac(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply virtual MAC match."""
    entry["virtual_mac_address"] = match.group("mac")


def _apply_adv_interval(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply advertisement interval match."""
    entry["advertisement_interval_secs"] = _interval_to_secs(
        match.group("value"), match.group("unit")
    )


def _apply_preemption(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply preemption match."""
    entry["preemption"] = match.group("preemption")


def _apply_flags(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply flags match."""
    entry["flags"] = match.group("flags")


def _apply_auth(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply authentication match."""
    entry["authentication"] = match.group("auth").strip()


def _apply_description(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply description match."""
    entry["description"] = match.group("desc")


def _apply_priority(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply priority match to entry."""
    entry["priority"] = int(match.group("priority"))
    configured = match.group("configured")
    if configured:
        entry["configured_priority"] = int(configured)


def _apply_track(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply track object match to entry."""
    track_id = match.group("id")
    track_entry: TrackObjectEntry = {
        "state": match.group("state"),
        "decrement": int(match.group("dec")),
    }
    if "track_objects" not in entry:
        entry["track_objects"] = {}
    entry["track_objects"][track_id] = track_entry


def _apply_master_router(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply master router match to entry."""
    ip = match.group("ip")
    if ip != "unknown":
        entry["master_router_ip"] = ip
    if match.group("local"):
        entry["master_router_is_local"] = True
    priority = match.group("priority")
    if priority != "unknown":
        entry["master_router_priority"] = int(priority)


def _apply_master_adv(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply master advertisement interval match to entry."""
    entry["master_advertisement_interval_secs"] = _interval_to_secs(
        match.group("value"), match.group("unit")
    )
    expires = match.group("expires")
    if expires:
        exp_unit = match.group("exp_unit")
        ms = int(float(expires) * (1 if exp_unit == "msec" else 1000))
        entry["master_advertisement_expires_msec"] = ms


def _apply_master_down(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply master down interval match to entry."""
    entry["master_down_interval_secs"] = _interval_to_secs(
        match.group("value"), match.group("unit")
    )
    expires = match.group("expires")
    if expires:
        entry["master_down_expires_secs"] = float(expires)


def _apply_state_duration(entry: VrrpGroupEntry, match: re.Match[str]) -> None:
    """Apply state duration match to entry."""
    mins = int(match.group("mins")) if match.group("mins") else 0
    secs = float(match.group("secs"))
    entry["state_duration_secs"] = mins * 60.0 + secs


_FieldApplier = type(_apply_state)

_FIELD_DISPATCH: dict[str, _FieldApplier] = {
    "state": _apply_state,
    "virtual_ip": _apply_virtual_ip,
    "virtual_mac": _apply_virtual_mac,
    "adv_interval": _apply_adv_interval,
    "preemption": _apply_preemption,
    "priority": _apply_priority,
    "track": _apply_track,
    "master_router": _apply_master_router,
    "master_adv": _apply_master_adv,
    "master_down": _apply_master_down,
    "flags": _apply_flags,
    "auth": _apply_auth,
    "description": _apply_description,
    "state_duration": _apply_state_duration,
}


@register(OS.CISCO_IOSXE, "show vrrp all")
class ShowVrrpAllParser(BaseParser[ShowVrrpAllResult]):
    """Parser for 'show vrrp all' command.

    Example output:
        GigabitEthernet3.420 - Group 10
          State is Master
          Virtual IP address is 10.13.120.254
          Virtual MAC address is 0000.5eff.010a
          Advertisement interval is 1.000 sec
    """

    @classmethod
    def parse(cls, output: str) -> ShowVrrpAllResult:
        """Parse 'show vrrp all' output.

        Args:
            output: Raw CLI output from 'show vrrp all' command.

        Returns:
            Parsed VRRP data keyed by interface and group number.

        Raises:
            ValueError: If no VRRP entries found in output.
        """
        interfaces: dict[str, dict[str, VrrpGroupEntry]] = {}
        current_entry: VrrpGroupEntry | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            header_match = _HEADER_PATTERN.match(stripped)
            if header_match:
                current_entry = _start_new_entry(interfaces, header_match)
                continue

            if current_entry is None:
                continue

            _parse_field_line(stripped, current_entry)

        if not interfaces:
            msg = "No VRRP entries found in output"
            raise ValueError(msg)

        return ShowVrrpAllResult(interfaces=interfaces)


def _start_new_entry(
    interfaces: dict[str, dict[str, VrrpGroupEntry]],
    match: re.Match[str],
) -> VrrpGroupEntry:
    """Create a new VRRP group entry from a header match."""
    raw_intf = match.group("interface")
    interface = canonical_interface_name(raw_intf, os=OS.CISCO_IOSXE)
    group = match.group("group")
    af = match.group("af")

    entry = VrrpGroupEntry(
        state="",
        virtual_ip_address="",
        virtual_mac_address="",
        advertisement_interval_secs=0.0,
        preemption="",
        priority=0,
    )

    if af:
        entry["address_family"] = af

    if interface not in interfaces:
        interfaces[interface] = {}
    interfaces[interface][group] = entry
    return entry


def _parse_field_line(line: str, entry: VrrpGroupEntry) -> None:
    """Parse a single field line and apply it to the entry."""
    for pattern, field in _FIELD_PARSERS:
        match = pattern.match(line)
        if match:
            _FIELD_DISPATCH[field](entry, match)
            return
