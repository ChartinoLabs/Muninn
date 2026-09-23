"""Parser for 'show hsrp detail' command on Cisco IOS-XR."""

import re
from collections.abc import Callable
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class HsrpStateChangeEntry(TypedDict):
    """Schema for one row of the state change history."""

    timestamp: str
    from_state: str
    to_state: str
    reason: str


class HsrpDetailGroupEntry(TypedDict):
    """Schema for a single HSRP group in detail output."""

    group: int
    address_family: str
    version: int
    state: str
    priority: NotRequired[int]
    preempt: NotRequired[bool]
    label: NotRequired[str]
    slave_count: NotRequired[int]
    slave_to: NotRequired[str]
    hello_time_msec: NotRequired[int]
    hold_time_msec: NotRequired[int]
    configured_hello_time_msec: NotRequired[int]
    configured_hold_time_msec: NotRequired[int]
    next_hello_sent_in_sec: NotRequired[float]
    minimum_delay_sec: NotRequired[int]
    reload_delay_sec: NotRequired[int]
    virtual_ip: NotRequired[str]
    virtual_ip_configured: NotRequired[bool]
    active_router: NotRequired[str]
    active_router_mac: NotRequired[str]
    active_router_priority: NotRequired[int]
    active_router_expires_in: NotRequired[str]
    standby_router: NotRequired[str]
    standby_router_mac: NotRequired[str]
    standby_router_priority: NotRequired[int]
    standby_router_expires_in: NotRequired[str]
    virtual_mac: NotRequired[str]
    virtual_mac_configured: NotRequired[bool]
    virtual_mac_state: NotRequired[str]
    authentication_type: NotRequired[str]
    authentication_string: NotRequired[str]
    state_changes: NotRequired[int]
    last_state_change: NotRequired[str]
    state_change_history: NotRequired[list[HsrpStateChangeEntry]]
    last_coup_sent: NotRequired[str]
    last_coup_received: NotRequired[str]
    last_resign_sent: NotRequired[str]
    last_resign_received: NotRequired[str]


class HsrpDetailInterfaceEntry(TypedDict):
    """Schema for HSRP groups under one interface, bucketed by address family."""

    ipv4_groups: NotRequired[dict[str, HsrpDetailGroupEntry]]
    ipv6_groups: NotRequired[dict[str, HsrpDetailGroupEntry]]


ShowHsrpDetailResult = dict[str, HsrpDetailInterfaceEntry]

# GigabitEthernet0/0/0/2 - IPv6 Group 1 (version 2)
_HEADER_RE = re.compile(
    r"^(?P<intf>\S+)\s+-\s+(?P<af>IPv4|IPv6)\s+Group\s+(?P<group>\d+)"
    r"\s+\(version\s+(?P<version>\d+)\)\s*$"
)
_LABEL_RE = re.compile(r"^Label\s+(?P<label>\S+)\s+\((?P<count>\d+)\s+slaves?\)$")
_SLAVE_TO_RE = re.compile(r"^Slave\s+to\s+(?P<label>\S+)$")
_LOCAL_STATE_RE = re.compile(
    r"^Local\s+state\s+is\s+(?P<state>\w+)"
    r"(?:,\s+priority\s+(?P<priority>\d+)(?P<preempt>,\s+may\s+preempt)?)?$"
)
_TIMERS_RE = re.compile(
    r"^(?P<configured>Configured\s+)?hellotime\s+(?P<hello>\d+)\s+msec"
    r"\s+holdtime\s+(?P<hold>\d+)\s+msec$",
    re.IGNORECASE,
)
_NEXT_HELLO_RE = re.compile(r"^Next\s+hello\s+sent\s+in\s+(?P<secs>\d+(?:\.\d+)?)$")
_DELAY_RE = re.compile(
    r"^Minimum\s+delay\s+(?P<minimum>\d+)\s+sec,\s+reload\s+delay\s+(?P<reload>\d+)"
    r"\s+sec$"
)
_VIRTUAL_IP_RE = re.compile(
    r"^Hot\s+standby\s+IP\s+address\s+is\s+(?P<ip>\S+)(?P<configured>\s+configured)?$"
)
# Active router is 10.1.1.2, priority 110 expires in 00:00:09
# Standby router is fe80::5000:1cff:feff:a0b, 5200.1cff.0a0b expires in 00:00:02
# Standby router is unknown expired
_ROUTER_RE = re.compile(
    r"^(?P<role>Active|Standby)\s+router\s+is\s+(?P<router>[^\s,]+)"
    rf"(?:,\s+(?P<mac>{MAC_ADDRESS}))?"
    r"(?:,\s+priority\s+(?P<priority>\d+))?"
    r"(?:\s+expires\s+in\s+(?P<expires>\S+)|\s+expired)?$"
)
_VIRTUAL_MAC_RE = re.compile(
    r"^Standby\s+virtual\s+mac\s+address\s+is\s+(?P<mac>\S+)"
    r"(?P<configured>\s+configured)?,\s+state\s+is\s+(?P<state>\S+)$"
)
_AUTH_RE = re.compile(
    r'^Authentication\s+(?P<type>\S+),\s+string\s+"(?P<string>[^"]*)"$'
)
_STATE_CHANGES_RE = re.compile(
    r"^(?P<count>\d+)\s+state\s+changes?,\s+last\s+state\s+change\s+(?P<last>\S+)$"
)
# Apr 15 00:12:19.913 WITA Init     -> Listen   Delay timer expired
_HISTORY_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\.\d+\s+\S+)"
    r"\s+(?P<from_state>\S+)\s+->\s+(?P<to_state>\S+)\s+(?P<reason>\S.*)$"
)
_COUP_RESIGN_RE = re.compile(
    r"^Last\s+(?P<kind>coup|resign)\s+(?P<direction>sent|received):\s+(?P<value>\S.*)$"
)


def _on_label(entry: dict, m: re.Match[str]) -> None:
    entry["label"] = m.group("label")
    entry["slave_count"] = int(m.group("count"))


def _on_slave_to(entry: dict, m: re.Match[str]) -> None:
    entry["slave_to"] = m.group("label")


def _on_local_state(entry: dict, m: re.Match[str]) -> None:
    entry["state"] = m.group("state")
    if m.group("priority"):
        entry["priority"] = int(m.group("priority"))
        entry["preempt"] = m.group("preempt") is not None


def _on_timers(entry: dict, m: re.Match[str]) -> None:
    prefix = "configured_" if m.group("configured") else ""
    entry[f"{prefix}hello_time_msec"] = int(m.group("hello"))
    entry[f"{prefix}hold_time_msec"] = int(m.group("hold"))


def _on_next_hello(entry: dict, m: re.Match[str]) -> None:
    entry["next_hello_sent_in_sec"] = float(m.group("secs"))


def _on_delay(entry: dict, m: re.Match[str]) -> None:
    entry["minimum_delay_sec"] = int(m.group("minimum"))
    entry["reload_delay_sec"] = int(m.group("reload"))


def _on_virtual_ip(entry: dict, m: re.Match[str]) -> None:
    entry["virtual_ip"] = m.group("ip")
    entry["virtual_ip_configured"] = m.group("configured") is not None


def _on_router(entry: dict, m: re.Match[str]) -> None:
    prefix = f"{m.group('role').lower()}_router"
    entry[prefix] = m.group("router")
    if m.group("mac"):
        entry[f"{prefix}_mac"] = m.group("mac")
    if m.group("priority"):
        entry[f"{prefix}_priority"] = int(m.group("priority"))
    if m.group("expires"):
        entry[f"{prefix}_expires_in"] = m.group("expires")


def _on_virtual_mac(entry: dict, m: re.Match[str]) -> None:
    entry["virtual_mac"] = m.group("mac")
    entry["virtual_mac_configured"] = m.group("configured") is not None
    entry["virtual_mac_state"] = m.group("state")


def _on_auth(entry: dict, m: re.Match[str]) -> None:
    entry["authentication_type"] = m.group("type")
    entry["authentication_string"] = m.group("string")


def _on_state_changes(entry: dict, m: re.Match[str]) -> None:
    entry["state_changes"] = int(m.group("count"))
    if m.group("last").lower() != "never":
        entry["last_state_change"] = m.group("last")


def _on_history(entry: dict, m: re.Match[str]) -> None:
    entry.setdefault("state_change_history", []).append(
        HsrpStateChangeEntry(
            timestamp=m.group("timestamp"),
            from_state=m.group("from_state"),
            to_state=m.group("to_state"),
            reason=m.group("reason"),
        )
    )


def _on_coup_resign(entry: dict, m: re.Match[str]) -> None:
    # "Never" means no such event; omit rather than store a sentinel.
    if m.group("value") != "Never":
        entry[f"last_{m.group('kind')}_{m.group('direction')}"] = m.group("value")


_LINE_HANDLERS: tuple[
    tuple[re.Pattern[str], Callable[[dict, re.Match[str]], None]], ...
] = (
    (_LOCAL_STATE_RE, _on_local_state),
    (_TIMERS_RE, _on_timers),
    (_NEXT_HELLO_RE, _on_next_hello),
    (_DELAY_RE, _on_delay),
    (_VIRTUAL_IP_RE, _on_virtual_ip),
    (_ROUTER_RE, _on_router),
    (_VIRTUAL_MAC_RE, _on_virtual_mac),
    (_AUTH_RE, _on_auth),
    (_STATE_CHANGES_RE, _on_state_changes),
    (_HISTORY_RE, _on_history),
    (_COUP_RESIGN_RE, _on_coup_resign),
    (_LABEL_RE, _on_label),
    (_SLAVE_TO_RE, _on_slave_to),
)


def _apply_line(entry: dict, line: str) -> None:
    """Dispatch a group body line to its handler; unknown lines are ignored."""
    for pattern, handler in _LINE_HANDLERS:
        m = pattern.match(line)
        if m:
            handler(entry, m)
            return


def _start_group(result: dict, m: re.Match[str]) -> dict:
    """Create a group entry under its interface / address-family bucket."""
    intf = canonical_interface_name(m.group("intf"), os=OS.CISCO_IOSXR)
    af = m.group("af").lower()
    entry: dict = {
        "group": int(m.group("group")),
        "address_family": af,
        "version": int(m.group("version")),
    }
    bucket = result.setdefault(intf, {}).setdefault(f"{af}_groups", {})
    bucket[m.group("group")] = entry
    return entry


def _validate(result: dict) -> None:
    """Require at least one group, and a local state on every group."""
    if not result:
        msg = "No HSRP groups found in output"
        raise ValueError(msg)
    for intf, buckets in result.items():
        for groups in buckets.values():
            for group, grp in groups.items():
                if "state" not in grp:
                    msg = f"Missing local state for {intf} group {group}"
                    raise ValueError(msg)


@register(OS.CISCO_IOSXR, "show hsrp detail")
class ShowHsrpDetailParser(BaseParser[ShowHsrpDetailResult]):
    """Parser for 'show hsrp detail' command on Cisco IOS-XR.

    Returns a dict keyed by canonical interface name, then ``ipv4_groups`` /
    ``ipv6_groups``, then group number (as string) — the same nesting as
    ``show hsrp``.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.FHRP})

    @classmethod
    def parse(cls, output: str) -> ShowHsrpDetailResult:
        """Parse 'show hsrp detail' output into structured data.

        Raises:
            ValueError: If no HSRP group is found, or a group lacks its state.
        """
        result: dict = {}
        entry: dict | None = None

        for raw in output.splitlines():
            line = raw.strip()
            header = _HEADER_RE.match(line)
            if header:
                entry = _start_group(result, header)
            elif entry is not None and line:
                _apply_line(entry, line)

        _validate(result)
        return cast(ShowHsrpDetailResult, result)
