"""Parser for 'show bundle' command on Cisco IOS-XR."""

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


class LoadBalancingEntry(TypedDict):
    """Schema for the 'Load balancing' block of a bundle."""

    link_order_signaling: NotRequired[str]
    hash_type: NotRequired[str]
    locality_threshold: NotRequired[str]


class LacpEntry(TypedDict):
    """Schema for the 'LACP' block of a bundle.

    ``flap_suppression_timer_enabled`` is ``False`` when the timer is ``Off``,
    in which case ``flap_suppression_timer_ms`` is omitted.
    """

    status: str
    flap_suppression_timer_enabled: NotRequired[bool]
    flap_suppression_timer_ms: NotRequired[int]
    cisco_extensions: NotRequired[bool]
    non_revertive: NotRequired[bool]


class MlacpEntry(TypedDict):
    """Schema for the 'mLACP' block of a bundle."""

    status: str
    iccp_group: NotRequired[int]
    role: NotRequired[str]
    foreign_links_active: NotRequired[int]
    foreign_links_configured: NotRequired[int]
    switchover_type: NotRequired[str]
    recovery_delay_seconds: NotRequired[int]
    maximize_threshold: NotRequired[str]


class BfdEntry(TypedDict):
    """Schema for the 'IPv4 BFD' / 'IPv6 BFD' block of a bundle."""

    status: str


class MemberEntry(TypedDict):
    """Schema for a bundle member port row."""

    state: str
    port_priority: str
    port_number: str
    bandwidth_kbps: int
    state_reason: NotRequired[str]


class BundleEntry(TypedDict):
    """Schema for a single bundle.

    ``wait_while_timer_enabled`` is ``False`` when the timer is ``Off``, in
    which case ``wait_while_timer_ms`` is omitted.
    ``members`` is keyed by device (``Local`` or the mLACP peer address),
    then by member interface, since the same interface name can appear on
    both the local device and the mLACP peer.
    """

    status: str
    local_links_active: int
    local_links_standby: int
    local_links_configured: int
    local_bandwidth_effective_kbps: NotRequired[int]
    local_bandwidth_available_kbps: NotRequired[int]
    mac_address: NotRequired[str]
    mac_address_source: NotRequired[str]
    inter_chassis_link: NotRequired[bool]
    minimum_active_links: NotRequired[int]
    minimum_active_bandwidth_kbps: NotRequired[int]
    maximum_active_links: NotRequired[int]
    wait_while_timer_enabled: NotRequired[bool]
    wait_while_timer_ms: NotRequired[int]
    load_balancing: NotRequired[LoadBalancingEntry]
    lacp: NotRequired[LacpEntry]
    mlacp: NotRequired[MlacpEntry]
    ipv4_bfd: NotRequired[BfdEntry]
    ipv6_bfd: NotRequired[BfdEntry]
    members: NotRequired[dict[str, dict[str, MemberEntry]]]


class ShowBundleResult(TypedDict):
    """Schema for 'show bundle' parsed output, keyed by bundle interface."""

    bundles: dict[str, BundleEntry]


# Bundle-Ether1
_BUNDLE_RE = re.compile(r"^(?P<name>Bundle-\S+)\s*$")

#   Status:                                    Up
#     Hash type:                               Default
_KV_RE = re.compile(r"^(?P<indent> +)(?P<label>[^:]+?):\s*(?P<value>.*?)\s*$")

#   Gi0/0/0/0             Local            Active       0x000a, 0x0001     1000000
_MEMBER_RE = re.compile(
    r"^\s+(?P<interface>\S+)\s+(?P<device>\S+)\s+(?P<state>\S+)\s+"
    r"(?P<priority>0x[0-9a-fA-F]+),\s*(?P<number>0x[0-9a-fA-F]+)\s+"
    r"(?P<bandwidth>\d+)\s*$"
)

#       Link is Active
_REASON_RE = re.compile(r"^\s+(?P<reason>\S.*?)\s*$")

_LINKS3_RE = re.compile(r"(\d+) / (\d+) / (\d+)")
_LINKS2_RE = re.compile(r"(\d+) / (\d+)")
_BANDWIDTH_RE = re.compile(r"(\d+) \((\d+)\) kbps")
_MIN_ACTIVE_RE = re.compile(r"(\d+) / (\d+) kbps")
_MAC_RE = re.compile(rf"(?P<mac>{MAC_ADDRESS}) \((?P<source>[^)]+)\)")
_MS_RE = re.compile(r"(\d+) ms")
_SECONDS_RE = re.compile(r"(\d+) s")
_INT_RE = re.compile(r"(\d+)")

_Fields = dict[str, object]


def _ints(pattern: re.Pattern[str], *keys: str) -> Callable[[str], _Fields]:
    """Build a handler mapping the integer groups of ``pattern`` to ``keys``."""

    def handler(value: str) -> _Fields:
        match = pattern.match(value)
        if not match:
            return {}
        return {
            key: int(group) for key, group in zip(keys, match.groups(), strict=True)
        }

    return handler


def _text(key: str) -> Callable[[str], _Fields]:
    """Build a handler storing the raw value under ``key``.

    Empty values and the ``None`` placeholder are omitted.
    """
    return lambda value: {key: value} if value and value != "None" else {}


_BOOLS = {"Yes": True, "No": False, "Enabled": True, "Disabled": False}


def _bool(key: str) -> Callable[[str], _Fields]:
    """Build a handler storing Yes/No or Enabled/Disabled as a bool."""
    return lambda value: {key: _BOOLS[value]} if value in _BOOLS else {}


def _timer(key: str) -> Callable[[str], _Fields]:
    """Build a handler for an 'Off' / '<n> ms' timer."""
    ms = _ints(_MS_RE, f"{key}_ms")

    def handler(value: str) -> _Fields:
        if value == "Off":
            return {f"{key}_enabled": False}
        fields = ms(value)
        return {f"{key}_enabled": True, **fields} if fields else {}

    return handler


def _mac(value: str) -> _Fields:
    """Split 'MAC address (source)' into address and source."""
    match = _MAC_RE.match(value)
    if not match:
        return {}
    return {"mac_address": match["mac"], "mac_address_source": match["source"]}


# Bundle-level labels (normalized: lowercase, hyphens as spaces).
_BUNDLE_FIELDS: dict[str, Callable[[str], _Fields]] = {
    "status": _text("status"),
    "local links <active/standby/configured>": _ints(
        _LINKS3_RE,
        "local_links_active",
        "local_links_standby",
        "local_links_configured",
    ),
    "local bandwidth <effective/available>": _ints(
        _BANDWIDTH_RE,
        "local_bandwidth_effective_kbps",
        "local_bandwidth_available_kbps",
    ),
    "mac address (source)": _mac,
    "inter chassis link": _bool("inter_chassis_link"),
    "minimum active links / bandwidth": _ints(
        _MIN_ACTIVE_RE, "minimum_active_links", "minimum_active_bandwidth_kbps"
    ),
    "maximum active links": _ints(_INT_RE, "maximum_active_links"),
    "wait while timer": _timer("wait_while_timer"),
}

# Bundle-level labels that open an indented block, mapped to the block key.
_SECTIONS: dict[str, str] = {
    "load balancing": "load_balancing",
    "lacp": "lacp",
    "mlacp": "mlacp",
    "ipv4 bfd": "ipv4_bfd",
    "ipv6 bfd": "ipv6_bfd",
}

# Labels inside an indented block.
_SECTION_FIELDS: dict[str, Callable[[str], _Fields]] = {
    "link order signaling": _text("link_order_signaling"),
    "hash type": _text("hash_type"),
    "locality threshold": _text("locality_threshold"),
    "flap suppression timer": _timer("flap_suppression_timer"),
    "cisco extensions": _bool("cisco_extensions"),
    "non revertive": _bool("non_revertive"),
    "iccp group": _ints(_INT_RE, "iccp_group"),
    "role": _text("role"),
    "foreign links <active/configured>": _ints(
        _LINKS2_RE, "foreign_links_active", "foreign_links_configured"
    ),
    "switchover type": _text("switchover_type"),
    "recovery delay": _ints(_SECONDS_RE, "recovery_delay_seconds"),
    "maximize threshold": _text("maximize_threshold"),
}

_REQUIRED = (
    "status",
    "local_links_active",
    "local_links_standby",
    "local_links_configured",
)


class _State:
    """Mutable parse state for the bundle currently being read."""

    def __init__(self, bundle: dict) -> None:
        self.bundle = bundle
        self.section: dict | None = None
        self.member: dict | None = None


def _handle_kv(state: _State, match: re.Match[str]) -> None:
    """Apply a 'Label: value' line to the current bundle or block."""
    label = match["label"].lower().replace("-", " ")
    value = match["value"]
    if len(match["indent"]) > 2 and state.section is not None:
        handler = _SECTION_FIELDS.get(label)
        if handler is not None:
            state.section.update(handler(value))
        return
    if label in _SECTIONS:
        state.section = state.bundle.setdefault(_SECTIONS[label], {})
        if label != "load balancing":
            state.section["status"] = value
        return
    state.section = None
    handler = _BUNDLE_FIELDS.get(label)
    if handler is not None:
        state.bundle.update(handler(value))


def _handle_member(state: _State, match: re.Match[str]) -> None:
    """Record a member port row."""
    interface = canonical_interface_name(match["interface"], os=OS.CISCO_IOSXR)
    device = state.bundle.setdefault("members", {}).setdefault(match["device"], {})
    state.member = device[interface] = {
        "state": match["state"],
        "port_priority": match["priority"],
        "port_number": match["number"],
        "bandwidth_kbps": int(match["bandwidth"]),
    }


def _handle_line(state: _State, line: str) -> None:
    """Dispatch one line within a bundle block."""
    member = _MEMBER_RE.match(line)
    if member:
        _handle_member(state, member)
        return
    if state.member is None:
        kv = _KV_RE.match(line)
        if kv:
            _handle_kv(state, kv)
        return
    reason = _REASON_RE.match(line)
    if reason:
        state.member["state_reason"] = reason["reason"]


def _validate(bundles: dict[str, dict]) -> None:
    """Raise ``ValueError`` if no bundle was parsed or one lacks required fields."""
    if not bundles:
        msg = "No bundles found in output"
        raise ValueError(msg)
    for name, bundle in bundles.items():
        missing = [key for key in _REQUIRED if key not in bundle]
        if missing:
            msg = f"Bundle {name} missing fields: {', '.join(missing)}"
            raise ValueError(msg)


@register(OS.CISCO_IOSXR, "show bundle")
@register(
    OS.CISCO_IOSXR,
    r"show bundle (?P<interface>bundle-ether ?\d+)",
    doc_template="show bundle <interface>",
)
class ShowBundleParser(BaseParser[ShowBundleResult]):
    """Parser for 'show bundle' command on Cisco IOS-XR."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.INTERFACES, ParserTag.LAG}
    )

    @classmethod
    def parse(cls, output: str) -> ShowBundleResult:
        """Parse 'show bundle' output.

        Args:
            output: Raw CLI output from 'show bundle'.

        Returns:
            Parsed bundles keyed by canonical bundle interface name.

        Raises:
            ValueError: If no bundle is found or a bundle lacks required fields.
        """
        bundles: dict[str, dict] = {}
        state: _State | None = None
        for line in output.splitlines():
            if not line.strip():
                continue
            header = _BUNDLE_RE.match(line)
            if header:
                name = canonical_interface_name(header["name"], os=OS.CISCO_IOSXR)
                state = _State(bundles.setdefault(name, {}))
            elif state is not None:
                _handle_line(state, line)

        _validate(bundles)
        return cast(ShowBundleResult, {"bundles": bundles})
