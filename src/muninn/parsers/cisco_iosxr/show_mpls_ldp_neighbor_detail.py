"""Parser for 'show mpls ldp neighbor detail' command on Cisco IOS-XR."""

import re
from collections.abc import Callable
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class LdpTcpConnection(TypedDict):
    """TCP transport connection for an LDP session."""

    peer_address: str
    peer_port: int
    local_address: str
    local_port: int


class LdpAddressFamilyCounts(TypedDict):
    """Per address-family counts, as in 'show mpls ldp neighbor brief'."""

    ipv4: int
    ipv6: int


class LdpTargetedDiscovery(TypedDict):
    """Targeted hello discovery source, keyed by target address."""

    local_address: str
    active: bool
    passive: bool


class LdpDiscoverySources(TypedDict):
    """LDP discovery sources for one address family."""

    interfaces: NotRequired[list[str]]
    targeted: NotRequired[dict[str, LdpTargetedDiscovery]]


class LdpSessionProtection(TypedDict):
    """LDP session protection status."""

    enabled: bool
    state: str
    duration_seconds: NotRequired[int]


class LdpNeighborDetailEntry(TypedDict):
    """Schema for a single LDP neighbor session (detail)."""

    tcp_connection: NotRequired[LdpTcpConnection]
    graceful_restart: NotRequired[bool]
    reconnect_timeout_seconds: NotRequired[int]
    recovery_time_seconds: NotRequired[int]
    session_holdtime_seconds: NotRequired[int]
    state: NotRequired[str]
    messages_sent: NotRequired[int]
    messages_received: NotRequired[int]
    advertisement_mode: NotRequired[str]
    up_time: NotRequired[str]
    discovery: NotRequired[LdpAddressFamilyCounts]
    discovery_sources: NotRequired[dict[str, LdpDiscoverySources]]
    addresses: NotRequired[LdpAddressFamilyCounts]
    bound_addresses: NotRequired[dict[str, list[str]]]
    peer_holdtime_seconds: NotRequired[int]
    keepalive_interval_seconds: NotRequired[int]
    peer_state: NotRequired[str]
    nsr_state: NotRequired[str]
    clients: NotRequired[list[str]]
    session_protection: NotRequired[LdpSessionProtection]
    capabilities_sent: NotRequired[dict[str, str]]
    capabilities_received: NotRequired[dict[str, str]]


ShowMplsLdpNeighborDetailResult = dict[str, LdpNeighborDetailEntry]


# Peer LDP Identifier: 192.168.70.6:0
_PEER_RE = re.compile(r"^Peer LDP Identifier:\s+(?P<peer>\S+:\d+)$")

# TCP connection: 192.168.70.6:15332 - 192.168.1.1:646
_TCP_RE = re.compile(
    rf"^TCP connection:\s+(?P<peer_addr>{IPV4_ADDRESS}):(?P<peer_port>\d+)"
    rf"\s+-\s+(?P<local_addr>{IPV4_ADDRESS}):(?P<local_port>\d+)$"
)

# Graceful Restart: Yes (Reconnect Timeout: 120 sec, Recovery: 180 sec)
# Graceful Restart: No
_GR_RE = re.compile(
    r"^Graceful Restart:\s+(?P<gr>Yes|No)"
    r"(?:\s+\(Reconnect Timeout:\s+(?P<reconnect>\d+) sec,\s+"
    r"Recovery:\s+(?P<recovery>\d+) sec\))?$"
)

# Session Holdtime: 180 sec
_SESSION_HOLDTIME_RE = re.compile(r"^Session Holdtime:\s+(?P<holdtime>\d+) sec$")

# State: Oper; Msgs sent/rcvd: 851/232; Downstream-Unsolicited
_STATE_RE = re.compile(
    r"^State:\s+(?P<state>[^;]+);\s+"
    r"Msgs sent/rcvd:\s+(?P<sent>\d+)/(?P<rcvd>\d+);\s+"
    r"(?P<mode>[^;]+)$"
)

# Up time: 00:02:44
_UP_TIME_RE = re.compile(r"^Up time:\s+(?P<up_time>\S+)$")

# Peer holdtime: 180 sec; KA interval: 60 sec; Peer state: Estab
_PEER_HOLDTIME_RE = re.compile(
    r"^Peer holdtime:\s+(?P<holdtime>\d+) sec;\s+"
    r"KA interval:\s+(?P<ka>\d+) sec;\s+"
    r"Peer state:\s+(?P<peer_state>\S+)$"
)

# NSR: Operational
_NSR_RE = re.compile(r"^NSR:\s+(?P<nsr>.+)$")

# Clients: Session Protection
_CLIENTS_RE = re.compile(r"^Clients:\s+(?P<clients>.+)$")

# IPv4: (2)
_AF_RE = re.compile(r"^(?P<af>IPv4|IPv6):\s+\((?P<count>\d+)\)$")

# Targeted Hello (192.168.1.1 -> 192.168.70.6, active/passive)
_TARGETED_RE = re.compile(
    rf"^Targeted Hello\s+\((?P<local>{IPV4_ADDRESS})\s+->\s+"
    rf"(?P<target>{IPV4_ADDRESS}),\s+(?P<flags>[^)]+)\)$"
)

# Enabled, state: Ready
_SESSION_PROT_RE = re.compile(
    r"^(?P<enabled>Enabled|Disabled),\s+state:\s+(?P<state>.+)$"
)

# Duration: 86400 sec
_DURATION_RE = re.compile(r"^Duration:\s+(?P<duration>\d+) sec$")

# 0x508  (MP: Point-to-Multipoint (P2MP))
_CAPABILITY_RE = re.compile(r"^(?P<code>0x[0-9a-fA-F]+)\s+\((?P<desc>.+)\)$")

_DISCOVERY = "LDP Discovery Sources:"
_ADDRESSES = "Addresses bound to this peer:"
_SESSION_PROT = "Session Protection:"
_CAPABILITIES = "Capabilities:"
_CAPS_SENT = "Sent:"
_CAPS_RECEIVED = "Received:"
_SECTIONS = (_DISCOVERY, _ADDRESSES, _SESSION_PROT, _CAPABILITIES)
_CAPS_FIELDS = {
    _CAPS_SENT: "capabilities_sent",
    _CAPS_RECEIVED: "capabilities_received",
}
_COUNT_FIELDS = {_DISCOVERY: "discovery", _ADDRESSES: "addresses"}


def _on_tcp(entry: dict, match: re.Match[str]) -> None:
    entry["tcp_connection"] = LdpTcpConnection(
        peer_address=match.group("peer_addr"),
        peer_port=int(match.group("peer_port")),
        local_address=match.group("local_addr"),
        local_port=int(match.group("local_port")),
    )


def _on_gr(entry: dict, match: re.Match[str]) -> None:
    entry["graceful_restart"] = match.group("gr") == "Yes"
    if match.group("reconnect"):
        entry["reconnect_timeout_seconds"] = int(match.group("reconnect"))
        entry["recovery_time_seconds"] = int(match.group("recovery"))


def _on_session_holdtime(entry: dict, match: re.Match[str]) -> None:
    entry["session_holdtime_seconds"] = int(match.group("holdtime"))


def _on_state(entry: dict, match: re.Match[str]) -> None:
    entry["state"] = match.group("state")
    entry["messages_sent"] = int(match.group("sent"))
    entry["messages_received"] = int(match.group("rcvd"))
    entry["advertisement_mode"] = match.group("mode")


def _on_up_time(entry: dict, match: re.Match[str]) -> None:
    entry["up_time"] = match.group("up_time")


def _on_peer_holdtime(entry: dict, match: re.Match[str]) -> None:
    entry["peer_holdtime_seconds"] = int(match.group("holdtime"))
    entry["keepalive_interval_seconds"] = int(match.group("ka"))
    entry["peer_state"] = match.group("peer_state")


def _on_nsr(entry: dict, match: re.Match[str]) -> None:
    entry["nsr_state"] = match.group("nsr")


def _on_clients(entry: dict, match: re.Match[str]) -> None:
    entry["clients"] = [c.strip() for c in match.group("clients").split(",")]


# Top-level session lines; each ends any open sub-section.
_SESSION_HANDLERS: tuple[
    tuple[re.Pattern[str], Callable[[dict, re.Match[str]], None]], ...
] = (
    (_TCP_RE, _on_tcp),
    (_GR_RE, _on_gr),
    (_SESSION_HOLDTIME_RE, _on_session_holdtime),
    (_STATE_RE, _on_state),
    (_UP_TIME_RE, _on_up_time),
    (_PEER_HOLDTIME_RE, _on_peer_holdtime),
    (_NSR_RE, _on_nsr),
    (_CLIENTS_RE, _on_clients),
)


class _Block:
    """Parsing state for one peer block."""

    def __init__(self) -> None:
        self.entry: dict = {}
        self.section: str | None = None
        # Address family (``ipv4``/``ipv6``) or capabilities direction field.
        self.sub: str | None = None

    def feed(self, line: str) -> None:
        """Consume one stripped line belonging to this peer block."""
        if line in _SECTIONS:
            self.section, self.sub = line, None
            return
        for pattern, handler in _SESSION_HANDLERS:
            if match := pattern.match(line):
                handler(self.entry, match)
                self.section = None
                return
        if self.section in _COUNT_FIELDS:
            self._feed_af_section(line)
        elif self.section == _CAPABILITIES:
            self._feed_capability(line)
        elif self.section == _SESSION_PROT:
            self._feed_session_protection(line)

    def _feed_af_section(self, line: str) -> None:
        section = cast(str, self.section)
        if match := _AF_RE.match(line):
            self.sub = match.group("af").lower()
            counts = self.entry.setdefault(_COUNT_FIELDS[section], {})
            counts[self.sub] = int(match.group("count"))
        elif self.sub is None:
            return
        elif section == _ADDRESSES:
            addresses = self.entry.setdefault("bound_addresses", {})
            addresses.setdefault(self.sub, []).extend(line.split())
        else:
            self._feed_discovery_source(line)

    def _feed_discovery_source(self, line: str) -> None:
        sources = self.entry.setdefault("discovery_sources", {})
        af_sources = sources.setdefault(self.sub, {})
        if match := _TARGETED_RE.match(line):
            flags = set(match.group("flags").split("/"))
            af_sources.setdefault("targeted", {})[match.group("target")] = {
                "local_address": match.group("local"),
                "active": "active" in flags,
                "passive": "passive" in flags,
            }
        elif " " not in line:
            # Only a bare interface name; unseen source formats are skipped.
            intf = canonical_interface_name(line, os=OS.CISCO_IOSXR)
            af_sources.setdefault("interfaces", []).append(intf)

    def _feed_capability(self, line: str) -> None:
        if line in _CAPS_FIELDS:
            self.sub = _CAPS_FIELDS[line]
        elif self.sub and (match := _CAPABILITY_RE.match(line)):
            caps = self.entry.setdefault(self.sub, {})
            caps[match.group("code")] = match.group("desc")

    def _feed_session_protection(self, line: str) -> None:
        if match := _SESSION_PROT_RE.match(line):
            self.entry["session_protection"] = {
                "enabled": match.group("enabled") == "Enabled",
                "state": match.group("state"),
            }
        elif (match := _DURATION_RE.match(line)) and (
            protection := self.entry.get("session_protection")
        ):
            protection["duration_seconds"] = int(match.group("duration"))


@register(OS.CISCO_IOSXR, "show mpls ldp neighbor detail")
@register(
    OS.CISCO_IOSXR,
    r"show mpls ldp neighbor (?P<interface>[A-Za-z][A-Za-z-]* ?\d\S*) detail",
    doc_template="show mpls ldp neighbor <interface> detail",
)
class ShowMplsLdpNeighborDetailParser(BaseParser["ShowMplsLdpNeighborDetailResult"]):
    """Parser for 'show mpls ldp neighbor [<interface>] detail' on IOS-XR.

    Parses each LDP session block into a dict keyed by peer LDP identifier,
    matching the keying of 'show mpls ldp neighbor brief'.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> "ShowMplsLdpNeighborDetailResult":
        """Parse 'show mpls ldp neighbor detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by peer LDP identifier with session details.

        Raises:
            ValueError: If no LDP neighbors found in output.
        """
        result: dict[str, dict] = {}
        block: _Block | None = None

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if match := _PEER_RE.match(line):
                block = _Block()
                result[match.group("peer")] = block.entry
            elif block is not None and line:
                block.feed(line)

        if not result:
            msg = "No LDP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowMplsLdpNeighborDetailResult, result)
