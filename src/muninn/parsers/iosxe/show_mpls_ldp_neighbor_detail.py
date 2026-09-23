"""Parser for 'show mpls ldp neighbor detail' command on Cisco IOS-XE."""

import re
from collections.abc import Callable
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.iosxe.show_mpls_ldp_neighbor import (
    _ADDRESSES_HEADER,
    _DISCOVERY_HEADER,
    _PEER_RE,
    _TCP_RE,
    LdpInterfaceDiscovery,
    LdpTargetedDiscovery,
    LdpTcpConnection,
    _apply_section_line,
    _tcp_connection,
)
from muninn.registry import register
from muninn.tags import ParserTag


class LdpPassword(TypedDict):
    """MD5 password status for an LDP session."""

    required: bool
    source: NotRequired[str]
    status: str


class LdpInterfaceDetailDiscovery(LdpInterfaceDiscovery):
    """Link hello discovery source on an interface, with hello timers."""

    holdtime_ms: NotRequired[int]
    hello_interval_ms: NotRequired[int]


class LdpTargetedDetailDiscovery(LdpTargetedDiscovery):
    """Targeted hello discovery source, with hello timers."""

    holdtime_ms: NotRequired[int]
    holdtime_infinite: NotRequired[bool]
    hello_interval_ms: NotRequired[int]


class LdpDetailDiscoverySources(TypedDict):
    """LDP discovery sources for a neighbor, with hello timers."""

    interfaces: NotRequired[dict[str, LdpInterfaceDetailDiscovery]]
    targeted: NotRequired[dict[str, LdpTargetedDetailDiscovery]]


class LdpSessionProtection(TypedDict):
    """LDP session protection status."""

    enabled: bool
    state: str
    duration_seconds: NotRequired[int]


class LdpNeighborDetailEntry(TypedDict):
    """Schema for a single LDP neighbor session (detail)."""

    local_ldp_id: str
    tcp_connection: NotRequired[LdpTcpConnection]
    password: NotRequired[LdpPassword]
    state: NotRequired[str]
    messages_sent: NotRequired[int]
    messages_received: NotRequired[int]
    advertisement_mode: NotRequired[str]
    last_tib_revision_sent: NotRequired[int]
    up_time: NotRequired[str]
    uid: NotRequired[int]
    peer_id: NotRequired[int]
    discovery_sources: NotRequired[LdpDetailDiscoverySources]
    bound_addresses: NotRequired[list[str]]
    peer_holdtime_ms: NotRequired[int]
    keepalive_interval_ms: NotRequired[int]
    peer_state: NotRequired[str]
    clients: NotRequired[list[str]]
    session_protection: NotRequired[LdpSessionProtection]
    nsr_state: NotRequired[str]
    capabilities_sent: NotRequired[list[str]]
    capabilities_received: NotRequired[list[str]]


ShowMplsLdpNeighborDetailResult = dict[str, LdpNeighborDetailEntry]


# Password: not required, none, in use
_PASSWORD_RE = re.compile(
    r"^Password:\s+(?P<required>(?:not )?required),\s+"
    r"(?P<source>[^,]+),\s+(?P<status>.+)$"
)

# State: Oper; Msgs sent/rcvd: 9981/10004; Downstream; Last TIB rev sent 4103
_STATE_RE = re.compile(
    r"^State:\s+(?P<state>[^;]+);\s+"
    r"Msgs sent/rcvd:\s+(?P<sent>\d+)/(?P<rcvd>\d+);\s+"
    r"(?P<mode>[^;]+)"
    r"(?:;\s+Last TIB rev sent\s+(?P<tib>\d+))?$"
)

# Up time: 3d21h; UID: 4; Peer Id 0
_UP_TIME_RE = re.compile(
    r"^Up time:\s+(?P<up_time>[^;\s]+)"
    r"(?:;\s+UID:\s+(?P<uid>\d+))?"
    r"(?:;\s+Peer Id\s+(?P<peer_id>\d+))?$"
)

# Peer holdtime: 180000 ms; KA interval: 60000 ms; Peer state: estab
_PEER_HOLDTIME_RE = re.compile(
    r"^Peer holdtime:\s+(?P<holdtime>\d+) ms;\s+"
    r"KA interval:\s+(?P<ka>\d+) ms;\s+"
    r"Peer state:\s+(?P<peer_state>\S+)$"
)

# Clients: Dir Adj Client
_CLIENTS_RE = re.compile(r"^Clients:\s+(?P<clients>.+)$")

# LDP Session Protection enabled, state: Ready
_SESSION_PROT_RE = re.compile(
    r"^LDP Session Protection (?P<enabled>enabled|disabled),\s+"
    r"state:\s+(?P<state>.+)$"
)

# duration: 86400 seconds
_DURATION_RE = re.compile(r"^duration:\s+(?P<duration>\d+) seconds$")

# NSR: Not Ready
_NSR_RE = re.compile(r"^NSR:\s+(?P<nsr>.+)$")

# holdtime: 15000 ms, hello interval: 5000 ms
# holdtime: infinite, hello interval: 10000 ms
_HELLO_TIMERS_RE = re.compile(
    r"^holdtime:\s+(?:(?P<holdtime>\d+) ms|(?P<infinite>infinite)),\s+"
    r"hello interval:\s+(?P<interval>\d+) ms$"
)

# [ICCP (type 0x0405) MajVer 1 MinVer 0]
_CAPABILITY_RE = re.compile(r"^\[(?P<capability>[^\]]+)\]$")

_CAPS_SENT = "Capabilities Sent:"
_CAPS_RECEIVED = "Capabilities Received:"
_SECTION_FIELDS = {
    _CAPS_SENT: "capabilities_sent",
    _CAPS_RECEIVED: "capabilities_received",
}
_NO_CAPABILITIES = "None"


def _on_tcp(entry: dict, match: re.Match[str]) -> None:
    entry["tcp_connection"] = _tcp_connection(match)


def _on_password(entry: dict, match: re.Match[str]) -> None:
    password: dict = {
        "required": match.group("required") == "required",
        "status": match.group("status"),
    }
    if match.group("source") != "none":
        password["source"] = match.group("source")
    entry["password"] = password


def _on_state(entry: dict, match: re.Match[str]) -> None:
    entry["state"] = match.group("state")
    entry["messages_sent"] = int(match.group("sent"))
    entry["messages_received"] = int(match.group("rcvd"))
    entry["advertisement_mode"] = match.group("mode")
    if match.group("tib"):
        entry["last_tib_revision_sent"] = int(match.group("tib"))


def _on_up_time(entry: dict, match: re.Match[str]) -> None:
    entry["up_time"] = match.group("up_time")
    if match.group("uid"):
        entry["uid"] = int(match.group("uid"))
    if match.group("peer_id"):
        entry["peer_id"] = int(match.group("peer_id"))


def _on_peer_holdtime(entry: dict, match: re.Match[str]) -> None:
    entry["peer_holdtime_ms"] = int(match.group("holdtime"))
    entry["keepalive_interval_ms"] = int(match.group("ka"))
    entry["peer_state"] = match.group("peer_state")


def _on_clients(entry: dict, match: re.Match[str]) -> None:
    entry["clients"] = [c.strip() for c in match.group("clients").split(",")]


def _on_session_protection(entry: dict, match: re.Match[str]) -> None:
    entry["session_protection"] = LdpSessionProtection(
        enabled=match.group("enabled") == "enabled",
        state=match.group("state"),
    )


def _on_nsr(entry: dict, match: re.Match[str]) -> None:
    entry["nsr_state"] = match.group("nsr")


# Top-level session lines; each ends any open sub-section.
_SESSION_HANDLERS: tuple[
    tuple[re.Pattern[str], Callable[[dict, re.Match[str]], None]], ...
] = (
    (_TCP_RE, _on_tcp),
    (_PASSWORD_RE, _on_password),
    (_STATE_RE, _on_state),
    (_UP_TIME_RE, _on_up_time),
    (_PEER_HOLDTIME_RE, _on_peer_holdtime),
    (_CLIENTS_RE, _on_clients),
    (_SESSION_PROT_RE, _on_session_protection),
    (_NSR_RE, _on_nsr),
)


class _Block:
    """Parsing state for one peer block."""

    def __init__(self, entry: dict) -> None:
        self.entry = entry
        self.section: str | None = None
        # Most recent hello source or session-protection dict, for the
        # indented timer line that follows it.
        self.last_timed: dict | None = None

    def feed(self, line: str) -> None:
        """Consume one stripped line belonging to this peer block."""
        if line in (_DISCOVERY_HEADER, _ADDRESSES_HEADER, _CAPS_SENT, _CAPS_RECEIVED):
            self.section = line
            return
        for pattern, handler in _SESSION_HANDLERS:
            if match := pattern.match(line):
                handler(self.entry, match)
                self.section = None
                self.last_timed = self.entry.get("session_protection")
                return
        self._feed_section(line)

    def _feed_section(self, line: str) -> None:
        if self.section in (_DISCOVERY_HEADER, _ADDRESSES_HEADER):
            source = _apply_section_line(self.entry, self.section, line)
            if source is not None:
                self.last_timed = source
            elif (match := _HELLO_TIMERS_RE.match(line)) and self.last_timed:
                self._apply_hello_timers(match)
        elif self.section in _SECTION_FIELDS:
            match = _CAPABILITY_RE.match(line)
            if match and match.group("capability") != _NO_CAPABILITIES:
                field = _SECTION_FIELDS[self.section]
                self.entry.setdefault(field, []).append(match.group("capability"))
        elif (match := _DURATION_RE.match(line)) and self.last_timed is not None:
            self.last_timed["duration_seconds"] = int(match.group("duration"))

    def _apply_hello_timers(self, match: re.Match[str]) -> None:
        timed = cast(dict, self.last_timed)
        if match.group("infinite"):
            timed["holdtime_infinite"] = True
        else:
            timed["holdtime_ms"] = int(match.group("holdtime"))
        timed["hello_interval_ms"] = int(match.group("interval"))


@register(OS.CISCO_IOSXE, "show mpls ldp neighbor detail")
@register(OS.CISCO_IOSXE, r"show mpls ldp neighbor vrf (?P<vrf>\S+) detail")
class ShowMplsLdpNeighborDetailParser(BaseParser["ShowMplsLdpNeighborDetailResult"]):
    """Parser for 'show mpls ldp neighbor detail' on IOS-XE.

    Parses each LDP session block into a dict keyed by peer LDP identifier.
    The schema is a superset of 'show mpls ldp neighbor'.
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
                block = _Block({"local_ldp_id": match.group("local")})
                result[match.group("peer")] = block.entry
            elif block is not None and line:
                block.feed(line)

        if not result:
            msg = "No LDP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowMplsLdpNeighborDetailResult, result)
