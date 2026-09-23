"""Parser for 'show mpls ldp neighbor' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, IPV4_ADDRESS_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class LdpTcpConnection(TypedDict):
    """TCP transport connection for an LDP session."""

    peer_address: str
    peer_port: int
    local_address: str
    local_port: int


class LdpInterfaceDiscovery(TypedDict):
    """Link hello discovery source on an interface."""

    source_address: str


class LdpDiscoverySources(TypedDict):
    """LDP discovery sources for a neighbor."""

    interfaces: NotRequired[dict[str, LdpInterfaceDiscovery]]


class LdpNeighborEntry(TypedDict):
    """Schema for a single LDP neighbor session."""

    local_ldp_id: str
    tcp_connection: NotRequired[LdpTcpConnection]
    state: NotRequired[str]
    messages_sent: NotRequired[int]
    messages_received: NotRequired[int]
    advertisement_mode: NotRequired[str]
    up_time: NotRequired[str]
    discovery_sources: NotRequired[LdpDiscoverySources]
    bound_addresses: NotRequired[list[str]]


ShowMplsLdpNeighborResult = dict[str, LdpNeighborEntry]


# Peer LDP Ident: 10.169.197.252:0; Local LDP Ident 10.169.197.254:0
_PEER_RE = re.compile(
    r"^Peer LDP Ident:\s+(?P<peer>\S+:\d+);\s+"
    r"Local LDP Ident:?\s+(?P<local>\S+:\d+)$"
)

# TCP connection: 10.169.197.252.646 - 10.169.197.254.20170
_TCP_RE = re.compile(
    rf"^TCP connection:\s+(?P<peer_addr>{IPV4_ADDRESS})\.(?P<peer_port>\d+)"
    rf"\s+-\s+(?P<local_addr>{IPV4_ADDRESS})\.(?P<local_port>\d+)$"
)

# State: Oper; Msgs sent/rcvd: 851/852; Downstream
_STATE_RE = re.compile(
    r"^State:\s+(?P<state>[^;]+);\s+"
    r"Msgs sent/rcvd:\s+(?P<sent>\d+)/(?P<rcvd>\d+);\s+"
    r"(?P<mode>[^;]+)$"
)

# Up time: 04:50:30
_UP_TIME_RE = re.compile(r"^Up time:\s+(?P<up_time>\S+)$")

# GigabitEthernet0/0/0, Src IP addr: 10.169.197.93
_INTF_SOURCE_RE = re.compile(
    rf"^(?P<intf>\S+)[,;]\s+Src IP addr:\s+(?P<addr>{IPV4_ADDRESS})$"
)

_DISCOVERY_HEADER = "LDP discovery sources:"
_ADDRESSES_HEADER = "Addresses bound to peer LDP Ident:"


def _apply_session_line(entry: dict, line: str) -> bool:
    """Apply a TCP / state / up-time line to the entry; return True if matched."""
    if match := _TCP_RE.match(line):
        entry["tcp_connection"] = LdpTcpConnection(
            peer_address=match.group("peer_addr"),
            peer_port=int(match.group("peer_port")),
            local_address=match.group("local_addr"),
            local_port=int(match.group("local_port")),
        )
    elif match := _STATE_RE.match(line):
        entry["state"] = match.group("state")
        entry["messages_sent"] = int(match.group("sent"))
        entry["messages_received"] = int(match.group("rcvd"))
        entry["advertisement_mode"] = match.group("mode")
    elif match := _UP_TIME_RE.match(line):
        entry["up_time"] = match.group("up_time")
    else:
        return False
    return True


def _apply_section_line(entry: dict, section: str | None, line: str) -> None:
    """Apply a line inside the discovery-sources or bound-addresses block."""
    if section == _DISCOVERY_HEADER:
        if match := _INTF_SOURCE_RE.match(line):
            intf = canonical_interface_name(match.group("intf"), os=OS.CISCO_IOSXE)
            sources = entry.setdefault("discovery_sources", {})
            sources.setdefault("interfaces", {})[intf] = LdpInterfaceDiscovery(
                source_address=match.group("addr")
            )
    elif section == _ADDRESSES_HEADER:
        addresses = IPV4_ADDRESS_RE.findall(line)
        if addresses:
            entry.setdefault("bound_addresses", []).extend(addresses)


@register(OS.CISCO_IOSXE, "show mpls ldp neighbor")
class ShowMplsLdpNeighborParser(BaseParser["ShowMplsLdpNeighborResult"]):
    """Parser for 'show mpls ldp neighbor' on IOS-XE.

    Parses each LDP session block into a dict keyed by peer LDP identifier.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> "ShowMplsLdpNeighborResult":
        """Parse 'show mpls ldp neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by peer LDP identifier with session details.

        Raises:
            ValueError: If no LDP neighbors found in output.
        """
        result: dict[str, dict] = {}
        entry: dict | None = None
        section: str | None = None

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if match := _PEER_RE.match(line):
                entry = {"local_ldp_id": match.group("local")}
                result[match.group("peer")] = entry
                section = None
            elif entry is None:
                continue
            elif line in (_DISCOVERY_HEADER, _ADDRESSES_HEADER):
                section = line
            elif _apply_session_line(entry, line):
                section = None
            else:
                _apply_section_line(entry, section, line)

        if not result:
            msg = "No LDP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowMplsLdpNeighborResult, result)
