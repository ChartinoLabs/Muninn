"""Parser for 'show bgp neighbors' command on Cisco IOS-XR.

IOS-XR ``show bgp neighbors`` displays detailed information about each BGP
neighbor including session state, timers, message counters, capabilities,
and per-address-family prefix statistics.

The parser produces a dict-of-dicts keyed by neighbor IP address (IPv4 or
IPv6).
"""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class AddressFamilyDetail(TypedDict):
    """Schema for per-address-family details within a neighbor."""

    accepted_prefixes: int
    bestpaths: int
    prefixes_advertised: int
    prefixes_suppressed: int
    prefixes_withdrawn: int
    max_prefixes_allowed: int
    route_refresh_received: int
    route_refresh_sent: int
    is_route_reflector_client: NotRequired[bool]
    inbound_policy: NotRequired[str]
    outbound_policy: NotRequired[str]


class NeighborDetail(TypedDict):
    """Schema for a single BGP neighbor in the detailed output."""

    remote_as: int
    local_as: int
    link_type: str
    router_id: str
    state: str
    description: NotRequired[str]
    up_time: NotRequired[str]
    hold_time: int
    keepalive_interval: int
    messages_received: int
    messages_sent: int
    notifications_received: int
    notifications_sent: int
    connections_established: int
    connections_dropped: int
    local_host: str
    local_port: int
    foreign_host: str
    foreign_port: int
    last_reset: NotRequired[str]
    last_reset_reason: NotRequired[str]
    address_families: dict[str, AddressFamilyDetail]


ShowBgpNeighborsResult = dict[str, NeighborDetail]

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_NEIGHBOR_HEADER_RE = re.compile(r"^BGP neighbor is (\S+)")
_REMOTE_AS_RE = re.compile(r"Remote AS (\d+), local AS (\d+), (internal|external) link")
_DESCRIPTION_RE = re.compile(r"Description:\s+(.+?)\s*$")
_ROUTER_ID_RE = re.compile(r"Remote router ID (\S+)")
_STATE_RE = re.compile(r"BGP state = (\S+?)(?:,\s*up for (.+))?$")
_HOLD_TIME_RE = re.compile(r"Hold time is (\d+), keepalive interval is (\d+) seconds")
_RECEIVED_RE = re.compile(r"Received (\d+) messages, (\d+) notifications, \d+ in queue")
_SENT_RE = re.compile(r"Sent (\d+) messages, (\d+) notifications, \d+ in queue")
_ADDRESS_FAMILY_RE = re.compile(r"For Address Family:\s+(.+?)\s*$")
_ACCEPTED_PREFIXES_RE = re.compile(r"(\d+) accepted prefixes, (\d+) are bestpaths")
_PREFIX_ADV_RE = re.compile(
    r"Prefix advertised (\d+), suppressed (\d+), withdrawn (\d+)"
)
_MAX_PREFIXES_RE = re.compile(r"Maximum prefixes allowed (\d+)")
_ROUTE_REFRESH_RE = re.compile(r"Route refresh request: received (\d+), sent (\d+)")
_CONNECTIONS_RE = re.compile(r"Connections established (\d+); dropped (\d+)")
_LOCAL_HOST_RE = re.compile(r"Local host: (\S+), Local port: (\d+)")
_FOREIGN_HOST_RE = re.compile(r"Foreign host: (\S+), Foreign port: (\d+)")
_LAST_RESET_RE = re.compile(r"Last reset (.+?), due to (.+?)\s*$")
_RR_CLIENT_RE = re.compile(r"Route-Reflector Client")
_INBOUND_POLICY_RE = re.compile(r"Policy for incoming advertisements is (\S+)")
_OUTBOUND_POLICY_RE = re.compile(r"Policy for outgoing advertisements is (\S+)")


def _parse_af_detail(lines: list[str]) -> AddressFamilyDetail:
    """Parse lines belonging to a single address-family section."""
    result: AddressFamilyDetail = {
        "accepted_prefixes": 0,
        "bestpaths": 0,
        "prefixes_advertised": 0,
        "prefixes_suppressed": 0,
        "prefixes_withdrawn": 0,
        "max_prefixes_allowed": 0,
        "route_refresh_received": 0,
        "route_refresh_sent": 0,
    }
    for line in lines:
        stripped = line.strip()
        if m := _ACCEPTED_PREFIXES_RE.search(stripped):
            result["accepted_prefixes"] = int(m.group(1))
            result["bestpaths"] = int(m.group(2))
        elif m := _PREFIX_ADV_RE.search(stripped):
            result["prefixes_advertised"] = int(m.group(1))
            result["prefixes_suppressed"] = int(m.group(2))
            result["prefixes_withdrawn"] = int(m.group(3))
        elif m := _MAX_PREFIXES_RE.search(stripped):
            result["max_prefixes_allowed"] = int(m.group(1))
        elif m := _ROUTE_REFRESH_RE.search(stripped):
            result["route_refresh_received"] = int(m.group(1))
            result["route_refresh_sent"] = int(m.group(2))
        elif _RR_CLIENT_RE.search(stripped):
            result["is_route_reflector_client"] = True
        elif m := _INBOUND_POLICY_RE.search(stripped):
            result["inbound_policy"] = m.group(1)
        elif m := _OUTBOUND_POLICY_RE.search(stripped):
            result["outbound_policy"] = m.group(1)
    return result


def _split_neighbor_blocks(output: str) -> list[tuple[str, list[str]]]:
    """Split raw output into (neighbor_address, lines) tuples."""
    blocks: list[tuple[str, list[str]]] = []
    current_addr: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _NEIGHBOR_HEADER_RE.match(line)
        if m:
            if current_addr is not None:
                blocks.append((current_addr, current_lines))
            current_addr = m.group(1)
            current_lines = []
        elif current_addr is not None:
            current_lines.append(line)

    if current_addr is not None:
        blocks.append((current_addr, current_lines))
    return blocks


def _split_af_sections(
    lines: list[str],
) -> list[tuple[str, list[str]]]:
    """Split neighbor lines into per-address-family sections."""
    sections: list[tuple[str, list[str]]] = []
    current_af: str | None = None
    current_lines: list[str] = []

    for line in lines:
        m = _ADDRESS_FAMILY_RE.search(line.strip())
        if m:
            if current_af is not None:
                sections.append((current_af, current_lines))
            current_af = m.group(1)
            current_lines = []
        elif current_af is not None:
            current_lines.append(line)

    if current_af is not None:
        sections.append((current_af, current_lines))
    return sections


def _match_remote_as(m: re.Match[str], fields: dict) -> None:
    fields["remote_as"] = int(m.group(1))
    fields["local_as"] = int(m.group(2))
    fields["link_type"] = m.group(3)


def _match_state(m: re.Match[str], fields: dict) -> None:
    fields["state"] = m.group(1)
    if m.group(2):
        fields["up_time"] = m.group(2)


def _match_hold_time(m: re.Match[str], fields: dict) -> None:
    fields["hold_time"] = int(m.group(1))
    fields["keepalive_interval"] = int(m.group(2))


def _match_received(m: re.Match[str], fields: dict) -> None:
    fields["messages_received"] = int(m.group(1))
    fields["notifications_received"] = int(m.group(2))


def _match_sent(m: re.Match[str], fields: dict) -> None:
    fields["messages_sent"] = int(m.group(1))
    fields["notifications_sent"] = int(m.group(2))


def _match_connections(m: re.Match[str], fields: dict) -> None:
    fields["connections_established"] = int(m.group(1))
    fields["connections_dropped"] = int(m.group(2))


def _match_local_host(m: re.Match[str], fields: dict) -> None:
    fields["local_host"] = m.group(1)
    fields["local_port"] = int(m.group(2))


def _match_foreign_host(m: re.Match[str], fields: dict) -> None:
    fields["foreign_host"] = m.group(1)
    fields["foreign_port"] = int(m.group(2))


def _match_last_reset(m: re.Match[str], fields: dict) -> None:
    fields["last_reset"] = m.group(1)
    fields["last_reset_reason"] = m.group(2)


_MatchHandler = Callable[[re.Match[str], dict], None]

_HEADER_MATCHERS: list[tuple[re.Pattern[str], _MatchHandler]] = [
    (_REMOTE_AS_RE, _match_remote_as),
    (_STATE_RE, _match_state),
    (_HOLD_TIME_RE, _match_hold_time),
    (_RECEIVED_RE, _match_received),
    (_SENT_RE, _match_sent),
    (_CONNECTIONS_RE, _match_connections),
    (_LOCAL_HOST_RE, _match_local_host),
    (_FOREIGN_HOST_RE, _match_foreign_host),
    (_LAST_RESET_RE, _match_last_reset),
]

_SIMPLE_HEADER_MATCHERS: list[tuple[re.Pattern[str], str, int, type]] = [
    (_DESCRIPTION_RE, "description", 1, str),
    (_ROUTER_ID_RE, "router_id", 1, str),
]


def _parse_neighbor_header(lines: list[str]) -> dict:
    """Extract header-level fields from neighbor lines (before AF sections)."""
    fields: dict = {}
    for line in lines:
        stripped = line.strip()
        for pattern, handler in _HEADER_MATCHERS:
            if m := pattern.search(stripped):
                handler(m, fields)
                break
        else:
            for pattern, key, group, transform in _SIMPLE_HEADER_MATCHERS:
                if m := pattern.search(stripped):
                    fields[key] = transform(m.group(group))
                    break
    return fields


def _build_neighbor_entry(
    lines: list[str],
) -> NeighborDetail:
    """Build a complete NeighborDetail from the lines of a single neighbor block."""
    header = _parse_neighbor_header(lines)
    af_sections = _split_af_sections(lines)

    address_families: dict[str, AddressFamilyDetail] = {}
    for af_name, af_lines in af_sections:
        address_families[af_name] = _parse_af_detail(af_lines)

    result: NeighborDetail = {
        "remote_as": header["remote_as"],
        "local_as": header["local_as"],
        "link_type": header["link_type"],
        "router_id": header["router_id"],
        "state": header["state"],
        "hold_time": header["hold_time"],
        "keepalive_interval": header["keepalive_interval"],
        "messages_received": header["messages_received"],
        "messages_sent": header["messages_sent"],
        "notifications_received": header["notifications_received"],
        "notifications_sent": header["notifications_sent"],
        "connections_established": header["connections_established"],
        "connections_dropped": header["connections_dropped"],
        "local_host": header["local_host"],
        "local_port": header["local_port"],
        "foreign_host": header["foreign_host"],
        "foreign_port": header["foreign_port"],
        "address_families": address_families,
    }

    # Add optional fields
    if "description" in header:
        result["description"] = header["description"]
    if "up_time" in header:
        result["up_time"] = header["up_time"]
    if "last_reset" in header:
        result["last_reset"] = header["last_reset"]
    if "last_reset_reason" in header:
        result["last_reset_reason"] = header["last_reset_reason"]

    return result


@register(OS.CISCO_IOSXR, "show bgp neighbors")
class ShowBgpNeighborsParser(BaseParser[ShowBgpNeighborsResult]):
    """Parser for 'show bgp neighbors' on Cisco IOS-XR.

    Parses detailed BGP neighbor information including session state,
    timers, message counters, and per-address-family prefix statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpNeighborsResult:
        """Parse 'show bgp neighbors' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by neighbor address with detailed neighbor info.

        Raises:
            ValueError: If no neighbor blocks are found in the output.
        """
        blocks = _split_neighbor_blocks(output)
        if not blocks:
            msg = "No BGP neighbor data found in output"
            raise ValueError(msg)

        result: ShowBgpNeighborsResult = {}
        for addr, lines in blocks:
            result[addr] = _build_neighbor_entry(lines)

        return result
