"""Parser for 'show ipv6 dhcp interface' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class IaPdEntry(TypedDict):
    """Schema for an IA PD (prefix delegation) entry."""

    iaid: str
    t1: int
    t2: int
    prefix: str
    preferred_lifetime: int
    valid_lifetime: int


class IaNaEntry(TypedDict):
    """Schema for an IA NA (non-temporary address) entry."""

    iaid: str
    t1: int
    t2: int
    address: str
    preferred_lifetime: int
    valid_lifetime: int


class KnownServerEntry(TypedDict):
    """Schema for a known DHCPv6 server entry."""

    duid: str
    preference: int
    ia_pd: NotRequired[IaPdEntry]
    ia_na: NotRequired[IaNaEntry]
    dns_server: NotRequired[str]
    domain_name: NotRequired[str]
    information_refresh_time: NotRequired[int]


class ClientInterfaceEntry(TypedDict):
    """Schema for an interface in client mode."""

    mode: str
    prefix_state: NotRequired[str]
    address_state: NotRequired[str]
    known_servers: NotRequired[dict[str, KnownServerEntry]]
    prefix_name: NotRequired[str]
    prefix_rapid_commit: NotRequired[str]
    address_rapid_commit: NotRequired[str]


class ServerInterfaceEntry(TypedDict):
    """Schema for an interface in server mode."""

    mode: str
    pool_name: NotRequired[str]
    preference_value: NotRequired[int]
    hint_from_client: NotRequired[str]
    rapid_commit: NotRequired[str]


class RelayInterfaceEntry(TypedDict):
    """Schema for an interface in relay mode."""

    mode: str
    relay_destinations: NotRequired[list[str]]


InterfaceEntry = ClientInterfaceEntry | ServerInterfaceEntry | RelayInterfaceEntry


class ShowIpv6DhcpInterfaceResult(TypedDict):
    """Schema for 'show ipv6 dhcp interface' parsed output."""

    interfaces: dict[str, InterfaceEntry]


# -- Compiled regex patterns --------------------------------------------------

_INTERFACE_HEADER = re.compile(r"^(?P<intf>\S+)\s+is\s+in\s+(?P<mode>\S+)\s+mode\s*$")

_PREFIX_STATE = re.compile(
    r"^\s*Prefix\s+State\s+is\s+(?P<state>\S+)(?:\s+\(\d+\))?\s*$"
)

_ADDRESS_STATE = re.compile(r"^\s*Address\s+State\s+is\s+(?P<state>\S+)\s*$")

_REACHABLE_VIA = re.compile(r"^\s*Reachable\s+via\s+address:\s+(?P<addr>\S+)\s*$")

_DUID = re.compile(r"^\s*DUID:\s+(?P<duid>\S+)\s*$")

_PREFERENCE = re.compile(r"^\s*Preference:\s+(?P<pref>\d+)\s*$")

_IA_PD = re.compile(
    r"^\s*IA\s+PD:\s+IA\s+ID\s+(?P<iaid>\S+),\s+"
    r"T1\s+(?P<t1>\d+),\s+T2\s+(?P<t2>\d+)\s*$"
)

_IA_NA = re.compile(
    r"^\s*IA\s+NA:\s+IA\s+ID\s+(?P<iaid>\S+),\s+"
    r"T1\s+(?P<t1>\d+),\s+T2\s+(?P<t2>\d+)\s*$"
)

_PREFIX_LINE = re.compile(r"^\s*Prefix:\s+(?P<prefix>\S+)\s*$")

_ADDRESS_LINE = re.compile(r"^\s*Address:\s+(?P<address>\S+)\s*$")

_LIFETIME_LINE = re.compile(
    r"^\s*preferred\s+lifetime\s+(?P<pref>\d+),\s+"
    r"valid\s+lifetime\s+(?P<valid>\d+)"
)

_DNS_SERVER = re.compile(r"^\s*DNS\s+server:\s+(?P<dns>\S+)\s*$")

_DOMAIN_NAME = re.compile(r"^\s*Domain\s+name:\s+(?P<domain>\S+)\s*$")

_INFO_REFRESH = re.compile(r"^\s*Information\s+refresh\s+time:\s+(?P<time>\d+)\s*$")

_PREFIX_NAME = re.compile(r"^\s*Prefix\s+name:\s+(?P<name>\S+)\s*$")

_PREFIX_RAPID_COMMIT = re.compile(r"^\s*Prefix\s+Rapid-Commit:\s+(?P<val>\S+)\s*$")

_ADDRESS_RAPID_COMMIT = re.compile(r"^\s*Address\s+Rapid-Commit:\s+(?P<val>\S+)\s*$")

# Server mode patterns
_USING_POOL = re.compile(r"^\s*Using\s+pool:\s+(?P<pool>\S+)\s*$")

_PREFERENCE_VALUE = re.compile(r"^\s*Preference\s+value:\s+(?P<val>\d+)\s*$")

_HINT_FROM_CLIENT = re.compile(r"^\s*Hint\s+from\s+client:\s+(?P<hint>\S+)\s*$")

_RAPID_COMMIT = re.compile(r"^\s*Rapid-Commit:\s+(?P<val>\S+)\s*$")

# Relay mode patterns
_RELAY_DEST_HEADER = re.compile(r"^\s*Relay\s+destinations:\s*$")

_RELAY_DEST_ADDR = re.compile(r"^\s+(?P<addr>\S+)\s*$")

# Sentinel indicating no pattern matched a line
_NO_MATCH = "_no_match"


def _handle_ia_header(
    m: re.Match[str],
    server: dict[str, object],
    ia_key: str,
) -> None:
    """Create an IA PD or IA NA sub-dict from a header match."""
    server[ia_key] = {
        "iaid": m.group("iaid"),
        "t1": int(m.group("t1")),
        "t2": int(m.group("t2")),
    }


def _handle_ia_detail(
    line: str,
    server: dict[str, object],
    current_ia_type: str | None,
) -> bool:
    """Handle Prefix, Address, and lifetime lines within an IA block.

    Returns True if the line was consumed.
    """
    if m := _PREFIX_LINE.match(line):
        if current_ia_type == "ia_pd" and "ia_pd" in server:
            server["ia_pd"]["prefix"] = m.group("prefix")
        return True

    if m := _ADDRESS_LINE.match(line):
        if current_ia_type == "ia_na" and "ia_na" in server:
            server["ia_na"]["address"] = m.group("address")
        return True

    if m := _LIFETIME_LINE.match(line):
        if current_ia_type and current_ia_type in server:
            server[current_ia_type]["preferred_lifetime"] = int(m.group("pref"))
            server[current_ia_type]["valid_lifetime"] = int(m.group("valid"))
        return True

    return False


def _handle_server_scalar(
    line: str,
    server: dict[str, object],
) -> bool:
    """Handle simple scalar fields within a server block.

    Returns True if the line was consumed.
    """
    if m := _DUID.match(line):
        server["duid"] = m.group("duid")
        return True

    if m := _PREFERENCE.match(line):
        server["preference"] = int(m.group("pref"))
        return True

    if m := _DNS_SERVER.match(line):
        server["dns_server"] = m.group("dns")
        return True

    if m := _DOMAIN_NAME.match(line):
        server["domain_name"] = m.group("domain")
        return True

    if m := _INFO_REFRESH.match(line):
        server["information_refresh_time"] = int(m.group("time"))
        return True

    return False


def _parse_server_line(
    line: str,
    server: dict[str, object],
    current_ia_type: str | None,
) -> str | None:
    """Parse a single line within a known-server block.

    Returns the updated current_ia_type on match, or the sentinel
    ``_NO_MATCH`` when no pattern matched.
    """
    if _handle_server_scalar(line, server):
        return current_ia_type

    if m := _IA_PD.match(line):
        _handle_ia_header(m, server, "ia_pd")
        return "ia_pd"

    if m := _IA_NA.match(line):
        _handle_ia_header(m, server, "ia_na")
        return "ia_na"

    if _handle_ia_detail(line, server, current_ia_type):
        return current_ia_type

    return _NO_MATCH


def _save_server(
    servers: dict[str, KnownServerEntry],
    addr: str | None,
    data: dict[str, object] | None,
) -> None:
    """Flush a completed server entry into the servers dict."""
    if data is not None and addr is not None:
        servers[addr] = KnownServerEntry(**data)  # type: ignore[arg-type]


def _parse_client_entry_fields(
    line: str,
    entry: dict[str, object],
) -> bool:
    """Handle interface-level fields for client mode.

    Returns True if the line was consumed.
    """
    if m := _PREFIX_STATE.match(line):
        entry["prefix_state"] = m.group("state")
        return True

    if m := _ADDRESS_STATE.match(line):
        entry["address_state"] = m.group("state")
        return True

    if m := _PREFIX_NAME.match(line):
        entry["prefix_name"] = m.group("name")
        return True

    if m := _PREFIX_RAPID_COMMIT.match(line):
        entry["prefix_rapid_commit"] = m.group("val")
        return True

    if m := _ADDRESS_RAPID_COMMIT.match(line):
        entry["address_rapid_commit"] = m.group("val")
        return True

    return False


def _parse_client_block(lines: list[str]) -> ClientInterfaceEntry:
    """Parse an interface block operating in client mode."""
    entry: dict[str, object] = {"mode": "client"}
    servers: dict[str, KnownServerEntry] = {}
    current_server: dict[str, object] | None = None
    current_server_addr: str | None = None
    current_ia_type: str | None = None

    for line in lines:
        if _parse_client_entry_fields(line, entry):
            continue

        if m := _REACHABLE_VIA.match(line):
            _save_server(servers, current_server_addr, current_server)
            current_server_addr = m.group("addr")
            current_server = {}
            current_ia_type = None
            continue

        if current_server is not None:
            result = _parse_server_line(line, current_server, current_ia_type)
            if result != _NO_MATCH:
                current_ia_type = result

    _save_server(servers, current_server_addr, current_server)

    if servers:
        entry["known_servers"] = servers

    return ClientInterfaceEntry(**entry)  # type: ignore[arg-type]


def _parse_server_block(lines: list[str]) -> ServerInterfaceEntry:
    """Parse an interface block operating in server mode."""
    entry: dict[str, object] = {"mode": "server"}

    for line in lines:
        if m := _USING_POOL.match(line):
            entry["pool_name"] = m.group("pool")
        elif m := _PREFERENCE_VALUE.match(line):
            entry["preference_value"] = int(m.group("val"))
        elif m := _HINT_FROM_CLIENT.match(line):
            entry["hint_from_client"] = m.group("hint")
        elif m := _RAPID_COMMIT.match(line):
            entry["rapid_commit"] = m.group("val")

    return ServerInterfaceEntry(**entry)  # type: ignore[arg-type]


def _parse_relay_block(lines: list[str]) -> RelayInterfaceEntry:
    """Parse an interface block operating in relay mode."""
    entry: dict[str, object] = {"mode": "relay"}
    destinations: list[str] = []
    in_relay_dests = False

    for line in lines:
        if _RELAY_DEST_HEADER.match(line):
            in_relay_dests = True
            continue

        if in_relay_dests:
            if m := _RELAY_DEST_ADDR.match(line):
                destinations.append(m.group("addr"))
                continue
            in_relay_dests = False

    if destinations:
        entry["relay_destinations"] = destinations

    return RelayInterfaceEntry(**entry)  # type: ignore[arg-type]


def _split_interface_blocks(
    output: str,
) -> list[tuple[str, str, list[str]]]:
    """Split output into per-interface blocks.

    Returns:
        List of (interface_name, mode, body_lines) tuples.
    """
    blocks: list[tuple[str, str, list[str]]] = []
    current_intf: str | None = None
    current_mode: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        if m := _INTERFACE_HEADER.match(line):
            if current_intf is not None and current_mode is not None:
                blocks.append((current_intf, current_mode, current_lines))
            current_intf = m.group("intf")
            current_mode = m.group("mode")
            current_lines = []
        elif current_intf is not None:
            current_lines.append(line)

    if current_intf is not None and current_mode is not None:
        blocks.append((current_intf, current_mode, current_lines))

    return blocks


@register(OS.CISCO_IOSXE, "show ipv6 dhcp interface")
class ShowIpv6DhcpInterfaceParser(BaseParser[ShowIpv6DhcpInterfaceResult]):
    """Parser for 'show ipv6 dhcp interface' command.

    Example output:
        TenGigabitEthernet1/0/2.154 is in client mode
          Prefix State is OPEN
          Address State is OPEN
          List of known servers:
            Reachable via address: FE80::20C:29FF:FE22:1DA5
            DUID: 00030001001EE59BE700
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpv6DhcpInterfaceResult:
        """Parse 'show ipv6 dhcp interface' output.

        Args:
            output: Raw CLI output from 'show ipv6 dhcp interface' command.

        Returns:
            Parsed DHCPv6 interface data keyed by canonical interface name.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        blocks = _split_interface_blocks(output)

        if not blocks:
            msg = "No DHCPv6 interface entries found in output"
            raise ValueError(msg)

        interfaces: dict[str, InterfaceEntry] = {}

        for raw_intf, mode, lines in blocks:
            intf_name = canonical_interface_name(raw_intf)

            if mode == "client":
                interfaces[intf_name] = _parse_client_block(lines)
            elif mode == "server":
                interfaces[intf_name] = _parse_server_block(lines)
            elif mode == "relay":
                interfaces[intf_name] = _parse_relay_block(lines)

        return ShowIpv6DhcpInterfaceResult(interfaces=interfaces)
