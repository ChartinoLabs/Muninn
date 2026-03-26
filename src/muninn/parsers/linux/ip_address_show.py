"""Parser for 'ip address show' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class AddressEntry(TypedDict):
    """Schema for an IP address entry (inet or inet6)."""

    address: str
    prefix_length: int
    family: str
    scope: str
    broadcast: NotRequired[str]
    dynamic: NotRequired[bool]
    secondary: NotRequired[bool]
    noprefixroute: NotRequired[bool]
    valid_lft: NotRequired[str]
    preferred_lft: NotRequired[str]


class InterfaceEntry(TypedDict):
    """Schema for a single interface's information."""

    index: int
    name: str
    flags: list[str]
    mtu: int
    qdisc: NotRequired[str]
    state: str
    group: NotRequired[str]
    qlen: NotRequired[int]
    master: NotRequired[str]
    link_type: str
    mac_address: NotRequired[str]
    broadcast_mac: NotRequired[str]
    altname: NotRequired[str]
    addresses: list[AddressEntry]


IpAddressShowResult = dict[str, InterfaceEntry]


# Pattern for the interface header line:
# N: name: <FLAGS> mtu N qdisc X state Y [group G] [qlen Q]
_IFACE_HEADER_RE = re.compile(
    r"^(?P<index>\d+):\s+(?P<name>\S+?):\s+"
    r"<(?P<flags>[^>]*)>\s+"
    r"mtu\s+(?P<mtu>\d+)\s+"
    r"qdisc\s+(?P<qdisc>\S+)\s+"
    r"(?:(?P<state_label>state)\s+(?P<state>\S+)\s*)?"
)

# Pattern for master keyword in the header line
_MASTER_RE = re.compile(r"\bmaster\s+(\S+)")

# Pattern for group keyword in the header line
_GROUP_RE = re.compile(r"\bgroup\s+(\S+)")

# Pattern for qlen keyword in the header line
_QLEN_RE = re.compile(r"\bqlen\s+(\d+)")

# Pattern for link layer info:
# link/ether AA:BB:CC:DD:EE:FF brd FF:FF:FF:FF:FF:FF
# link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
# link/none
_LINK_RE = re.compile(
    r"^\s+link/(?P<type>\S+)"
    r"(?:\s+(?P<mac>[0-9a-f:]+))?"
    r"(?:\s+brd\s+(?P<brd>[0-9a-f:]+))?"
)

# Pattern for altname
_ALTNAME_RE = re.compile(r"^\s+altname\s+(?P<altname>\S+)")

# Pattern for inet/inet6 address lines:
# inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
# inet6 ::1/128 scope host
_INET_RE = re.compile(
    r"^\s+(?P<family>inet6?)\s+"
    r"(?P<address>\S+?)/(?P<prefix>\d+)"
    r"(?:\s+brd\s+(?P<broadcast>\S+))?"
    r"\s+scope\s+(?P<scope>\S+)"
    r"(?P<remainder>.*)"
)

# Pattern for valid_lft / preferred_lft lines:
# valid_lft forever preferred_lft forever
# valid_lft 86400sec preferred_lft 86400sec
_LIFETIME_RE = re.compile(
    r"^\s+valid_lft\s+(?P<valid>\S+)\s+preferred_lft\s+(?P<preferred>\S+)"
)


def _parse_header(line: str) -> InterfaceEntry | None:
    """Parse an interface header line into an InterfaceEntry."""
    header_match = _IFACE_HEADER_RE.match(line)
    if not header_match:
        return None

    iface: InterfaceEntry = {
        "index": int(header_match.group("index")),
        "name": header_match.group("name"),
        "flags": header_match.group("flags").split(","),
        "mtu": int(header_match.group("mtu")),
        "state": header_match.group("state") or "UNKNOWN",
        "link_type": "",
        "addresses": [],
    }

    qdisc = header_match.group("qdisc")
    if qdisc:
        iface["qdisc"] = qdisc

    master_match = _MASTER_RE.search(line)
    if master_match:
        iface["master"] = master_match.group(1)

    group_match = _GROUP_RE.search(line)
    if group_match:
        iface["group"] = group_match.group(1)

    qlen_match = _QLEN_RE.search(line)
    if qlen_match:
        iface["qlen"] = int(qlen_match.group(1))

    return iface


def _parse_link(line: str, iface: InterfaceEntry) -> bool:
    """Parse a link layer info line. Returns True if matched."""
    link_match = _LINK_RE.match(line)
    if not link_match:
        return False

    iface["link_type"] = link_match.group("type")
    if link_match.group("mac"):
        iface["mac_address"] = link_match.group("mac")
    if link_match.group("brd"):
        iface["broadcast_mac"] = link_match.group("brd")
    return True


def _parse_address(line: str) -> AddressEntry | None:
    """Parse an inet/inet6 address line into an AddressEntry."""
    inet_match = _INET_RE.match(line)
    if not inet_match:
        return None

    addr: AddressEntry = {
        "address": inet_match.group("address"),
        "prefix_length": int(inet_match.group("prefix")),
        "family": inet_match.group("family"),
        "scope": inet_match.group("scope"),
    }

    if inet_match.group("broadcast"):
        addr["broadcast"] = inet_match.group("broadcast")

    remainder = inet_match.group("remainder")
    if remainder:
        words = remainder.split()
        if "dynamic" in words:
            addr["dynamic"] = True
        if "secondary" in words:
            addr["secondary"] = True
        if "noprefixroute" in words:
            addr["noprefixroute"] = True

    return addr


def _parse_altname(line: str, iface: InterfaceEntry) -> bool:
    """Parse an altname line. Returns True if matched."""
    altname_match = _ALTNAME_RE.match(line)
    if not altname_match:
        return False
    iface["altname"] = altname_match.group("altname")
    return True


def _parse_lifetime(line: str, addr: AddressEntry) -> bool:
    """Parse a valid_lft/preferred_lft line. Returns True if matched."""
    lft_match = _LIFETIME_RE.match(line)
    if not lft_match:
        return False
    addr["valid_lft"] = lft_match.group("valid")
    addr["preferred_lft"] = lft_match.group("preferred")
    return True


class _ParseState:
    """Mutable state for the line-by-line parser loop."""

    __slots__ = ("current_iface", "current_addr", "result")

    def __init__(self) -> None:
        self.result: dict[str, InterfaceEntry] = {}
        self.current_iface: InterfaceEntry | None = None
        self.current_addr: AddressEntry | None = None

    def handle_line(self, line: str) -> None:
        """Dispatch a single line to the appropriate sub-parser."""
        iface = _parse_header(line)
        if iface is not None:
            self.current_addr = None
            self.current_iface = iface
            self.result[iface["name"]] = iface
            return

        if self.current_iface is None:
            return

        self._handle_iface_detail(line)

    def _handle_iface_detail(self, line: str) -> None:
        """Parse a detail line belonging to the current interface."""
        assert self.current_iface is not None  # noqa: S101

        if _parse_link(line, self.current_iface):
            self.current_addr = None
            return

        if _parse_altname(line, self.current_iface):
            self.current_addr = None
            return

        addr = _parse_address(line)
        if addr is not None:
            self.current_addr = addr
            self.current_iface["addresses"].append(addr)
            return

        if self.current_addr is not None:
            _parse_lifetime(line, self.current_addr)


@register(OS.LINUX, "ip address show")
class IpAddressShowParser(BaseParser[IpAddressShowResult]):
    """Parser for 'ip address show' command on Linux.

    Parses interface information including flags, MTU, state,
    link-layer addresses, and IPv4/IPv6 addresses.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    @classmethod
    def parse(cls, output: str) -> IpAddressShowResult:
        """Parse 'ip address show' output on Linux.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of interface entries keyed by interface name.

        Raises:
            ValueError: If no interfaces can be parsed.
        """
        state = _ParseState()

        for line in output.splitlines():
            state.handle_line(line)

        if not state.result:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(IpAddressShowResult, state.result)
