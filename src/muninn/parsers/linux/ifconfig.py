"""Parser for 'ifconfig' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IPv4Entry(TypedDict):
    """Schema for an IPv4 address entry."""

    address: str
    netmask: str
    broadcast: NotRequired[str]


class IPv6Entry(TypedDict):
    """Schema for an IPv6 address entry."""

    address: str
    prefix_length: int
    scope_id: str


class Counters(TypedDict):
    """Schema for interface RX/TX counters."""

    rx_packets: int
    rx_bytes: int
    rx_errors: int
    rx_dropped: int
    rx_overruns: int
    rx_frame: int
    tx_packets: int
    tx_bytes: int
    tx_errors: int
    tx_dropped: int
    tx_overruns: int
    tx_carrier: int
    tx_collisions: int


class InterfaceEntry(TypedDict):
    """Schema for a single interface from ifconfig output."""

    flags: str
    mtu: int
    mac_address: NotRequired[str]
    link_encap: str
    tx_queue_length: int
    ipv4: NotRequired[dict[str, IPv4Entry]]
    ipv6: NotRequired[dict[str, IPv6Entry]]
    counters: Counters
    device_interrupt: NotRequired[int]
    device_memory: NotRequired[str]


IfconfigResult = dict[str, InterfaceEntry]

# Modern ifconfig format (iproute2-style):
# eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
_IFACE_HEADER_RE = re.compile(
    r"^(?P<name>\S+?):\s+flags=\d+<(?P<flags>[^>]*)>\s+mtu\s+(?P<mtu>\d+)"
)

# inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
_INET_RE = re.compile(
    r"^\s+inet\s+(?P<addr>\S+)"
    r"\s+netmask\s+(?P<netmask>\S+)"
    r"(?:\s+broadcast\s+(?P<broadcast>\S+))?"
)

# inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
_INET6_RE = re.compile(
    r"^\s+inet6\s+(?P<addr>\S+)"
    r"\s+prefixlen\s+(?P<prefixlen>\d+)"
    r"\s+scopeid\s+(?P<scopeid>\S+)"
)

# ether 02:42:04:ff:68:9b  txqueuelen 0  (Ethernet)
# loop  txqueuelen 1000  (Local Loopback)
_LINK_RE = re.compile(
    r"^\s+(?P<type>ether|loop)\s+"
    r"(?:(?P<mac>[0-9a-f:]+)\s+)?"
    r"txqueuelen\s+(?P<txq>\d+)"
    r"\s+\((?P<encap>[^)]+)\)"
)

# RX packets 2567079  bytes 636136982 (606.6 MiB)
_RX_PACKETS_RE = re.compile(
    r"^\s+RX\s+packets\s+(?P<packets>\d+)\s+bytes\s+(?P<bytes>\d+)"
)

# RX errors 0  dropped 0  overruns 0  frame 0
_RX_ERRORS_RE = re.compile(
    r"^\s+RX\s+errors\s+(?P<errors>\d+)"
    r"\s+dropped\s+(?P<dropped>\d+)"
    r"\s+overruns\s+(?P<overruns>\d+)"
    r"\s+frame\s+(?P<frame>\d+)"
)

# TX packets 3057807  bytes 628781252 (599.6 MiB)
_TX_PACKETS_RE = re.compile(
    r"^\s+TX\s+packets\s+(?P<packets>\d+)\s+bytes\s+(?P<bytes>\d+)"
)

# TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
_TX_ERRORS_RE = re.compile(
    r"^\s+TX\s+errors\s+(?P<errors>\d+)"
    r"\s+dropped\s+(?P<dropped>\d+)"
    r"\s+overruns\s+(?P<overruns>\d+)"
    r"\s+carrier\s+(?P<carrier>\d+)"
    r"\s+collisions\s+(?P<collisions>\d+)"
)

# device interrupt 16  memory 0xe9200000-e9220000
_DEVICE_RE = re.compile(
    r"^\s+device\s+interrupt\s+(?P<irq>\d+)"
    r"(?:\s+memory\s+(?P<memory>\S+))?"
)


def _new_counters() -> Counters:
    """Return a zero-initialized Counters dict."""
    return Counters(
        rx_packets=0,
        rx_bytes=0,
        rx_errors=0,
        rx_dropped=0,
        rx_overruns=0,
        rx_frame=0,
        tx_packets=0,
        tx_bytes=0,
        tx_errors=0,
        tx_dropped=0,
        tx_overruns=0,
        tx_carrier=0,
        tx_collisions=0,
    )


def _parse_interface_block(lines: list[str]) -> tuple[str, InterfaceEntry] | None:
    """Parse a single interface block into a (name, InterfaceEntry) tuple."""
    if not lines:
        return None

    header_match = _IFACE_HEADER_RE.match(lines[0])
    if not header_match:
        return None

    name = header_match.group("name")
    counters = _new_counters()

    entry: InterfaceEntry = {
        "flags": header_match.group("flags"),
        "mtu": int(header_match.group("mtu")),
        "link_encap": "unknown",
        "tx_queue_length": 0,
        "counters": counters,
    }

    for line in lines[1:]:
        _parse_detail_line(line, entry, counters)

    return name, entry


def _parse_inet(line: str, entry: InterfaceEntry) -> bool:
    """Parse an IPv4 address line. Returns True if matched."""
    match = _INET_RE.match(line)
    if not match:
        return False
    addr = match.group("addr")
    ipv4_entry = IPv4Entry(address=addr, netmask=match.group("netmask"))
    if match.group("broadcast"):
        ipv4_entry["broadcast"] = match.group("broadcast")
    entry.setdefault("ipv4", {})[addr] = ipv4_entry
    return True


def _parse_inet6(line: str, entry: InterfaceEntry) -> bool:
    """Parse an IPv6 address line. Returns True if matched."""
    match = _INET6_RE.match(line)
    if not match:
        return False
    addr = match.group("addr")
    entry.setdefault("ipv6", {})[addr] = IPv6Entry(
        address=addr,
        prefix_length=int(match.group("prefixlen")),
        scope_id=match.group("scopeid"),
    )
    return True


def _parse_link(line: str, entry: InterfaceEntry) -> bool:
    """Parse a link/encap line. Returns True if matched."""
    match = _LINK_RE.match(line)
    if not match:
        return False
    entry["link_encap"] = match.group("encap")
    entry["tx_queue_length"] = int(match.group("txq"))
    if match.group("mac"):
        entry["mac_address"] = match.group("mac")
    return True


def _parse_rx_counters(line: str, counters: Counters) -> bool:
    """Parse RX packets/bytes and RX errors lines. Returns True if matched."""
    match = _RX_PACKETS_RE.match(line)
    if match:
        counters["rx_packets"] = int(match.group("packets"))
        counters["rx_bytes"] = int(match.group("bytes"))
        return True
    match = _RX_ERRORS_RE.match(line)
    if match:
        counters["rx_errors"] = int(match.group("errors"))
        counters["rx_dropped"] = int(match.group("dropped"))
        counters["rx_overruns"] = int(match.group("overruns"))
        counters["rx_frame"] = int(match.group("frame"))
        return True
    return False


def _parse_tx_counters(line: str, counters: Counters) -> bool:
    """Parse TX packets/bytes and TX errors lines. Returns True if matched."""
    match = _TX_PACKETS_RE.match(line)
    if match:
        counters["tx_packets"] = int(match.group("packets"))
        counters["tx_bytes"] = int(match.group("bytes"))
        return True
    match = _TX_ERRORS_RE.match(line)
    if match:
        counters["tx_errors"] = int(match.group("errors"))
        counters["tx_dropped"] = int(match.group("dropped"))
        counters["tx_overruns"] = int(match.group("overruns"))
        counters["tx_carrier"] = int(match.group("carrier"))
        counters["tx_collisions"] = int(match.group("collisions"))
        return True
    return False


def _parse_device_info(line: str, entry: InterfaceEntry) -> bool:
    """Parse device interrupt/memory line. Returns True if matched."""
    match = _DEVICE_RE.match(line)
    if not match:
        return False
    entry["device_interrupt"] = int(match.group("irq"))
    if match.group("memory"):
        entry["device_memory"] = match.group("memory")
    return True


def _parse_detail_line(line: str, entry: InterfaceEntry, counters: Counters) -> None:
    """Dispatch a single detail line to the appropriate sub-parser."""
    if _parse_inet(line, entry):
        return
    if _parse_inet6(line, entry):
        return
    if _parse_link(line, entry):
        return
    if _parse_rx_counters(line, counters):
        return
    if _parse_tx_counters(line, counters):
        return
    _parse_device_info(line, entry)


@register(OS.LINUX, "ifconfig")
class IfconfigParser(BaseParser[IfconfigResult]):
    """Parser for 'ifconfig' command on Linux.

    Parses interface information including flags, MTU, MAC addresses,
    IPv4/IPv6 addresses, and TX/RX counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> IfconfigResult:
        """Parse 'ifconfig' output on Linux.

        Args:
            output: Raw CLI output from the ifconfig command.

        Returns:
            Dict of interface entries keyed by interface name.

        Raises:
            ValueError: If no interfaces can be parsed.
        """
        result: IfconfigResult = {}
        current_block: list[str] = []

        for line in output.splitlines():
            # An interface header starts at column 0 (no leading whitespace)
            if line and not line[0].isspace():
                parsed = _parse_interface_block(current_block)
                if parsed:
                    result[parsed[0]] = parsed[1]
                current_block = [line]
            elif line.strip():
                current_block.append(line)

        # Process the last block
        parsed = _parse_interface_block(current_block)
        if parsed:
            result[parsed[0]] = parsed[1]

        if not result:
            msg = "No interfaces found in ifconfig output"
            raise ValueError(msg)

        return result
