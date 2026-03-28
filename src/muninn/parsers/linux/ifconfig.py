"""Parser for 'ifconfig' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class Ipv4Entry(TypedDict):
    """Schema for an IPv4 address entry."""

    ip: str
    netmask: str
    broadcast: NotRequired[str]


class Ipv6Entry(TypedDict):
    """Schema for an IPv6 address entry."""

    ip: str
    prefixlen: int
    scopeid: NotRequired[str]


class Counters(TypedDict):
    """Schema for interface packet/byte counters."""

    rx_pkts: int
    rx_bytes: int
    rx_value: NotRequired[str]
    rx_errors: int
    rx_dropped: int
    rx_overruns: int
    rx_frame: int
    tx_pkts: int
    tx_bytes: int
    tx_value: NotRequired[str]
    tx_errors: int
    tx_dropped: int
    tx_overruns: int
    tx_carrier: int
    tx_collisions: int


class InterfaceEntry(TypedDict):
    """Schema for a single interface from ifconfig output."""

    interface: str
    flags: list[str]
    mtu: int
    type: NotRequired[str]
    description: NotRequired[str]
    mac: NotRequired[str]
    txqueuelen: NotRequired[int]
    ipv4: NotRequired[dict[str, Ipv4Entry]]
    ipv6: NotRequired[dict[str, Ipv6Entry]]
    counters: NotRequired[Counters]
    device_interrupt: NotRequired[int]
    device_memory: NotRequired[str]


IfconfigResult = dict[str, InterfaceEntry]

# Modern format header: "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500"
_MODERN_HEADER_RE = re.compile(
    r"^(?P<name>\S+?):\s+flags=(?P<flags>\d+<[^>]*>)\s+mtu\s+(?P<mtu>\d+)"
)

# Legacy format header: "eth0      Link encap:Ethernet  HWaddr 00:50:56:FF:01:14"
_LEGACY_HEADER_RE = re.compile(
    r"^(?P<name>\S+)\s+Link\s+encap:(?P<encap>\S+(?:\s+\S+)*?)"
    r"(?:\s+HWaddr\s+(?P<hwaddr>[0-9a-fA-F:]+))?\s*$"
)

# Modern inet: "inet 192.168.66.1  netmask 255.255.255.0  broadcast 192.168.66.255"
_INET_RE = re.compile(
    r"inet\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    r"(?:\s+netmask\s+(?P<netmask>\d+\.\d+\.\d+\.\d+))?"
    r"(?:\s+broadcast\s+(?P<broadcast>\d+\.\d+\.\d+\.\d+))?"
)

# Legacy inet: "inet addr:172.27.114.205  Bcast:172.27.114.255  Mask:255.255.255.0"
_INET_LEGACY_RE = re.compile(
    r"inet\s+addr:(?P<ip>\d+\.\d+\.\d+\.\d+)"
    r"(?:\s+Bcast:(?P<broadcast>\d+\.\d+\.\d+\.\d+))?"
    r"(?:\s+Mask:(?P<netmask>\d+\.\d+\.\d+\.\d+))?"
)

# Modern inet6: "inet6 fe80::42:4ff:feff:689b  prefixlen 64  scopeid 0x20<link>"
_INET6_RE = re.compile(
    r"inet6\s+(?P<ip>\S+?)\s+prefixlen\s+(?P<prefixlen>\d+)"
    r"(?:\s+scopeid\s+(?P<scopeid>\S+))?"
)

# Legacy inet6: "inet6 addr: fe80::250:56ff:feff:114/64 Scope:Link"
_INET6_LEGACY_RE = re.compile(
    r"inet6\s+addr:\s*(?P<ip>\S+?)/(?P<prefixlen>\d+)\s+Scope:(?P<scope>\S+)"
)

# Modern ether line: "ether 02:42:04:ff:68:9b  txqueuelen 0  (Ethernet)"
# Also matches without txqueuelen: "ether 00:50:b6:ff:4b:83  (Ethernet)"
_ETHER_RE = re.compile(
    r"(?P<type>ether|loop)\s+"
    r"(?:(?P<mac>[0-9a-fA-F:]+)\s+)?"
    r"(?:txqueuelen\s+(?P<txqueuelen>\d+)\s+)?"
    r"\((?P<desc>[^)]+)\)"
)

# Legacy flags/MTU line: "UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1"
_LEGACY_FLAGS_RE = re.compile(r"^\s+(?P<flags>[A-Z][A-Z ]+?)\s+MTU:(?P<mtu>\d+)")

# RX packets line (modern): "RX packets 2567079  bytes 636136982 (606.6 MiB)"
_RX_PACKETS_RE = re.compile(
    r"RX\s+packets\s+(?P<pkts>\d+)\s+bytes\s+(?P<bytes>\d+)\s+\((?P<value>[^)]+)\)"
)

# RX packets line (modern, no bytes): "RX packets 0  bytes 0 (0.0 B)"
# Already covered by _RX_PACKETS_RE

# Legacy RX packets: "RX packets:2004256429 errors:0 dropped:0 overruns:0 frame:0"
_RX_PACKETS_LEGACY_RE = re.compile(
    r"RX\s+packets:(?P<pkts>\d+)"
    r"\s+errors:(?P<errors>\d+)"
    r"\s+dropped:(?P<dropped>\d+)"
    r"\s+overruns:(?P<overruns>\d+)"
    r"\s+frame:(?P<frame>\d+)"
)

# RX errors line (modern): "RX errors 0  dropped 0  overruns 0  frame 0"
_RX_ERRORS_RE = re.compile(
    r"RX\s+errors\s+(?P<errors>\d+)"
    r"\s+dropped\s+(?P<dropped>\d+)"
    r"\s+overruns\s+(?P<overruns>\d+)"
    r"\s+frame\s+(?P<frame>\d+)"
)

# TX packets line (modern): "TX packets 3057807  bytes 628781252 (599.6 MiB)"
_TX_PACKETS_RE = re.compile(
    r"TX\s+packets\s+(?P<pkts>\d+)\s+bytes\s+(?P<bytes>\d+)\s+\((?P<value>[^)]+)\)"
)

# Legacy TX packets: "TX packets:4779769715 errors:0 dropped:0 overruns:0 carrier:0"
_TX_PACKETS_LEGACY_RE = re.compile(
    r"TX\s+packets:(?P<pkts>\d+)"
    r"\s+errors:(?P<errors>\d+)"
    r"\s+dropped:(?P<dropped>\d+)"
    r"\s+overruns:(?P<overruns>\d+)"
    r"\s+carrier:(?P<carrier>\d+)"
)

# TX errors line (modern): "TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"
_TX_ERRORS_RE = re.compile(
    r"TX\s+errors\s+(?P<errors>\d+)"
    r"\s+dropped\s+(?P<dropped>\d+)"
    r"\s*overruns\s+(?P<overruns>\d+)"
    r"\s+carrier\s+(?P<carrier>\d+)"
    r"\s+collisions\s+(?P<collisions>\d+)"
)

# Legacy collisions/txqueuelen: "collisions:0 txqueuelen:1000"
_LEGACY_COLLISIONS_RE = re.compile(
    r"collisions:(?P<collisions>\d+)\s+txqueuelen:(?P<txqueuelen>\d+)"
)

# Legacy RX/TX bytes:
# "RX bytes:2084687440241 (1.8 TiB)  TX bytes:6145946777794 (5.5 TiB)"
_LEGACY_BYTES_RE = re.compile(
    r"RX\s+bytes:(?P<rx_bytes>\d+)\s+\((?P<rx_value>[^)]+)\)"
    r"\s+TX\s+bytes:(?P<tx_bytes>\d+)\s+\((?P<tx_value>[^)]+)\)"
)

# Device interrupt/memory: "device interrupt 16  memory 0xe9200000-e9220000"
_DEVICE_RE = re.compile(
    r"device\s+interrupt\s+(?P<interrupt>\d+)"
    r"(?:\s+memory\s+(?P<memory>\S+))?"
)

# Loopback inet line that has no broadcast
_LOOP_ETHER_RE = re.compile(
    r"(?P<type>loop)\s+txqueuelen\s+(?P<txqueuelen>\d+)\s+\((?P<desc>[^)]+)\)"
)

# txqueuelen in modern ether-less format (for loop)
# Already handled by _ETHER_RE with optional mac group


def _init_counters() -> Counters:
    """Create a zeroed counters dict."""
    return Counters(
        rx_pkts=0,
        rx_bytes=0,
        rx_errors=0,
        rx_dropped=0,
        rx_overruns=0,
        rx_frame=0,
        tx_pkts=0,
        tx_bytes=0,
        tx_errors=0,
        tx_dropped=0,
        tx_overruns=0,
        tx_carrier=0,
        tx_collisions=0,
    )


def _ensure_counters(iface: InterfaceEntry) -> Counters:
    """Get or create the counters dict for an interface."""
    if "counters" not in iface:
        iface["counters"] = _init_counters()
    return iface["counters"]


def _parse_modern_header(line: str) -> InterfaceEntry | None:
    """Parse a modern-format interface header line."""
    match = _MODERN_HEADER_RE.match(line)
    if not match:
        return None
    raw_flags = match.group("flags")
    # Extract flags from inside angle brackets: "4163<UP,BROADCAST,RUNNING,MULTICAST>"
    bracket_match = re.search(r"<([^>]*)>", raw_flags)
    flags = bracket_match.group(1).split(",") if bracket_match else []
    return InterfaceEntry(
        interface=match.group("name"),
        flags=flags,
        mtu=int(match.group("mtu")),
    )


def _parse_legacy_header(line: str) -> InterfaceEntry | None:
    """Parse a legacy-format interface header line."""
    match = _LEGACY_HEADER_RE.match(line)
    if not match:
        return None
    encap = match.group("encap")
    iface = InterfaceEntry(
        interface=match.group("name"),
        flags=[],
        mtu=0,
        type=encap,
        description=encap,
    )
    hwaddr = match.group("hwaddr")
    if hwaddr:
        iface["mac"] = hwaddr.lower()
    return iface


def _parse_inet(line: str, iface: InterfaceEntry) -> bool:
    """Parse an IPv4 address line (modern or legacy). Returns True if matched."""
    # Try modern format first
    match = _INET_RE.search(line)
    legacy_match = _INET_LEGACY_RE.search(line)

    target = legacy_match or match
    if not target:
        return False

    ip_addr = target.group("ip")
    entry = Ipv4Entry(ip=ip_addr, netmask=target.group("netmask") or "")

    broadcast = target.group("broadcast")
    if broadcast:
        entry["broadcast"] = broadcast

    if "ipv4" not in iface:
        iface["ipv4"] = {}
    iface["ipv4"][ip_addr] = entry
    return True


def _parse_inet6(line: str, iface: InterfaceEntry) -> bool:
    """Parse an IPv6 address line (modern or legacy). Returns True if matched."""
    # Try legacy format first
    legacy = _INET6_LEGACY_RE.search(line)
    if legacy:
        ip_addr = legacy.group("ip")
        entry = Ipv6Entry(
            ip=ip_addr,
            prefixlen=int(legacy.group("prefixlen")),
        )
        scope = legacy.group("scope")
        if scope:
            entry["scopeid"] = scope
        if "ipv6" not in iface:
            iface["ipv6"] = {}
        iface["ipv6"][ip_addr] = entry
        return True

    modern = _INET6_RE.search(line)
    if modern:
        ip_addr = modern.group("ip")
        entry = Ipv6Entry(
            ip=ip_addr,
            prefixlen=int(modern.group("prefixlen")),
        )
        scopeid = modern.group("scopeid")
        if scopeid:
            entry["scopeid"] = scopeid
        if "ipv6" not in iface:
            iface["ipv6"] = {}
        iface["ipv6"][ip_addr] = entry
        return True

    return False


def _parse_ether(line: str, iface: InterfaceEntry) -> bool:
    """Parse ether/loop type line. Returns True if matched."""
    match = _ETHER_RE.search(line)
    if not match:
        return False

    iface["type"] = match.group("type")
    iface["description"] = match.group("desc")
    mac = match.group("mac")
    if mac:
        iface["mac"] = mac
    txqueuelen = match.group("txqueuelen")
    if txqueuelen is not None:
        iface["txqueuelen"] = int(txqueuelen)
    return True


def _parse_counters(line: str, iface: InterfaceEntry) -> bool:
    """Parse counter-related lines (RX/TX packets, errors, bytes).

    Returns True if the line was matched as a counter line.
    """
    # RX packets (modern)
    rx_match = _RX_PACKETS_RE.search(line)
    if rx_match:
        counters = _ensure_counters(iface)
        counters["rx_pkts"] = int(rx_match.group("pkts"))
        counters["rx_bytes"] = int(rx_match.group("bytes"))
        counters["rx_value"] = rx_match.group("value")
        return True

    # RX packets (legacy)
    rx_legacy = _RX_PACKETS_LEGACY_RE.search(line)
    if rx_legacy:
        counters = _ensure_counters(iface)
        counters["rx_pkts"] = int(rx_legacy.group("pkts"))
        counters["rx_errors"] = int(rx_legacy.group("errors"))
        counters["rx_dropped"] = int(rx_legacy.group("dropped"))
        counters["rx_overruns"] = int(rx_legacy.group("overruns"))
        counters["rx_frame"] = int(rx_legacy.group("frame"))
        return True

    # RX errors (modern)
    rx_err = _RX_ERRORS_RE.search(line)
    if rx_err:
        counters = _ensure_counters(iface)
        counters["rx_errors"] = int(rx_err.group("errors"))
        counters["rx_dropped"] = int(rx_err.group("dropped"))
        counters["rx_overruns"] = int(rx_err.group("overruns"))
        counters["rx_frame"] = int(rx_err.group("frame"))
        return True

    # TX packets (modern)
    tx_match = _TX_PACKETS_RE.search(line)
    if tx_match:
        counters = _ensure_counters(iface)
        counters["tx_pkts"] = int(tx_match.group("pkts"))
        counters["tx_bytes"] = int(tx_match.group("bytes"))
        counters["tx_value"] = tx_match.group("value")
        return True

    # TX packets (legacy)
    tx_legacy = _TX_PACKETS_LEGACY_RE.search(line)
    if tx_legacy:
        counters = _ensure_counters(iface)
        counters["tx_pkts"] = int(tx_legacy.group("pkts"))
        counters["tx_errors"] = int(tx_legacy.group("errors"))
        counters["tx_dropped"] = int(tx_legacy.group("dropped"))
        counters["tx_overruns"] = int(tx_legacy.group("overruns"))
        counters["tx_carrier"] = int(tx_legacy.group("carrier"))
        return True

    # TX errors (modern)
    tx_err = _TX_ERRORS_RE.search(line)
    if tx_err:
        counters = _ensure_counters(iface)
        counters["tx_errors"] = int(tx_err.group("errors"))
        counters["tx_dropped"] = int(tx_err.group("dropped"))
        counters["tx_overruns"] = int(tx_err.group("overruns"))
        counters["tx_carrier"] = int(tx_err.group("carrier"))
        counters["tx_collisions"] = int(tx_err.group("collisions"))
        return True

    # Legacy collisions/txqueuelen
    coll_match = _LEGACY_COLLISIONS_RE.search(line)
    if coll_match:
        counters = _ensure_counters(iface)
        counters["tx_collisions"] = int(coll_match.group("collisions"))
        iface["txqueuelen"] = int(coll_match.group("txqueuelen"))
        return True

    # Legacy RX/TX bytes
    bytes_match = _LEGACY_BYTES_RE.search(line)
    if bytes_match:
        counters = _ensure_counters(iface)
        counters["rx_bytes"] = int(bytes_match.group("rx_bytes"))
        counters["rx_value"] = bytes_match.group("rx_value")
        counters["tx_bytes"] = int(bytes_match.group("tx_bytes"))
        counters["tx_value"] = bytes_match.group("tx_value")
        return True

    return False


def _parse_detail_line(line: str, iface: InterfaceEntry) -> None:
    """Parse a detail line belonging to the current interface."""
    stripped = line.strip()
    if not stripped:
        return

    # IPv4 address
    if _parse_inet(line, iface):
        return

    # IPv6 address
    if _parse_inet6(line, iface):
        return

    # Ether/loop type line (modern)
    if _parse_ether(line, iface):
        return

    # Legacy flags/MTU
    flags_match = _LEGACY_FLAGS_RE.match(line)
    if flags_match:
        iface["flags"] = flags_match.group("flags").strip().split()
        iface["mtu"] = int(flags_match.group("mtu"))
        return

    # Counter lines (RX/TX packets, errors, bytes)
    if _parse_counters(line, iface):
        return

    # Device interrupt/memory
    dev_match = _DEVICE_RE.search(line)
    if dev_match:
        iface["device_interrupt"] = int(dev_match.group("interrupt"))
        mem = dev_match.group("memory")
        if mem:
            iface["device_memory"] = mem


def _is_header_line(line: str) -> bool:
    """Check if a line is an interface header (starts with non-whitespace)."""
    return bool(line) and not line[0].isspace()


@register(OS.LINUX, "ifconfig")
class IfconfigParser(BaseParser[IfconfigResult]):
    """Parser for 'ifconfig' command on Linux.

    Parses interface information including flags, MTU, addresses,
    link-layer type, MAC address, and packet/byte counters.

    Supports both modern (iproute2-style) and legacy (net-tools) output formats.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

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
        result: dict[str, InterfaceEntry] = {}
        current_iface: InterfaceEntry | None = None

        for line in output.splitlines():
            # Check for modern header
            modern = _parse_modern_header(line)
            if modern is not None:
                current_iface = modern
                result[modern["interface"]] = modern
                continue

            # Check for legacy header
            if _is_header_line(line):
                legacy = _parse_legacy_header(line)
                if legacy is not None:
                    current_iface = legacy
                    result[legacy["interface"]] = legacy
                    continue

            # Detail line for current interface
            if current_iface is not None:
                _parse_detail_line(line, current_iface)

        if not result:
            msg = "No interfaces found in ifconfig output"
            raise ValueError(msg)

        return cast(IfconfigResult, result)
