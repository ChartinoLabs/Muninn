"""Parser for 'show ipv6 interface' command on IOS-XE."""

import re
from typing import Any, ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class GlobalUnicastAddress(TypedDict):
    """Schema for a global unicast address on an interface."""

    subnet: str
    prefix_length: int
    flags: NotRequired[list[str]]


class Ipv6InterfaceEntry(TypedDict):
    """Schema for a single interface entry from 'show ipv6 interface'."""

    status: str
    line_protocol: str
    ipv6_status: NotRequired[str]
    link_local_address: NotRequired[str]
    link_local_flags: NotRequired[list[str]]
    global_unicast_addresses: NotRequired[dict[str, GlobalUnicastAddress]]
    multicast_groups: NotRequired[list[str]]
    mtu: NotRequired[int]
    vrf: NotRequired[str]
    icmp_error_interval_ms: NotRequired[int]
    icmp_redirects: NotRequired[str]
    icmp_unreachables: NotRequired[str]
    nd_dad: NotRequired[str]
    nd_dad_attempts: NotRequired[int]
    nd_reachable_time_ms: NotRequired[int]
    nd_reachable_time_in_use_ms: NotRequired[int]
    nd_advertised_reachable_time_ms: NotRequired[int]
    nd_advertised_retransmit_interval_ms: NotRequired[int]
    nd_ns_retransmit_interval_ms: NotRequired[int]
    nd_ra_interval_seconds: NotRequired[int]
    nd_ra_lifetime_seconds: NotRequired[int]
    nd_default_router_preference: NotRequired[str]
    nd_ra_suppression: NotRequired[str]
    hosts_address_configuration: NotRequired[str]


class ShowIpv6InterfaceResult(TypedDict):
    """Schema for 'show ipv6 interface' parsed output."""

    interfaces: dict[str, Ipv6InterfaceEntry]


# "GigabitEthernet2 is up, line protocol is up"
_HEADER_RE = re.compile(
    r"^(?P<interface>\S+)\s+is\s+(?P<status>administratively down|up|down|deleted),"
    r"\s+line\s+protocol\s+is\s+(?P<protocol>up|down)\s*$",
    re.IGNORECASE,
)

# "IPv6 is enabled, link-local address is FE80::1 [TEN]"
_LINK_LOCAL_RE = re.compile(
    r"^\s*IPv6 is (?P<ipv6_status>\S+), link-local address is (?P<address>\S+)"
    r"(?:\s+\[(?P<flags>[^\]]+)\])?\s*$"
)

# "2001:db8::1, subnet is 2001:db8::/64 [EUI/TEN]"
_GLOBAL_ADDRESS_RE = re.compile(
    r"^\s+(?P<address>[0-9A-Fa-f:.]+), subnet is "
    r"(?P<subnet>[0-9A-Fa-f:.]+/(?P<prefix>\d+))"
    r"(?:\s+\[(?P<flags>[^\]]+)\])?\s*$"
)

# "Joined group address(es):"
_JOINED_GROUPS_RE = re.compile(r"^\s*Joined group address\(es\):\s*$")

# "    FF02::1"
_GROUP_RE = re.compile(r"^\s+(?P<group>[0-9A-Fa-f:]+)\s*$")

# "ND DAD is enabled, number of DAD attempts: 1" / "ND DAD is not supported"
_ND_DAD_RE = re.compile(
    r"^\s*ND DAD is (?P<state>.+?)(?:, number of DAD attempts: (?P<attempts>\d+))?"
    r"\s*$"
)

# "ND reachable time is 30000 milliseconds (using 30000)"
_ND_REACHABLE_RE = re.compile(
    r"^\s*ND reachable time is (?P<time>\d+) milliseconds"
    r"(?: \(using (?P<using>\d+)\))?\s*$"
)

# Lines with a single integer value
_INT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^\s*MTU is (?P<v>\d+) bytes\s*$"), "mtu"),
    (
        re.compile(
            r"^\s*ICMP error messages limited to one every (?P<v>\d+) milliseconds"
        ),
        "icmp_error_interval_ms",
    ),
    (
        re.compile(r"^\s*ND advertised reachable time is (?P<v>\d+)"),
        "nd_advertised_reachable_time_ms",
    ),
    (
        re.compile(r"^\s*ND advertised retransmit interval is (?P<v>\d+)"),
        "nd_advertised_retransmit_interval_ms",
    ),
    (
        re.compile(r"^\s*ND NS retransmit interval is (?P<v>\d+) milliseconds"),
        "nd_ns_retransmit_interval_ms",
    ),
    (
        re.compile(r"^\s*ND router advertisements are sent every (?P<v>\d+) seconds"),
        "nd_ra_interval_seconds",
    ),
    (
        re.compile(r"^\s*ND router advertisements live for (?P<v>\d+) seconds"),
        "nd_ra_lifetime_seconds",
    ),
)

# Lines with a single string value
_STR_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r'^\s*VPN Routing/Forwarding\s+"(?P<v>[^"]+)"\s*$'), "vrf"),
    (re.compile(r"^\s*ICMP redirects are (?P<v>.+?)\s*$"), "icmp_redirects"),
    (re.compile(r"^\s*ICMP unreachables are (?P<v>.+?)\s*$"), "icmp_unreachables"),
    (
        re.compile(r"^\s*ND advertised default router preference is (?P<v>.+?)\s*$"),
        "nd_default_router_preference",
    ),
    (
        re.compile(r"^\s*ND RAs are suppressed \((?P<v>[^)]+)\)\s*$"),
        "nd_ra_suppression",
    ),
    (
        re.compile(
            r"^\s*Hosts use (?P<v>.+?) (?:for|to obtain routable) addresses\.\s*$"
        ),
        "hosts_address_configuration",
    ),
)


def _flags(raw: str | None) -> list[str] | None:
    return raw.split("/") if raw else None


@register(OS.CISCO_IOSXE, "show ipv6 interface")
class ShowIpv6InterfaceParser(BaseParser[ShowIpv6InterfaceResult]):
    """Parser for 'show ipv6 interface' on IOS-XE.

    Parses per-interface IPv6 addressing, joined multicast groups, ICMP
    behavior, and Neighbor Discovery settings.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @staticmethod
    def _apply_addressing(entry: Ipv6InterfaceEntry, line: str) -> bool:
        m = _LINK_LOCAL_RE.match(line)
        if m:
            entry["ipv6_status"] = m.group("ipv6_status")
            entry["link_local_address"] = m.group("address")
            flags = _flags(m.group("flags"))
            if flags:
                entry["link_local_flags"] = flags
            return True

        m = _GLOBAL_ADDRESS_RE.match(line)
        if m:
            addr = GlobalUnicastAddress(
                subnet=m.group("subnet"), prefix_length=int(m.group("prefix"))
            )
            flags = _flags(m.group("flags"))
            if flags:
                addr["flags"] = flags
            entry.setdefault("global_unicast_addresses", {})[m.group("address")] = addr
            return True

        return False

    @staticmethod
    def _apply_nd(entry: Ipv6InterfaceEntry, line: str) -> bool:
        m = _ND_DAD_RE.match(line)
        if m:
            entry["nd_dad"] = m.group("state")
            if m.group("attempts"):
                entry["nd_dad_attempts"] = int(m.group("attempts"))
            return True

        m = _ND_REACHABLE_RE.match(line)
        if m:
            entry["nd_reachable_time_ms"] = int(m.group("time"))
            if m.group("using"):
                entry["nd_reachable_time_in_use_ms"] = int(m.group("using"))
            return True

        return False

    @staticmethod
    def _apply_table_driven(entry: Ipv6InterfaceEntry, line: str) -> None:
        mutable = cast("dict[str, Any]", entry)
        for pattern, key in _INT_PATTERNS:
            m = pattern.match(line)
            if m:
                mutable[key] = int(m.group("v"))
                return
        for pattern, key in _STR_PATTERNS:
            m = pattern.match(line)
            if m:
                mutable[key] = m.group("v")
                return

    @classmethod
    def _apply_line(cls, entry: Ipv6InterfaceEntry, line: str) -> None:
        if cls._apply_addressing(entry, line) or cls._apply_nd(entry, line):
            return
        cls._apply_table_driven(entry, line)

    @classmethod
    def parse(cls, output: str) -> ShowIpv6InterfaceResult:
        """Parse 'show ipv6 interface' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed interface data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found.
        """
        interfaces: dict[str, Ipv6InterfaceEntry] = {}
        current: Ipv6InterfaceEntry | None = None
        groups: list[str] | None = None

        for line in output.splitlines():
            header = _HEADER_RE.match(line)
            if header:
                name = canonical_interface_name(
                    header.group("interface"), os=OS.CISCO_IOSXE
                )
                current = Ipv6InterfaceEntry(
                    status=header.group("status").lower(),
                    line_protocol=header.group("protocol").lower(),
                )
                interfaces[name] = current
                groups = None
                continue

            if current is None:
                continue

            if _JOINED_GROUPS_RE.match(line):
                groups = current["multicast_groups"] = []
                continue

            group = _GROUP_RE.match(line)
            if group and groups is not None:
                groups.append(group.group("group"))
                continue

            groups = None
            cls._apply_line(current, line)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowIpv6InterfaceResult(interfaces=interfaces)
