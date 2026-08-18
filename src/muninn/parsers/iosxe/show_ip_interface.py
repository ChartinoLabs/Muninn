"""Parser for 'show ip interface' command on IOS and IOS-XE."""

import re
from typing import Any, ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceEntry(TypedDict):
    """Schema for a single interface entry from 'show ip interface'."""

    status: str
    line_protocol: str
    vrf: NotRequired[str]
    ip_address: NotRequired[str]
    prefix_length: NotRequired[int]
    broadcast_address: NotRequired[str]
    address_determined_by: NotRequired[str]
    mtu: NotRequired[int]
    helper_addresses: list[str]
    directed_broadcast_forwarding: NotRequired[bool]
    multicast_groups: list[str]
    outgoing_common_access_list: NotRequired[str]
    outgoing_access_list: NotRequired[str]
    inbound_common_access_list: NotRequired[str]
    inbound_access_list: NotRequired[str]
    proxy_arp: NotRequired[bool]
    local_proxy_arp: NotRequired[bool]
    security_level: NotRequired[str]
    split_horizon: NotRequired[bool]
    icmp_redirects: NotRequired[str]
    icmp_unreachables: NotRequired[str]
    icmp_mask_replies: NotRequired[str]
    ip_fast_switching: NotRequired[bool]
    ip_flow_switching: NotRequired[bool]
    ip_cef_switching: NotRequired[bool]
    ip_multicast_fast_switching: NotRequired[bool]
    ip_multicast_distributed_fast_switching: NotRequired[bool]
    router_discovery: NotRequired[bool]
    ip_output_packet_accounting: NotRequired[bool]
    ip_access_violation_accounting: NotRequired[bool]
    tcp_ip_header_compression: NotRequired[bool]
    rtp_ip_header_compression: NotRequired[bool]
    probe_proxy_name_replies: NotRequired[bool]
    policy_routing: NotRequired[bool]
    network_address_translation: NotRequired[bool]
    bgp_policy_mapping: NotRequired[bool]
    input_features: list[str]
    ipv4_wccp_redirect_outbound: NotRequired[bool]
    ipv4_wccp_redirect_inbound: NotRequired[bool]
    ipv4_wccp_redirect_exclude: NotRequired[bool]
    ip_clear_dont_fragment: NotRequired[bool]


class ShowIpInterfaceResult(TypedDict):
    """Schema for 'show ip interface' parsed output."""

    interfaces: dict[str, InterfaceEntry]


# "GigabitEthernet2 is up, line protocol is up"
_HEADER_RE = re.compile(
    r"^(?P<interface>\S+)\s+is\s+(?P<status>administratively down|up|down|deleted),"
    r"\s+line\s+protocol\s+is\s+(?P<protocol>up|down)\s*$",
    re.IGNORECASE,
)

# "  Internet address is 10.12.0.1/30"
_INTERNET_ADDRESS_RE = re.compile(
    rf"^\s*Internet address is (?P<ip>{IPV4_ADDRESS})/(?P<prefix>\d{{1,2}})\s*$"
)

# "  Broadcast address is 255.255.255.255"
_BROADCAST_ADDRESS_RE = re.compile(
    rf"^\s*Broadcast address is (?P<addr>{IPV4_ADDRESS})\s*$"
)

# "  Address determined by non-volatile memory"
_ADDRESS_DETERMINED_BY_RE = re.compile(r"^\s*Address determined by (?P<source>.+?)\s*$")

# "  MTU is 1500 bytes"
_MTU_RE = re.compile(r"^\s*MTU is (?P<mtu>\d+) bytes\s*$")

# "  Helper address is not set" or "  Helper address is 10.0.0.1" (may repeat)
_HELPER_ADDRESS_RE = re.compile(
    rf"^\s*Helper address is (?P<addr>not set|{IPV4_ADDRESS})\s*$"
)

# "  Directed broadcast forwarding is disabled"
_DIRECTED_BCAST_RE = re.compile(
    r"^\s*Directed broadcast forwarding is (?P<state>enabled|disabled)\s*$"
)

# "  Multicast reserved groups joined: 224.0.0.5 224.0.0.6"
_MULTICAST_GROUPS_RE = re.compile(
    r"^\s*Multicast reserved groups joined:\s*(?P<groups>.*)$"
)

# '  VPN Routing/Forwarding "RED"'
_VRF_RE = re.compile(r'^\s*VPN Routing/Forwarding\s+"(?P<vrf>[^"]+)"\s*$')

# ACL lines: "  Outgoing access list is not set" / "... is FOO"
_ACL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^\s*Outgoing Common access list is (?P<value>.+?)\s*$"),
        "outgoing_common_access_list",
    ),
    (
        re.compile(r"^\s*Outgoing access list is (?P<value>.+?)\s*$"),
        "outgoing_access_list",
    ),
    (
        re.compile(r"^\s*Inbound Common access list is (?P<value>.+?)\s*$"),
        "inbound_common_access_list",
    ),
    (
        re.compile(r"^\s*Inbound\s+access list is (?P<value>.+?)\s*$"),
        "inbound_access_list",
    ),
)

# "  Security level is default"
_SECURITY_LEVEL_RE = re.compile(r"^\s*Security level is (?P<level>.+?)\s*$")

# ICMP lines: "  ICMP redirects are always sent"
_ICMP_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^\s*ICMP redirects are (?P<value>.+?)\s*$"),
        "icmp_redirects",
    ),
    (
        re.compile(r"^\s*ICMP unreachables are (?P<value>.+?)\s*$"),
        "icmp_unreachables",
    ),
    (
        re.compile(r"^\s*ICMP mask replies are (?P<value>.+?)\s*$"),
        "icmp_mask_replies",
    ),
)

# Boolean lines matching "<label> is enabled|disabled"
_BOOLEAN_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^\s*Proxy ARP is (?P<state>enabled|disabled)\s*$"),
        "proxy_arp",
    ),
    (
        re.compile(r"^\s*Local Proxy ARP is (?P<state>enabled|disabled)\s*$"),
        "local_proxy_arp",
    ),
    (
        re.compile(r"^\s*Split horizon is (?P<state>enabled|disabled)\s*$"),
        "split_horizon",
    ),
    (
        re.compile(r"^\s*IP fast switching is (?P<state>enabled|disabled)\s*$"),
        "ip_fast_switching",
    ),
    (
        re.compile(r"^\s*IP Flow switching is (?P<state>enabled|disabled)\s*$"),
        "ip_flow_switching",
    ),
    (
        re.compile(r"^\s*IP CEF switching is (?P<state>enabled|disabled)\s*$"),
        "ip_cef_switching",
    ),
    (
        re.compile(
            r"^\s*IP multicast fast switching is (?P<state>enabled|disabled)\s*$"
        ),
        "ip_multicast_fast_switching",
    ),
    (
        re.compile(
            r"^\s*IP multicast distributed fast switching is "
            r"(?P<state>enabled|disabled)\s*$"
        ),
        "ip_multicast_distributed_fast_switching",
    ),
    (
        re.compile(r"^\s*Router Discovery is (?P<state>enabled|disabled)\s*$"),
        "router_discovery",
    ),
    (
        re.compile(
            r"^\s*IP output packet accounting is (?P<state>enabled|disabled)\s*$"
        ),
        "ip_output_packet_accounting",
    ),
    (
        re.compile(
            r"^\s*IP access violation accounting is (?P<state>enabled|disabled)\s*$"
        ),
        "ip_access_violation_accounting",
    ),
    (
        re.compile(r"^\s*TCP/IP header compression is (?P<state>enabled|disabled)\s*$"),
        "tcp_ip_header_compression",
    ),
    (
        re.compile(r"^\s*RTP/IP header compression is (?P<state>enabled|disabled)\s*$"),
        "rtp_ip_header_compression",
    ),
    (
        re.compile(r"^\s*Probe proxy name replies are (?P<state>enabled|disabled)\s*$"),
        "probe_proxy_name_replies",
    ),
    (
        re.compile(r"^\s*Policy routing is (?P<state>enabled|disabled)\s*$"),
        "policy_routing",
    ),
    (
        re.compile(
            r"^\s*Network address translation is (?P<state>enabled|disabled)\s*$"
        ),
        "network_address_translation",
    ),
    (
        re.compile(r"^\s*BGP Policy Mapping is (?P<state>enabled|disabled)\s*$"),
        "bgp_policy_mapping",
    ),
    (
        re.compile(
            r"^\s*IPv4 WCCP Redirect outbound is (?P<state>enabled|disabled)\s*$"
        ),
        "ipv4_wccp_redirect_outbound",
    ),
    (
        re.compile(
            r"^\s*IPv4 WCCP Redirect inbound is (?P<state>enabled|disabled)\s*$"
        ),
        "ipv4_wccp_redirect_inbound",
    ),
    (
        re.compile(
            r"^\s*IPv4 WCCP Redirect exclude is (?P<state>enabled|disabled)\s*$"
        ),
        "ipv4_wccp_redirect_exclude",
    ),
    (
        re.compile(r"^\s*IP Clear Dont Fragment is (?P<state>enabled|disabled)\s*$"),
        "ip_clear_dont_fragment",
    ),
)

# "  Input features: MCI Check, TCP Adjust MSS"
_INPUT_FEATURES_RE = re.compile(r"^\s*Input features:\s*(?P<features>.+?)\s*$")


@register(OS.CISCO_IOS, "show ip interface")
@register(OS.CISCO_IOSXE, "show ip interface")
class ShowIpInterfaceParser(BaseParser[ShowIpInterfaceResult]):
    """Parser for 'show ip interface' command.

    Parses per-interface IP configuration details including IP MTU,
    addressing, ACLs, ICMP behavior, and feature states.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @staticmethod
    def _new_entry(status: str, protocol: str) -> InterfaceEntry:
        return InterfaceEntry(
            status=status,
            line_protocol=protocol,
            helper_addresses=[],
            multicast_groups=[],
            input_features=[],
        )

    @staticmethod
    def _apply_addressing(entry: InterfaceEntry, line: str) -> bool:
        m = _INTERNET_ADDRESS_RE.match(line)
        if m:
            entry["ip_address"] = m.group("ip")
            entry["prefix_length"] = int(m.group("prefix"))
            return True

        m = _BROADCAST_ADDRESS_RE.match(line)
        if m:
            entry["broadcast_address"] = m.group("addr")
            return True

        m = _ADDRESS_DETERMINED_BY_RE.match(line)
        if m:
            entry["address_determined_by"] = m.group("source")
            return True

        m = _MTU_RE.match(line)
        if m:
            entry["mtu"] = int(m.group("mtu"))
            return True

        m = _HELPER_ADDRESS_RE.match(line)
        if m:
            addr = m.group("addr")
            if addr != "not set":
                entry["helper_addresses"].append(addr)
            return True

        return False

    @staticmethod
    def _apply_scalars(entry: InterfaceEntry, line: str) -> bool:
        m = _DIRECTED_BCAST_RE.match(line)
        if m:
            entry["directed_broadcast_forwarding"] = m.group("state") == "enabled"
            return True

        m = _MULTICAST_GROUPS_RE.match(line)
        if m:
            groups = m.group("groups").strip()
            if groups:
                entry["multicast_groups"].extend(groups.split())
            return True

        m = _VRF_RE.match(line)
        if m:
            entry["vrf"] = m.group("vrf")
            return True

        m = _SECURITY_LEVEL_RE.match(line)
        if m:
            entry["security_level"] = m.group("level")
            return True

        m = _INPUT_FEATURES_RE.match(line)
        if m:
            features = [f.strip() for f in m.group("features").split(",") if f.strip()]
            entry["input_features"].extend(features)
            return True

        return False

    @staticmethod
    def _apply_table_driven(entry: InterfaceEntry, line: str) -> bool:
        mutable = cast("dict[str, Any]", entry)

        for pattern, key in _ACL_PATTERNS:
            m = pattern.match(line)
            if m:
                value = m.group("value")
                if value != "not set":
                    mutable[key] = value
                return True

        for pattern, key in _ICMP_PATTERNS:
            m = pattern.match(line)
            if m:
                mutable[key] = m.group("value")
                return True

        for pattern, key in _BOOLEAN_PATTERNS:
            m = pattern.match(line)
            if m:
                mutable[key] = m.group("state") == "enabled"
                return True

        return False

    @classmethod
    def _apply_line(cls, entry: InterfaceEntry, line: str) -> None:
        """Match a single line against all known patterns and update entry."""
        if cls._apply_addressing(entry, line):
            return
        if cls._apply_scalars(entry, line):
            return
        cls._apply_table_driven(entry, line)

    @classmethod
    def parse(cls, output: str) -> ShowIpInterfaceResult:
        """Parse 'show ip interface' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed interface data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found.
        """
        interfaces: dict[str, InterfaceEntry] = {}
        current: InterfaceEntry | None = None

        for raw_line in output.splitlines():
            header = _HEADER_RE.match(raw_line)
            if header:
                name = canonical_interface_name(
                    header.group("interface"), os=OS.CISCO_IOSXE
                )
                current = cls._new_entry(
                    header.group("status").lower(),
                    header.group("protocol").lower(),
                )
                interfaces[name] = current
                continue

            if current is None:
                continue

            cls._apply_line(current, raw_line)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowIpInterfaceResult(interfaces=interfaces)
