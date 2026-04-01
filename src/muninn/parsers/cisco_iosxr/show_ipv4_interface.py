"""Parser for 'show ipv4 interface' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IPv4InterfaceEntry(TypedDict, total=False):
    """Schema for a single interface entry in 'show ipv4 interface' output.

    All fields except interface_status and protocol_status are optional
    because shutdown interfaces may only show VRF and
    "Internet protocol processing disabled".
    """

    interface_status: str
    protocol_status: str
    vrf: str
    vrf_id: str
    ip_address: str
    prefix_length: int
    mtu: int
    ip_mtu: int
    proxy_arp: bool
    icmp_redirects: str
    icmp_unreachables: str
    icmp_mask_replies: str
    directed_broadcast: bool
    table_id: str
    multicast_groups: list[str]
    outgoing_access_list: str
    inbound_access_list: str
    helper_address: str


class ShowIPv4InterfaceResult(TypedDict):
    """Schema for 'show ipv4 interface' parsed output.

    Dict-of-dicts keyed by canonical interface name.
    """

    interfaces: dict[str, IPv4InterfaceEntry]


@register(OS.CISCO_IOSXR, "show ipv4 interface")
class ShowIPv4InterfaceParser(BaseParser[ShowIPv4InterfaceResult]):
    """Parser for 'show ipv4 interface' command on Cisco IOS-XR.

    Parses per-interface IPv4 configuration and status information into
    a dict-of-dicts keyed by canonical interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Header line: "GigabitEthernet0/0/0/0 is Up, ipv4 protocol is Up"
    _INTF_HEADER = re.compile(
        r"^(?P<name>\S+)\s+is\s+(?P<status>\S+),\s+"
        r"ipv4\s+protocol\s+is\s+(?P<proto>\S+)\s*$",
        re.IGNORECASE,
    )

    _VRF = re.compile(
        r"^\s+Vrf\s+is\s+(?P<vrf>\S+)\s+\(vrfid\s+(?P<vrfid>\S+)\)",
        re.IGNORECASE,
    )

    _ADDRESS = re.compile(
        r"^\s+Internet\s+address\s+is\s+(?P<ip>\S+)/(?P<prefix>\d+)",
        re.IGNORECASE,
    )

    _MTU = re.compile(
        r"^\s+MTU\s+is\s+(?P<mtu>\d+)\s+\((?P<ip_mtu>\d+)\s+is\s+available",
        re.IGNORECASE,
    )

    _HELPER = re.compile(
        r"^\s+Helper\s+address\s+is\s+(?P<helper>.+)$",
        re.IGNORECASE,
    )

    _MULTICAST = re.compile(
        r"^\s+Multicast\s+reserved\s+groups\s+joined:\s*(?P<groups>.+)$",
        re.IGNORECASE,
    )

    _MULTICAST_CONT = re.compile(
        r"^\s{6,}(?P<groups>[\d.]+(?:\s+[\d.]+)*)$",
    )

    _DIRECTED_BROADCAST = re.compile(
        r"^\s+Directed\s+broadcast\s+forwarding\s+is\s+(?P<state>\S+)",
        re.IGNORECASE,
    )

    _OUT_ACL = re.compile(
        r"^\s+Outgoing\s+access\s+list\s+is\s+(?P<acl>.+)$",
        re.IGNORECASE,
    )

    _IN_ACL = re.compile(
        r"^\s+Inbound\s+(?:common\s+)?access\s+list\s+is\s+(?P<common>.+?),"
        r"\s+access\s+list\s+is\s+(?P<acl>.+)$",
        re.IGNORECASE,
    )

    _IN_ACL_SIMPLE = re.compile(
        r"^\s+Inbound\s+access\s+list\s+is\s+(?P<acl>.+)$",
        re.IGNORECASE,
    )

    _PROXY_ARP = re.compile(
        r"^\s+Proxy\s+ARP\s+is\s+(?P<state>\S+)",
        re.IGNORECASE,
    )

    _ICMP_REDIRECTS = re.compile(
        r"^\s+ICMP\s+redirects\s+are\s+(?P<state>.+)$",
        re.IGNORECASE,
    )

    _ICMP_UNREACHABLES = re.compile(
        r"^\s+ICMP\s+unreachables\s+are\s+(?P<state>.+)$",
        re.IGNORECASE,
    )

    _ICMP_MASK = re.compile(
        r"^\s+ICMP\s+mask\s+replies\s+are\s+(?P<state>.+)$",
        re.IGNORECASE,
    )

    _TABLE_ID = re.compile(
        r"^\s+Table\s+Id\s+is\s+(?P<id>\S+)",
        re.IGNORECASE,
    )

    _NOT_SET = "not set"

    @classmethod
    def parse(cls, output: str) -> ShowIPv4InterfaceResult:
        """Parse 'show ipv4 interface' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IPv4 interface information keyed by interface name.

        Raises:
            ValueError: If no interface entries can be parsed from the output.
        """
        interfaces: dict[str, IPv4InterfaceEntry] = {}
        current: IPv4InterfaceEntry | None = None
        current_name: str | None = None
        collecting_multicast = False

        for line in output.splitlines():
            # Check for interface header line
            header = cls._INTF_HEADER.match(line)
            if header:
                current = IPv4InterfaceEntry(
                    interface_status=header.group("status"),
                    protocol_status=header.group("proto"),
                )
                current_name = canonical_interface_name(
                    header.group("name"), os=OS.CISCO_IOSXR
                )
                interfaces[current_name] = current
                collecting_multicast = False
                continue

            if current is None:
                continue

            # Multicast continuation lines (indented IP addresses)
            if collecting_multicast:
                mc_cont = cls._MULTICAST_CONT.match(line)
                if mc_cont:
                    current.setdefault("multicast_groups", []).extend(
                        mc_cont.group("groups").split()
                    )
                    continue
                collecting_multicast = False

            cls._parse_detail_line(line, current)

            # Check if this line started multicast collection
            mc = cls._MULTICAST.match(line)
            if mc:
                collecting_multicast = True

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return cast(ShowIPv4InterfaceResult, {"interfaces": interfaces})

    @classmethod
    def _parse_detail_line(cls, line: str, entry: IPv4InterfaceEntry) -> None:
        """Parse a single detail line within an interface block."""
        parsers = (
            cls._try_parse_vrf,
            cls._try_parse_address,
            cls._try_parse_mtu,
            cls._try_parse_helper,
            cls._try_parse_multicast,
            cls._try_parse_forwarding,
            cls._try_parse_acl,
            cls._try_parse_icmp,
            cls._try_parse_table_id,
        )
        for parser_fn in parsers:
            if parser_fn(line, entry):
                return

    @classmethod
    def _try_parse_vrf(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse VRF line. Returns True if matched."""
        m = cls._VRF.match(line)
        if not m:
            return False
        entry["vrf"] = m.group("vrf")
        entry["vrf_id"] = m.group("vrfid")
        return True

    @classmethod
    def _try_parse_address(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse IP address line. Returns True if matched."""
        m = cls._ADDRESS.match(line)
        if not m:
            return False
        entry["ip_address"] = m.group("ip")
        entry["prefix_length"] = int(m.group("prefix"))
        return True

    @classmethod
    def _try_parse_mtu(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse MTU line. Returns True if matched."""
        m = cls._MTU.match(line)
        if not m:
            return False
        entry["mtu"] = int(m.group("mtu"))
        entry["ip_mtu"] = int(m.group("ip_mtu"))
        return True

    @classmethod
    def _try_parse_helper(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse helper address line. Returns True if matched."""
        m = cls._HELPER.match(line)
        if not m:
            return False
        value = m.group("helper").strip()
        if value.lower() != cls._NOT_SET:
            entry["helper_address"] = value
        return True

    @classmethod
    def _try_parse_multicast(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse multicast groups line. Returns True if matched."""
        m = cls._MULTICAST.match(line)
        if not m:
            return False
        entry["multicast_groups"] = m.group("groups").split()
        return True

    @classmethod
    def _try_parse_forwarding(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse directed broadcast and proxy ARP. Returns True if matched."""
        m = cls._DIRECTED_BROADCAST.match(line)
        if m:
            entry["directed_broadcast"] = m.group("state").lower() == "enabled"
            return True
        m = cls._PROXY_ARP.match(line)
        if m:
            entry["proxy_arp"] = m.group("state").lower() == "enabled"
            return True
        return False

    @classmethod
    def _try_parse_acl(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse ACL lines. Returns True if matched."""
        m = cls._OUT_ACL.match(line)
        if m:
            value = m.group("acl").strip()
            if value.lower() != cls._NOT_SET:
                entry["outgoing_access_list"] = value
            return True
        m = cls._IN_ACL.match(line)
        if m:
            acl_value = m.group("acl").strip()
            if acl_value.lower() != cls._NOT_SET:
                entry["inbound_access_list"] = acl_value
            return True
        m = cls._IN_ACL_SIMPLE.match(line)
        if m:
            acl_value = m.group("acl").strip()
            if acl_value.lower() != cls._NOT_SET:
                entry["inbound_access_list"] = acl_value
            return True
        return False

    @classmethod
    def _try_parse_icmp(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse ICMP settings lines. Returns True if matched."""
        m = cls._ICMP_REDIRECTS.match(line)
        if m:
            entry["icmp_redirects"] = m.group("state").strip()
            return True
        m = cls._ICMP_UNREACHABLES.match(line)
        if m:
            entry["icmp_unreachables"] = m.group("state").strip()
            return True
        m = cls._ICMP_MASK.match(line)
        if m:
            entry["icmp_mask_replies"] = m.group("state").strip()
            return True
        return False

    @classmethod
    def _try_parse_table_id(cls, line: str, entry: IPv4InterfaceEntry) -> bool:
        """Try to parse table ID line. Returns True if matched."""
        m = cls._TABLE_ID.match(line)
        if not m:
            return False
        entry["table_id"] = m.group("id")
        return True
