"""Parser for 'show ip arp detail vrf all' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class ArpDetailEntry(TypedDict):
    """Schema for a single detailed ARP entry."""

    interface: str
    physical_interface: NotRequired[str]
    age: NotRequired[str]
    mac_address: NotRequired[str]
    flags: NotRequired[str]
    vrf: NotRequired[str]


class ShowIpArpDetailVrfAllResult(TypedDict):
    """Schema for 'show ip arp detail vrf all' parsed output."""

    arp_entries: dict[str, ArpDetailEntry]


_ARP_DETAIL_PATTERN = re.compile(
    rf"^(?P<address>{IPV4_ADDRESS})\s+"
    r"(?P<age>-|\d{2}:\d{2}:\d{2})\s+"
    rf"(?P<mac>{MAC_ADDRESS}|INCOMPLETE)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<physical_interface>\S+)"
    r"(?:\s+(?P<flags>[\*\+\#]+|CP|PS|RO))?"
    r"(?:\s+(?P<vrf>\S+))?$"
)


def _build_entry(match: re.Match[str]) -> ArpDetailEntry:
    """Build an ARP detail entry from a regex match."""
    entry: ArpDetailEntry = {
        "interface": canonical_interface_name(
            match.group("interface"), os=OS.CISCO_NXOS
        ),
    }
    raw_physical = match.group("physical_interface")
    if raw_physical != "-":
        entry["physical_interface"] = canonical_interface_name(
            raw_physical, os=OS.CISCO_NXOS
        )

    age_str = match.group("age")
    if age_str != "-":
        entry["age"] = age_str

    mac = match.group("mac")
    if mac.upper() != "INCOMPLETE":
        entry["mac_address"] = mac.lower()

    flags = match.group("flags")
    if flags:
        entry["flags"] = flags

    vrf = match.group("vrf")
    if vrf:
        entry["vrf"] = vrf

    return entry


@register(OS.CISCO_NXOS, "show ip arp detail vrf all")
class ShowIpArpDetailVrfAllParser(BaseParser[ShowIpArpDetailVrfAllResult]):
    """Parser for 'show ip arp detail vrf all' command on NX-OS.

    Example output:
        10.1.7.1       00:17:15  0012.7fff.04d7  mgmt0    mgmt0
        10.1.3.5          -      aaaa.bbff.8888  Eth1/1   Eth1/1
        192.168.240.59 00:02:40  0cc4.7aee.9c2e  Vlan240  Po1000  +
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    @classmethod
    def parse(cls, output: str) -> ShowIpArpDetailVrfAllResult:
        """Parse 'show ip arp detail vrf all' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed ARP detail entries keyed by IP address.

        Raises:
            ValueError: If no ARP entries found.
        """
        arp_entries: dict[str, ArpDetailEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _ARP_DETAIL_PATTERN.match(line)
            if match:
                arp_entries[match.group("address")] = _build_entry(match)

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return ShowIpArpDetailVrfAllResult(arp_entries=arp_entries)
