"""Parser for 'show arp' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class ArpEntry(TypedDict):
    """Schema for a single ARP entry."""

    interface: str
    mac_address: str
    age: int


class ShowArpResult(TypedDict):
    """Schema for 'show arp' parsed output keyed by IP address."""

    arp_entries: dict[str, ArpEntry]


@register(OS.CISCO_FTD, "show arp")
class ShowArpParser(BaseParser[ShowArpResult]):
    """Parser for 'show arp' command on Cisco FTD.

    Parses ARP table entries showing IP to MAC address mappings
    with interface nameif and age in seconds.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    # Pattern for ARP table entries on FTD
    # <interface> <ip_address> <mac_address> <age_seconds>
    # HA 192.168.1.2 b2c3.d4e5.f601 610
    # Inside 172.16.1.3 b2c3.d4e5.f602 363
    _ARP_ENTRY_PATTERN = re.compile(
        r"^\s*(?P<interface>\S+)\s+"
        rf"(?P<address>{IPV4_ADDRESS})\s+"
        rf"(?P<mac_address>{MAC_ADDRESS})\s+"
        r"(?P<age>\d+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowArpResult:
        """Parse 'show arp' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed ARP entries keyed by IP address.

        Raises:
            ValueError: If no ARP entries found.
        """
        arp_entries: dict[str, ArpEntry] = {}

        for line in output.splitlines():
            if not line.strip():
                continue

            match = cls._ARP_ENTRY_PATTERN.match(line)
            if match:
                address = match.group("address")
                arp_entries[address] = ArpEntry(
                    interface=match.group("interface"),
                    mac_address=match.group("mac_address").lower(),
                    age=int(match.group("age")),
                )

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return ShowArpResult(arp_entries=arp_entries)
