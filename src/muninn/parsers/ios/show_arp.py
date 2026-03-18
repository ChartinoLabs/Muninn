"""Parser for 'show arp' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class ArpEntry(TypedDict):
    """Schema for a single ARP entry."""

    hardware_addr: str
    type: str
    age: NotRequired[int]
    interface: NotRequired[str]


class ShowArpResult(TypedDict):
    """Schema for 'show arp' parsed output."""

    arp_entries: dict[str, ArpEntry]


@register(OS.CISCO_IOS, "show arp")
class ShowArpParser(BaseParser[ShowArpResult]):
    """Parser for 'show arp' command.

    Example output:
        Protocol  Address          Age (min)  Hardware Addr   Type   Interface
        Internet  10.1.18.122             -   58bf.eaff.e5b6  ARPA   GigabitEthernet0/0
        Internet  10.1.18.1              45   0012.7fff.04d7  ARPA   GigabitEthernet0/0
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    _ARP_ENTRY_PATTERN = re.compile(
        r"^Internet\s+"
        rf"(?P<address>{IPV4_ADDRESS})\s+"
        r"(?P<age>-|\d+)\s+"
        rf"(?P<hardware_addr>{MAC_ADDRESS})\s+"
        r"(?P<type>\S+)"
        r"(?:\s+(?P<interface>\S+))?",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowArpResult:
        """Parse 'show arp' output.

        Args:
            output: Raw CLI output from 'show arp' command.

        Returns:
            Parsed ARP entries keyed by IP address.

        Raises:
            ValueError: If no ARP entries found.
        """
        arp_entries: dict[str, ArpEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._ARP_ENTRY_PATTERN.match(line)
            if match:
                address = match.group("address")
                age_str = match.group("age")
                hardware_addr = match.group("hardware_addr").lower()
                entry_type = match.group("type")
                interface = match.group("interface")

                entry: ArpEntry = {
                    "hardware_addr": hardware_addr,
                    "type": entry_type,
                }

                if age_str != "-":
                    entry["age"] = int(age_str)

                if interface:
                    entry["interface"] = interface

                arp_entries[address] = entry

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return ShowArpResult(arp_entries=arp_entries)
