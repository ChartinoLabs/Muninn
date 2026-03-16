"""Parser for 'show ip arp' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ArpEntry(TypedDict):
    """Schema for a single ARP entry."""

    hardware_addr: str
    type: str
    age: NotRequired[int]
    interface: NotRequired[str]


class ShowIpArpResult(TypedDict):
    """Schema for 'show ip arp' parsed output."""

    arp_entries: dict[str, ArpEntry]


@register(OS.CISCO_IOS, "show ip arp")
@register(OS.CISCO_IOSXE, "show ip arp")
class ShowIpArpParser(BaseParser[ShowIpArpResult]):
    """Parser for 'show ip arp' command.

    Parses ARP table entries showing IP to MAC address mappings.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"arp"})

    # Pattern for ARP table entries
    # Protocol  Address          Age (min)  Hardware Addr   Type   Interface
    # Internet  10.1.8.1               79   0012.7fff.04d7  ARPA   FastEthernet0
    _ARP_ENTRY_PATTERN = re.compile(
        r"^Internet\s+"
        r"(?P<address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"(?P<age>-|\d+)\s+"
        r"(?P<hardware_addr>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(?P<type>\S+)"
        r"(?:\s+(?P<interface>\S+))?",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpArpResult:
        """Parse 'show ip arp' output.

        Args:
            output: Raw CLI output from command.

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

                # Add age only if not "-" (local entry)
                if age_str != "-":
                    entry["age"] = int(age_str)

                if interface:
                    entry["interface"] = interface

                arp_entries[address] = entry

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return ShowIpArpResult(arp_entries=arp_entries)
