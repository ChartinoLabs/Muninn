"""Parser for 'show ip arp' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ArpEntry(TypedDict):
    """Schema for a single ARP entry."""

    interface: str
    age: NotRequired[str]
    mac_address: NotRequired[str]


class ShowIpArpResult(TypedDict):
    """Schema for 'show ip arp' parsed output."""

    arp_entries: dict[str, ArpEntry]


@register(OS.CISCO_NXOS, "show ip arp")
class ShowIpArpParser(BaseParser[ShowIpArpResult]):
    """Parser for 'show ip arp' command on NX-OS.

    Parses ARP table entries showing IP to MAC address mappings.
    """

    # Pattern for ARP table entries
    # Address         Age       MAC Address     Interface
    # 10.2.4.4        00:13:42  5e00.00ff.030a  Ethernet1/1
    # 10.215.51.250      -      0000.0c9f.f9d3  Vlan2515
    # 10.5.6.10       00:00:16  INCOMPLETE      Vlan1425
    _ARP_ENTRY_PATTERN = re.compile(
        r"^(?P<address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"(?P<age>-|\d{2}:\d{2}:\d{2})\s+"
        r"(?P<mac_address>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|INCOMPLETE)\s+"
        r"(?P<interface>\S+)"
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpArpResult:
        """Parse 'show ip arp' output on NX-OS.

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
                mac_address = match.group("mac_address")
                interface = match.group("interface")

                entry: ArpEntry = {
                    "interface": canonical_interface_name(interface),
                }

                # Add age only if not "-" (static entry)
                if age_str != "-":
                    entry["age"] = age_str

                # Add mac_address only if not INCOMPLETE
                if mac_address.upper() != "INCOMPLETE":
                    entry["mac_address"] = mac_address.lower()

                arp_entries[address] = entry

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return ShowIpArpResult(arp_entries=arp_entries)
