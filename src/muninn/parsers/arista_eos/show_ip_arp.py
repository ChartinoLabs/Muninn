"""Parser for 'show ip arp' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class ArpEntry(TypedDict):
    """Schema for a single ARP entry."""

    mac_address: str
    age: str
    interface: str


class ShowIpArpResult(TypedDict):
    """Schema for 'show ip arp' parsed output on Arista EOS."""

    arp_entries: dict[str, ArpEntry]


@register(OS.ARISTA_EOS, "show ip arp")
class ShowIpArpParser(BaseParser[ShowIpArpResult]):
    """Parser for 'show ip arp' command on Arista EOS.

    Parses ARP table entries showing IP to MAC address mappings.
    Supports output with and without VRF headers, and both
    ``Age (min)`` and ``Age (sec)`` column formats.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    # VRF header line, e.g. "VRF: MGMT" or "VRF: default"
    _VRF_HEADER = re.compile(r"^VRF:\s+\S+")

    # ARP entry line.  The interface column may contain a comma-separated
    # qualifier (e.g. "Vlan101, Port-Channel2" or "Vlan1, not learned"),
    # so we capture everything after the MAC address.
    #
    # Examples:
    #   172.25.0.2           0 004c.6211.021e Vlan101, Port-Channel2
    #   10.1.1.1       0:00:00 004c.6211.113e Vlan1
    #   10.10.1.1          N/A 0002.00ff.0001 Vlan1, not learned
    _ARP_ENTRY_PATTERN = re.compile(
        rf"^(?P<address>{IPV4_ADDRESS})\s+"
        r"(?P<age>N/A|\d+(?::\d{2}:\d{2})?)\s+"
        rf"(?P<mac_address>{MAC_ADDRESS})\s+"
        r"(?P<interface>.+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpArpResult:
        """Parse 'show ip arp' output on Arista EOS.

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
                age = match.group("age")
                mac_address = match.group("mac_address").lower()
                interface = match.group("interface").strip()

                entry: ArpEntry = {
                    "mac_address": mac_address,
                    "age": age,
                    "interface": interface,
                }

                arp_entries[address] = entry

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return cast(ShowIpArpResult, {"arp_entries": arp_entries})
