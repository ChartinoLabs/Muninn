"""Parser for 'show arp' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class ArpEntry(TypedDict):
    """Schema for a single ARP entry."""

    age: NotRequired[str]
    mac_address: str
    state: str
    type: str
    interface: str


class ShowArpResult(TypedDict):
    """Schema for 'show arp' parsed output on Cisco IOS-XR."""

    arp_entries: dict[str, ArpEntry]


@register(OS.CISCO_IOSXR, "show arp")
class ShowArpParser(BaseParser[ShowArpResult]):
    """Parser for 'show arp' command on Cisco IOS-XR.

    Parses ARP table entries showing IP-to-MAC address mappings.
    Output may contain multiple line-card sections (e.g. ``0/0/CPU0``,
    ``0/1/CPU0``), each with its own header row.  All entries across
    sections are merged into a single dict keyed by IP address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    # ARP entry line.
    # Examples:
    #   10.10.10.1    -        5254.0001.9002  Interface  ARPA  Gi0/0/0/0
    #   10.10.10.101  01:25:23 aabb.cc00.6500  Dynamic    ARPA  Gi0/0/0/0
    _ARP_ENTRY_PATTERN = re.compile(
        rf"^(?P<address>{IPV4_ADDRESS})\s+"
        r"(?P<age>-|\d{2}:\d{2}:\d{2})\s+"
        rf"(?P<mac_address>{MAC_ADDRESS})\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<interface>\S+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowArpResult:
        """Parse 'show arp' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed ARP entries keyed by IP address.

        Raises:
            ValueError: If no ARP entries found.
        """
        arp_entries: dict[str, ArpEntry] = {}

        for line in output.splitlines():
            match = cls._ARP_ENTRY_PATTERN.match(line.strip())
            if not match:
                continue

            address = match.group("address")
            raw_age = match.group("age")

            entry: ArpEntry = {
                "mac_address": match.group("mac_address").lower(),
                "state": match.group("state"),
                "type": match.group("type"),
                "interface": canonical_interface_name(
                    match.group("interface"), os=OS.CISCO_IOSXR
                ),
            }
            if raw_age != "-":
                entry["age"] = raw_age

            arp_entries[address] = entry

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return cast(ShowArpResult, {"arp_entries": arp_entries})
