"""Parser for 'show arp no-resolve' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS_COLON
from muninn.registry import register
from muninn.tags import ParserTag


class ArpEntry(TypedDict):
    """Schema for a single ARP entry from 'show arp no-resolve'."""

    mac_address: str
    interface: str
    flags: NotRequired[str]


class ShowArpNoResolveResult(TypedDict):
    """Schema for 'show arp no-resolve' parsed output.

    ARP entries are keyed by IP address.
    """

    arp_entries: dict[str, ArpEntry]


@register(OS.JUNIPER_JUNOS, "show arp no-resolve")
class ShowArpNoResolveParser(BaseParser[ShowArpNoResolveResult]):
    """Parser for 'show arp no-resolve' command on Juniper Junos.

    Parses ARP table entries containing MAC address, IP address, interface,
    and flags. The output does not include hostname resolution.

    Example output::

        MAC Address       Address         Interface     Flags
        00:50:56:ff:ba:6f 10.1.0.1         fxp0.0        none
        00:50:56:ff:8b:e0 10.1.0.201       fxp0.0        none
        Total entries: 7
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    _ARP_ENTRY = re.compile(
        rf"^\s*(?P<mac>{MAC_ADDRESS_COLON})\s+"
        rf"(?P<ip>{IPV4_ADDRESS})\s+"
        r"(?P<interface>\S+)\s+"
        r"(?P<flags>\S+)\s*$",
    )

    @classmethod
    def parse(cls, output: str) -> ShowArpNoResolveResult:
        """Parse 'show arp no-resolve' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed ARP entries keyed by IP address.

        Raises:
            ValueError: If no ARP entries are found in the output.
        """
        arp_entries: dict[str, ArpEntry] = {}

        for line in output.splitlines():
            match = cls._ARP_ENTRY.match(line)
            if not match:
                continue

            ip_address = match.group("ip")
            flags = match.group("flags")
            entry = ArpEntry(
                mac_address=match.group("mac").lower(),
                interface=match.group("interface"),
            )
            if flags.lower() != "none":
                entry["flags"] = flags
            arp_entries[ip_address] = entry

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return cast(ShowArpNoResolveResult, {"arp_entries": arp_entries})
