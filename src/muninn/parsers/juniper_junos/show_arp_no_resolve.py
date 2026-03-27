"""Parser for 'show arp no-resolve' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Colon-delimited MAC address pattern (aa:bb:cc:dd:ee:ff)
_MAC_COLON = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"

# Dotted-decimal IPv4 address
_IPV4 = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"


class ArpEntry(TypedDict):
    """Schema for a single ARP entry from 'show arp no-resolve'."""

    mac_address: str
    interface: str
    flags: str


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
        rf"^\s*(?P<mac>{_MAC_COLON})\s+"
        rf"(?P<ip>{_IPV4})\s+"
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
            arp_entries[ip_address] = ArpEntry(
                mac_address=match.group("mac").lower(),
                interface=match.group("interface"),
                flags=match.group("flags"),
            )

        if not arp_entries:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return cast(ShowArpNoResolveResult, {"arp_entries": arp_entries})
