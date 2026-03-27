"""Parser for 'show arp all' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ArpEntry(TypedDict):
    """Schema for a single ARP table entry."""

    interface: str
    ip_address: str
    mac_address: str
    port: str
    status: str
    ttl: int
    status_description: NotRequired[str]


ShowArpAllResult = dict[str, ArpEntry]

# Map single-character status codes to human-readable descriptions
_STATUS_MAP: dict[str, str] = {
    "s": "static",
    "c": "complete",
    "e": "expiring",
    "i": "incomplete",
}


@register(OS.PALOALTO_PANOS, "show arp all")
class ShowArpAllParser(BaseParser[ShowArpAllResult]):
    """Parser for 'show arp all' command on Palo Alto PAN-OS.

    Parses the tabular ARP output into a dictionary keyed by IP address,
    with each value containing interface, MAC address, port, status, and TTL.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ARP,
        }
    )

    _ARP_LINE = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|\(incomplete\))\s+"
        r"(?P<port>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<ttl>\d+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowArpAllResult:
        """Parse 'show arp all' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dictionary keyed by IP address with ARP entry details.

        Raises:
            ValueError: If no valid ARP entries are found in the output.
        """
        result: dict[str, ArpEntry] = {}

        for line in output.splitlines():
            match = cls._ARP_LINE.match(line.strip())
            if not match:
                continue

            ip_address = match.group("ip")
            raw_mac = match.group("mac")
            # Strip parentheses from "(incomplete)" to normalize
            mac_address = raw_mac.strip("()")
            status_code = match.group("status")

            entry: ArpEntry = {
                "interface": match.group("interface"),
                "ip_address": ip_address,
                "mac_address": mac_address,
                "port": match.group("port"),
                "status": status_code,
                "ttl": int(match.group("ttl")),
            }

            description = _STATUS_MAP.get(status_code)
            if description is not None:
                entry["status_description"] = description

            result[ip_address] = entry

        if not result:
            msg = "No valid ARP entries found in output"
            raise ValueError(msg)

        return cast(ShowArpAllResult, result)
