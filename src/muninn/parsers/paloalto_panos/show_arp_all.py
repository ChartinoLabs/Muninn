"""Parser for 'show arp all' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS_COLON
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


class ShowArpAllResult(TypedDict):
    """Schema for 'show arp all' parsed output."""

    max_entries: int
    default_timeout: int
    total_entries: int
    total_entries_shown: int
    entries: dict[str, ArpEntry]


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
        rf"(?P<ip>{IPV4_ADDRESS})\s+"
        rf"(?P<mac>{MAC_ADDRESS_COLON}|\(incomplete\))\s+"
        r"(?P<port>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<ttl>\d+)\s*$"
    )

    _HEADER_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        "max_entries": re.compile(
            r"maximum of entries supported\s*:\s*(\d+)", re.IGNORECASE
        ),
        "default_timeout": re.compile(r"default timeout\s*:\s*(\d+)", re.IGNORECASE),
        "total_entries": re.compile(
            r"total ARP entries in table\s*:\s*(\d+)", re.IGNORECASE
        ),
        "total_entries_shown": re.compile(
            r"total ARP entries shown\s*:\s*(\d+)", re.IGNORECASE
        ),
    }

    @classmethod
    def parse(cls, output: str) -> ShowArpAllResult:
        """Parse 'show arp all' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dictionary with header metadata and entries keyed by IP address.

        Raises:
            ValueError: If no valid ARP entries are found in the output.
        """
        entries: dict[str, ArpEntry] = {}
        header: dict[str, int] = {}

        for line in output.splitlines():
            stripped = line.strip()

            # Try header patterns
            for key, pattern in cls._HEADER_PATTERNS.items():
                header_match = pattern.search(stripped)
                if header_match:
                    header[key] = int(header_match.group(1))
                    break

            match = cls._ARP_LINE.match(stripped)
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

            entries[ip_address] = entry

        if not entries:
            msg = "No valid ARP entries found in output"
            raise ValueError(msg)

        return ShowArpAllResult(
            max_entries=header.get("max_entries", 0),
            default_timeout=header.get("default_timeout", 0),
            total_entries=header.get("total_entries", 0),
            total_entries_shown=header.get("total_entries_shown", 0),
            entries=entries,
        )
