"""Parser for 'show router arp dynamic' command on Nokia SR OS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ArpDynamicEntry(TypedDict):
    """Schema for a single dynamic ARP entry."""

    mac_address: str
    expiry: str
    arp_type: str
    interface: str


# Top-level result is a dict keyed by IP address
ShowRouterArpDynamicResult = dict[str, ArpDynamicEntry]


@register(OS.NOKIA_SROS, "show router arp dynamic")
class ShowRouterArpDynamicParser(BaseParser[ShowRouterArpDynamicResult]):
    """Parser for 'show router arp dynamic' command on Nokia SR OS.

    Parses the dynamic ARP table output, returning a dict keyed by
    IP address. Each entry contains the MAC address, expiry timer,
    ARP type, and associated interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ARP,
        }
    )

    _SEPARATOR = re.compile(r"^[=\-]{10,}$")
    _TABLE_TITLE = re.compile(r"^\s*ARP Table\s+Router:", re.I)
    _HEADER = re.compile(r"^\s*IP Address\s+MAC Address\s+Expiry", re.I)
    _FOOTER = re.compile(r"^\s*No\.\s+of\s+ARP\s+Entries:", re.I)

    _ARP_ROW = re.compile(
        r"^(?P<ip>\S+)\s+"
        r"(?P<mac>[0-9a-fA-F:]{17})\s+"
        r"(?P<expiry>\S+)\s+"
        r"(?P<arp_type>\S+)\s+"
        r"(?P<interface>\S+)\s*$"
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True for lines that are not data rows."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._SEPARATOR.match(stripped):
            return True
        if cls._TABLE_TITLE.match(stripped):
            return True
        if cls._HEADER.match(stripped):
            return True
        if cls._FOOTER.match(stripped):
            return True
        return False

    @classmethod
    def parse(cls, output: str) -> ShowRouterArpDynamicResult:
        """Parse 'show router arp dynamic' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by IP address, each value an ArpDynamicEntry dict.

        Raises:
            ValueError: If no ARP entries can be parsed.
        """
        result: dict[str, ArpDynamicEntry] = {}

        for line in output.splitlines():
            if cls._is_skip_line(line):
                continue

            match = cls._ARP_ROW.match(line.strip())
            if match:
                ip_address = match.group("ip")
                entry: ArpDynamicEntry = {
                    "mac_address": match.group("mac"),
                    "expiry": match.group("expiry"),
                    "arp_type": match.group("arp_type"),
                    "interface": match.group("interface"),
                }
                result[ip_address] = entry

        if not result:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return cast(ShowRouterArpDynamicResult, result)
