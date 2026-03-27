"""Parser for 'arp -a' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ArpEntry(TypedDict):
    """Schema for a single ARP table entry."""

    hostname: str
    mac_address: str
    hw_type: str
    interface: str
    permanent: NotRequired[bool]


ArpResult = dict[str, ArpEntry]

# Pattern for arp -a output lines:
# hostname (ip_address) at mac_address [hw_type] on interface
# ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
# ? (10.0.0.1) at <incomplete> on eth0
_ARP_LINE_RE = re.compile(
    r"^(?P<hostname>\S+)\s+"
    r"\((?P<ip>[^)]+)\)\s+"
    r"at\s+(?P<mac>\S+)"
    r"(?:\s+\[(?P<hw_type>[^\]]+)\])?"
    r"\s+on\s+(?P<interface>\S+)"
    r"(?P<remainder>.*)"
)

# MAC address indicating an incomplete ARP entry
_INCOMPLETE_MAC = "<incomplete>"


@register(OS.LINUX, "arp -a")
class ArpAParser(BaseParser[ArpResult]):
    """Parser for 'arp -a' command on Linux.

    Parses ARP table entries including hostname, MAC address,
    hardware type, and interface.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ARP,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ArpResult:
        """Parse 'arp -a' output on Linux.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of ARP entries keyed by IP address.

        Raises:
            ValueError: If no ARP entries can be parsed.
        """
        result: dict[str, ArpEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _ARP_LINE_RE.match(line)
            if not match:
                continue

            ip_address = match.group("ip")
            mac_raw = match.group("mac")

            # Normalize incomplete MAC entries
            if mac_raw == _INCOMPLETE_MAC:
                mac_address = "incomplete"
            else:
                mac_address = mac_raw

            entry: ArpEntry = {
                "hostname": match.group("hostname"),
                "mac_address": mac_address,
                "hw_type": match.group("hw_type") or "",
                "interface": match.group("interface"),
            }

            # Check for PERM flag in remainder
            remainder = match.group("remainder")
            if remainder and "PERM" in remainder:
                entry["permanent"] = True

            result[ip_address] = entry

        if not result:
            msg = "No ARP entries found in output"
            raise ValueError(msg)

        return cast(ArpResult, result)
