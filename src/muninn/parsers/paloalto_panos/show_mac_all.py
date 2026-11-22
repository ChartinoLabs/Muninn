"""Parser for 'show mac all' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS_COLON
from muninn.registry import register
from muninn.tags import ParserTag


class MacEntry(TypedDict):
    """Schema for a single MAC table entry."""

    vlan: str
    mac_address: str
    interface: str
    status: str
    ttl: int
    status_description: NotRequired[str]


class ShowMacAllResult(TypedDict):
    """Schema for 'show mac all' parsed output."""

    max_entries: int
    default_timeout: int
    total_entries: int
    total_entries_shown: int
    entries: dict[str, MacEntry]


# Map single-character status codes to human-readable descriptions
_STATUS_MAP: dict[str, str] = {
    "s": "static",
    "c": "complete",
    "i": "incomplete",
}


@register(OS.PALOALTO_PANOS, "show mac all")
class ShowMacAllParser(BaseParser[ShowMacAllResult]):
    """Parser for 'show mac all' command on Palo Alto PAN-OS.

    Parses the tabular MAC address output into a dictionary keyed by
    MAC address, with each value containing VLAN, interface, status, and TTL.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MAC,
        }
    )

    _MAC_LINE = re.compile(
        r"^(?P<vlan>\S+)\s+"
        rf"(?P<mac>{MAC_ADDRESS_COLON})\s+"
        r"(?P<interface>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<ttl>\d+)\s*$"
    )

    _HEADER_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        "max_entries": re.compile(
            r"maximum of entries supported\s*:\s*(\d+)", re.IGNORECASE
        ),
        "default_timeout": re.compile(r"default timeout\s*:\s*(\d+)", re.IGNORECASE),
        "total_entries": re.compile(
            r"total MAC entries in table\s*:\s*(\d+)", re.IGNORECASE
        ),
        "total_entries_shown": re.compile(
            r"total MAC entries shown\s*:\s*(\d+)", re.IGNORECASE
        ),
    }

    @classmethod
    def parse(cls, output: str) -> ShowMacAllResult:
        """Parse 'show mac all' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dictionary with header metadata and entries keyed by MAC address.

        Raises:
            ValueError: If no valid MAC entries are found in the output.
        """
        entries: dict[str, MacEntry] = {}
        header: dict[str, int] = {}

        for line in output.splitlines():
            stripped = line.strip()

            # Try header patterns
            for key, pattern in cls._HEADER_PATTERNS.items():
                header_match = pattern.search(stripped)
                if header_match:
                    header[key] = int(header_match.group(1))
                    break

            match = cls._MAC_LINE.match(stripped)
            if not match:
                continue

            mac_address = match.group("mac")
            status_code = match.group("status")

            entry: MacEntry = {
                "vlan": match.group("vlan"),
                "mac_address": mac_address,
                "interface": match.group("interface"),
                "status": status_code,
                "ttl": int(match.group("ttl")),
            }

            description = _STATUS_MAP.get(status_code)
            if description is not None:
                entry["status_description"] = description

            entries[mac_address] = entry

        if not entries:
            msg = "No valid MAC entries found in output"
            raise ValueError(msg)

        return ShowMacAllResult(
            max_entries=header.get("max_entries", 0),
            default_timeout=header.get("default_timeout", 0),
            total_entries=header.get("total_entries", 0),
            total_entries_shown=header.get("total_entries_shown", 0),
            entries=entries,
        )
