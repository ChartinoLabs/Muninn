"""Parser for 'show mac address-table' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MacEntry(TypedDict):
    """Schema for a single MAC address table entry."""

    entry_type: str
    interface: str
    moves: NotRequired[int]
    last_move: NotRequired[str]


class MulticastMacEntry(TypedDict):
    """Schema for a single multicast MAC address table entry."""

    entry_type: str
    interfaces: list[str]


class ShowMacAddressTableResult(TypedDict):
    """Schema for 'show mac address-table' parsed output on Arista EOS.

    Unicast entries are keyed by VLAN ID (str), then by MAC address.
    Multicast entries follow the same structure but use a list of interfaces.
    """

    unicast: dict[str, dict[str, MacEntry]]
    multicast: dict[str, dict[str, MulticastMacEntry]]


@register(OS.ARISTA_EOS, "show mac address-table")
class ShowMacAddressTableParser(BaseParser[ShowMacAddressTableResult]):
    """Parser for 'show mac address-table' command on Arista EOS.

    Parses both unicast and multicast MAC address table sections.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MAC,
            ParserTag.SWITCHING,
        }
    )

    # Section headers
    _UNICAST_HEADER = re.compile(r"mac\s+Address\s+Table", re.I)
    _MULTICAST_HEADER = re.compile(r"Multicast\s+mac\s+Address\s+Table", re.I)

    # Unicast entry: Vlan  MAC  Type  Port  [Moves  Last Move]
    _UNICAST_ENTRY = re.compile(
        r"^\s*(?P<vlan>\d+)\s+"
        r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<port>\S+)"
        r"(?:\s+(?P<moves>\d+)\s+(?P<last_move>.+\s+ago))?\s*$"
    )

    # Multicast entry: Vlan  MAC  Type  Ports (space-separated list)
    # MAC pattern is permissive to handle sanitized output where octets
    # may contain non-hex characters.
    _MULTICAST_ENTRY = re.compile(
        r"^\s*(?P<vlan>\d+)\s+"
        r"(?P<mac>\S{4}\.\S{4}\.\S{4})\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<ports>.+?)\s*$"
    )

    # Lines to skip
    _SEPARATOR_LINE = re.compile(r"^-+$")
    _HEADER_LINE = re.compile(r"^\s*Vlan\s+mac\s+Address", re.I)
    _TOTAL_LINE = re.compile(r"^Total\s+mac\s+Addresses", re.I)

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True if the line should be skipped."""
        stripped = line.strip()
        return (
            not stripped
            or cls._SEPARATOR_LINE.match(stripped) is not None
            or cls._HEADER_LINE.match(stripped) is not None
            or cls._TOTAL_LINE.match(stripped) is not None
            or cls._UNICAST_HEADER.search(stripped) is not None
            or cls._MULTICAST_HEADER.search(stripped) is not None
        )

    @classmethod
    def _parse_unicast_line(
        cls, line: str, table: dict[str, dict[str, MacEntry]]
    ) -> None:
        """Parse a single unicast MAC address table line."""
        match = cls._UNICAST_ENTRY.match(line)
        if not match:
            return
        entry: MacEntry = {
            "entry_type": match.group("type").upper(),
            "interface": canonical_interface_name(
                match.group("port"), os=OS.ARISTA_EOS
            ),
        }
        if match.group("moves") is not None:
            entry["moves"] = int(match.group("moves"))
        if match.group("last_move") is not None:
            entry["last_move"] = match.group("last_move").strip()
        table.setdefault(match.group("vlan"), {})[match.group("mac")] = entry

    @classmethod
    def _parse_multicast_line(
        cls, line: str, table: dict[str, dict[str, MulticastMacEntry]]
    ) -> None:
        """Parse a single multicast MAC address table line."""
        match = cls._MULTICAST_ENTRY.match(line)
        if not match:
            return
        interfaces = [
            canonical_interface_name(p, os=OS.ARISTA_EOS)
            for p in match.group("ports").strip().split()
        ]
        table.setdefault(match.group("vlan"), {})[match.group("mac")] = (
            MulticastMacEntry(
                entry_type=match.group("type").upper(),
                interfaces=interfaces,
            )
        )

    @classmethod
    def parse(cls, output: str) -> ShowMacAddressTableResult:
        """Parse 'show mac address-table' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MAC address table with unicast and multicast sections.
        """
        unicast: dict[str, dict[str, MacEntry]] = {}
        multicast: dict[str, dict[str, MulticastMacEntry]] = {}
        section = "unicast"

        for line in output.splitlines():
            if cls._MULTICAST_HEADER.search(line):
                section = "multicast"
                continue
            if cls._is_skip_line(line):
                continue
            if section == "unicast":
                cls._parse_unicast_line(line, unicast)
            else:
                cls._parse_multicast_line(line, multicast)

        return ShowMacAddressTableResult(
            unicast=unicast,
            multicast=multicast,
        )
