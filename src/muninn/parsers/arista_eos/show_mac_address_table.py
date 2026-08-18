"""Parser for 'show mac address-table' command on Arista EOS."""

import re
from typing import ClassVar, Literal, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MacTableRow(TypedDict):
    """One row under ``mac_table[vlan_key][mac_key]``.

    ``kind`` discriminates unicast vs multicast; ``ports`` is always a list
    (single-element for unicast). ``moves`` and ``last_move`` only appear on
    dynamic unicast entries.
    """

    kind: Literal["unicast", "multicast"]
    type: str
    ports: list[str]
    moves: NotRequired[int]
    last_move: NotRequired[str]


class ShowMacAddressTableResult(TypedDict):
    """Schema for 'show mac address-table' parsed output on Arista EOS.

    Entries are keyed by VLAN ID (str) then MAC address. Unicast and
    multicast entries share the same shape and live in the same map, with
    ``kind`` distinguishing them — matching the IOS / IOS-XE sibling parser.
    """

    mac_table: dict[str, dict[str, MacTableRow]]
    total_unicast_mac_addresses: NotRequired[int]
    total_multicast_mac_addresses: NotRequired[int]


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
        rf"(?P<mac>{MAC_ADDRESS})\s+"
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
    _TOTAL_LINE = re.compile(
        r"^Total\s+mac\s+Addresses[^:]*:\s*(?P<count>\d+)\s*$", re.I
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True if the line should be skipped."""
        stripped = line.strip()
        return (
            not stripped
            or cls._SEPARATOR_LINE.match(stripped) is not None
            or cls._HEADER_LINE.match(stripped) is not None
            or cls._UNICAST_HEADER.search(stripped) is not None
            or cls._MULTICAST_HEADER.search(stripped) is not None
        )

    @classmethod
    def _parse_unicast_line(
        cls, line: str, table: dict[str, dict[str, MacTableRow]]
    ) -> None:
        """Parse a single unicast MAC address table line."""
        match = cls._UNICAST_ENTRY.match(line)
        if not match:
            return
        row: MacTableRow = {
            "kind": "unicast",
            "type": match.group("type").lower(),
            "ports": [canonical_interface_name(match.group("port"), os=OS.ARISTA_EOS)],
        }
        if match.group("moves") is not None:
            row["moves"] = int(match.group("moves"))
        if match.group("last_move") is not None:
            row["last_move"] = match.group("last_move").strip()
        table.setdefault(match.group("vlan"), {})[match.group("mac").lower()] = row

    @classmethod
    def _parse_multicast_line(
        cls, line: str, table: dict[str, dict[str, MacTableRow]]
    ) -> None:
        """Parse a single multicast MAC address table line."""
        match = cls._MULTICAST_ENTRY.match(line)
        if not match:
            return
        ports = [
            canonical_interface_name(p, os=OS.ARISTA_EOS)
            for p in match.group("ports").strip().split()
        ]
        row: MacTableRow = {
            "kind": "multicast",
            "type": match.group("type").lower(),
            "ports": ports,
        }
        table.setdefault(match.group("vlan"), {})[match.group("mac").lower()] = row

    @classmethod
    def parse(cls, output: str) -> ShowMacAddressTableResult:
        """Parse 'show mac address-table' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MAC address table with unicast and multicast entries
            merged under ``mac_table`` keyed by VLAN then MAC, plus
            optional per-section totals from the footer summaries.
        """
        mac_table: dict[str, dict[str, MacTableRow]] = {}
        section: Literal["unicast", "multicast"] = "unicast"
        total_unicast: int | None = None
        total_multicast: int | None = None

        for line in output.splitlines():
            if cls._MULTICAST_HEADER.search(line):
                section = "multicast"
                continue

            total_match = cls._TOTAL_LINE.match(line.strip())
            if total_match:
                count = int(total_match.group("count"))
                if section == "unicast":
                    total_unicast = count
                else:
                    total_multicast = count
                continue

            if cls._is_skip_line(line):
                continue

            if section == "unicast":
                cls._parse_unicast_line(line, mac_table)
            else:
                cls._parse_multicast_line(line, mac_table)

        result: ShowMacAddressTableResult = {"mac_table": mac_table}
        if total_unicast is not None:
            result["total_unicast_mac_addresses"] = total_unicast
        if total_multicast is not None:
            result["total_multicast_mac_addresses"] = total_multicast
        return result
