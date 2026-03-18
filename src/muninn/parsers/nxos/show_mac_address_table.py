"""Parser for 'show mac address-table' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Entry flag character to descriptive string mapping
_ENTRY_FLAG_MAP: dict[str, str] = {
    "*": "primary",
    "+": "vpc_peer_link",
    "G": "gateway",
}

# Age values that indicate unknown/not-applicable
_NULL_AGE_VALUES = frozenset({"-", "NA", "~~~"})

# Pattern to detect port values that are normalizable interface names.
# Matches common NX-OS interface abbreviations like Eth, Po, Lo, Vlan, etc.
_INTERFACE_PORT_PATTERN = re.compile(r"^(?:Eth|Po|Lo|Vlan|mgmt|nve|Tu|Fa|Gi|Te)\S*$")


class MacTableEntry(TypedDict):
    """Schema for a single MAC address table entry.

    Optional fields (vlan, age, entry_flag) are omitted when not applicable
    rather than set to null, following the project convention.
    """

    mac_address: str
    type: str
    secure: bool
    ntfy: bool
    port: str
    is_routed: bool
    vlan: NotRequired[int]
    age: NotRequired[int]
    entry_flag: NotRequired[str]


class ShowMacAddressTableResult(TypedDict):
    """Schema for 'show mac address-table' parsed output."""

    mac_table: list[MacTableEntry]


@register(OS.CISCO_NXOS, "show mac address-table")
class ShowMacAddressTableParser(BaseParser[ShowMacAddressTableResult]):
    """Parser for 'show mac address-table' command on NX-OS.

    Parses the MAC address table showing L2 forwarding entries including
    VLAN, MAC address, type, age, security flags, and port information.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"mac", "switching"})

    # Match MAC table entry lines. The format is:
    # [flag] VLAN  MAC_ADDRESSESS  TYPE  AGE  SECURE  NTFY  PORTS [extra]
    #
    # Examples:
    # *   10     aaaa.bbff.8888   static   -         F      F    Eth1/2
    # G    -     0000.deff.6c9d   static   -         F      F    sup-eth1(R)
    # + 100     0000.0000.1111   dynamic  NA        F      F    Po100
    #   2000     7e00.c0ff.0007   static   -         F      F    vPC Peer-Link(R)
    _ENTRY_PATTERN = re.compile(
        r"^(?P<flag>[*+G])?\s*"
        r"(?P<vlan>\d+|-)\s+"
        rf"(?P<mac>{MAC_ADDRESS})\s+"
        r"(?P<type>static|dynamic)\s+"
        r"(?P<age>\d+|-|NA|~~~)\s+"
        r"(?P<secure>[FT])\s+"
        r"(?P<ntfy>[FT])\s+"
        r"(?P<port>\S+(?:\s+\S+)*?)\s*$"
    )

    @classmethod
    def _parse_entry(cls, match: re.Match[str]) -> MacTableEntry:
        """Build a MacTableEntry from a regex match.

        Args:
            match: Regex match object from _ENTRY_PATTERN.

        Returns:
            Parsed MAC table entry dictionary.
        """
        flag_char = match.group("flag")
        vlan_str = match.group("vlan")
        age_str = match.group("age")
        port_raw = match.group("port").strip()

        # Determine if port has the routed indicator (R)
        is_routed = "(R)" in port_raw

        # Normalize interface abbreviations (Eth -> Ethernet, Po -> Port-channel)
        # but leave special values like Drop, sup-eth1(R), vPC Peer-Link(R) as-is
        if _INTERFACE_PORT_PATTERN.match(port_raw):
            port_raw = canonical_interface_name(port_raw, os=OS.CISCO_NXOS)

        entry: MacTableEntry = {
            "mac_address": match.group("mac").lower(),
            "type": match.group("type"),
            "secure": match.group("secure") == "T",
            "ntfy": match.group("ntfy") == "T",
            "port": port_raw,
            "is_routed": is_routed,
        }

        # Only include optional fields when they have a meaningful value
        if vlan_str != "-":
            entry["vlan"] = int(vlan_str)

        if age_str not in _NULL_AGE_VALUES:
            entry["age"] = int(age_str)

        if flag_char and flag_char in _ENTRY_FLAG_MAP:
            entry["entry_flag"] = _ENTRY_FLAG_MAP[flag_char]

        return entry

    @classmethod
    def parse(cls, output: str) -> ShowMacAddressTableResult:
        """Parse 'show mac address-table' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MAC address table with list of entries.

        Raises:
            ValueError: If no MAC table entries found.
        """
        mac_table: list[MacTableEntry] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._ENTRY_PATTERN.match(line)
            if match:
                mac_table.append(cls._parse_entry(match))

        if not mac_table:
            msg = "No MAC address table entries found in output"
            raise ValueError(msg)

        return ShowMacAddressTableResult(mac_table=mac_table)
