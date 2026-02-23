"""Parser for 'show mac address-table dynamic' command on IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class MacAddressEntry(TypedDict):
    """Schema for a MAC address entry."""

    type: str
    ports: list[str]


class VlanMacs(TypedDict):
    """Schema for MAC addresses within a VLAN."""

    macs: dict[str, MacAddressEntry]


class ShowMacAddressTableDynamicResult(TypedDict):
    """Schema for 'show mac address-table dynamic' parsed output."""

    vlans: dict[str, VlanMacs]


@register(OS.CISCO_IOSXE, "show mac address-table dynamic")
class ShowMacAddressTableDynamicParser(BaseParser[ShowMacAddressTableDynamicResult]):
    """Parser for 'show mac address-table dynamic' command."""

    _ROW_PATTERN = re.compile(
        r"^(?P<vlan>\d+)\s+(?P<mac>\S+)\s+(?P<type>\S+)\s+(?P<port>\S+)$"
    )

    @staticmethod
    def _normalize_interface(interface: str) -> str:
        return canonical_interface_name(interface, os=OS.CISCO_IOSXE)

    @classmethod
    def parse(cls, output: str) -> ShowMacAddressTableDynamicResult:
        """Parse 'show mac address-table dynamic' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MAC address table.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        vlans: dict[str, VlanMacs] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.lower().startswith("mac address table"):
                continue

            if line.lower().startswith("vlan"):
                continue

            if set(line) == {"-"}:
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                vlan = match.group("vlan")
                mac = match.group("mac")
                mac_type = match.group("type")
                port = cls._normalize_interface(match.group("port"))

                vlan_entry = vlans.setdefault(vlan, {"macs": {}})
                mac_entry = vlan_entry["macs"].setdefault(
                    mac, {"type": mac_type, "ports": []}
                )
                if port not in mac_entry["ports"]:
                    mac_entry["ports"].append(port)

        if not vlans:
            msg = "No MAC address table entries found"
            raise ValueError(msg)

        return ShowMacAddressTableDynamicResult(vlans=vlans)
