"""Parser for 'show ip interface brief' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class InterfaceBriefEntry(TypedDict):
    """Schema for a single interface entry."""

    ip_address: str
    protocol_status: str
    link_status: str
    admin_status: str
    unnumbered_source: NotRequired[str]


class VrfEntry(TypedDict):
    """Schema for a VRF entry."""

    vrf_id: int
    interfaces: dict[str, InterfaceBriefEntry]


class ShowIpInterfaceBriefResult(TypedDict):
    """Schema for 'show ip interface brief' parsed output."""

    vrfs: dict[str, VrfEntry]


@register(OS.CISCO_NXOS, "show ip interface brief")
class ShowIpInterfaceBriefParser(BaseParser[ShowIpInterfaceBriefResult]):
    """Parser for 'show ip interface brief' command on NX-OS.

    Parses interface IP addressing and status information organized by VRF.
    """

    # Pattern for VRF header
    # IP Interface Status for VRF "default"(1)
    _VRF_PATTERN = re.compile(
        r'IP Interface Status for VRF "(?P<vrf_name>[^"]+)"\((?P<vrf_id>\d+)\)'
    )

    # Pattern for interface entries
    # Eth1/1               10.1.1.11       protocol-down/link-down/admin-up
    # tunnel-te11          unnumbered      protocol-up/link-up/admin-up
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|unnumbered|forward-enabled)\s+"
        r"protocol-(?P<protocol>up|down)/link-(?P<link>up|down)/admin-(?P<admin>up|down)"
    )

    # Pattern for unnumbered source continuation line
    # (loopback0)
    _UNNUMBERED_SOURCE_PATTERN = re.compile(r"^\s+\((?P<source>\S+)\)\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowIpInterfaceBriefResult:
        """Parse 'show ip interface brief' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data organized by VRF.

        Raises:
            ValueError: If no VRFs or interfaces found.
        """
        vrfs: dict[str, VrfEntry] = {}
        current_vrf: str | None = None
        current_vrf_id: int | None = None
        last_interface: str | None = None

        for line in output.splitlines():
            # Skip empty lines and headers
            stripped = line.strip()
            if not stripped or "Interface" in stripped and "IP Address" in stripped:
                continue

            # Try to match VRF header
            vrf_match = cls._VRF_PATTERN.search(line)
            if vrf_match:
                current_vrf = vrf_match.group("vrf_name")
                current_vrf_id = int(vrf_match.group("vrf_id"))
                vrfs[current_vrf] = VrfEntry(vrf_id=current_vrf_id, interfaces={})
                last_interface = None
                continue

            # Try to match unnumbered source continuation line
            unnumbered_match = cls._UNNUMBERED_SOURCE_PATTERN.match(line)
            if unnumbered_match and current_vrf and last_interface:
                source = unnumbered_match.group("source")
                vrfs[current_vrf]["interfaces"][last_interface]["unnumbered_source"] = (
                    canonical_interface_name(source)
                )
                continue

            # Try to match interface entry
            intf_match = cls._INTERFACE_PATTERN.match(stripped)
            if intf_match and current_vrf:
                interface = canonical_interface_name(intf_match.group("interface"))
                ip_address = intf_match.group("ip_address")

                entry: InterfaceBriefEntry = {
                    "ip_address": ip_address,
                    "protocol_status": intf_match.group("protocol").lower(),
                    "link_status": intf_match.group("link").lower(),
                    "admin_status": intf_match.group("admin").lower(),
                }

                vrfs[current_vrf]["interfaces"][interface] = entry
                last_interface = interface

        if not vrfs:
            msg = "No VRFs found in output"
            raise ValueError(msg)

        # Check if any interfaces were found
        total_interfaces = sum(len(v["interfaces"]) for v in vrfs.values())
        if total_interfaces == 0:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowIpInterfaceBriefResult(vrfs=vrfs)
