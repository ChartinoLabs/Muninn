"""Parser for 'show ip interface brief' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


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

    tags: ClassVar[frozenset[str]] = frozenset({"interfaces"})

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
    def _handle_vrf_header(cls, line: str, vrfs: dict[str, VrfEntry]) -> str | None:
        """Match a VRF header and initialize it. Returns VRF name or None."""
        vrf_match = cls._VRF_PATTERN.search(line)
        if not vrf_match:
            return None
        name = vrf_match.group("vrf_name")
        vrfs[name] = VrfEntry(vrf_id=int(vrf_match.group("vrf_id")), interfaces={})
        return name

    @classmethod
    def _handle_interface(
        cls, stripped: str, vrfs: dict[str, VrfEntry], current_vrf: str
    ) -> str | None:
        """Match an interface entry and add it. Returns interface name or None."""
        intf_match = cls._INTERFACE_PATTERN.match(stripped)
        if not intf_match:
            return None
        interface = canonical_interface_name(
            intf_match.group("interface"), os=OS.CISCO_NXOS
        )
        entry: InterfaceBriefEntry = {
            "ip_address": intf_match.group("ip_address"),
            "protocol_status": intf_match.group("protocol").lower(),
            "link_status": intf_match.group("link").lower(),
            "admin_status": intf_match.group("admin").lower(),
        }
        vrfs[current_vrf]["interfaces"][interface] = entry
        return interface

    @classmethod
    def _is_skip_line(cls, stripped: str) -> bool:
        """Check if a line should be skipped."""
        return not stripped or ("Interface" in stripped and "IP Address" in stripped)

    @classmethod
    def _handle_unnumbered(
        cls,
        line: str,
        vrfs: dict[str, VrfEntry],
        current_vrf: str,
        last_interface: str,
    ) -> bool:
        """Handle unnumbered source continuation line. Returns True if matched."""
        unnumbered_match = cls._UNNUMBERED_SOURCE_PATTERN.match(line)
        if not unnumbered_match:
            return False
        source = unnumbered_match.group("source")
        vrfs[current_vrf]["interfaces"][last_interface]["unnumbered_source"] = (
            canonical_interface_name(source, os=OS.CISCO_NXOS)
        )
        return True

    @staticmethod
    def _validate_result(vrfs: dict[str, VrfEntry]) -> None:
        """Validate that parsed data contains VRFs and interfaces."""
        if not vrfs:
            msg = "No VRFs found in output"
            raise ValueError(msg)
        total_interfaces = sum(len(v["interfaces"]) for v in vrfs.values())
        if total_interfaces == 0:
            msg = "No interfaces found in output"
            raise ValueError(msg)

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
        last_interface: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if cls._is_skip_line(stripped):
                continue

            vrf_name = cls._handle_vrf_header(line, vrfs)
            if vrf_name is not None:
                current_vrf = vrf_name
                last_interface = None
                continue

            if current_vrf and last_interface:
                if cls._handle_unnumbered(line, vrfs, current_vrf, last_interface):
                    continue

            if current_vrf:
                intf = cls._handle_interface(stripped, vrfs, current_vrf)
                if intf is not None:
                    last_interface = intf

        cls._validate_result(vrfs)
        return ShowIpInterfaceBriefResult(vrfs=vrfs)
