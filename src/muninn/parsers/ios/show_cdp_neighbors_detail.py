"""Parser for 'show cdp neighbors detail' command on IOS/IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class CdpNeighborDetailEntry(TypedDict):
    """Schema for a single CDP neighbor detail entry."""

    device_id: str
    entry_addresses: list[str]
    platform: str
    capabilities: str
    local_interface: str
    port_id: str
    hold_time: int
    version: str
    advertisement_version: NotRequired[int]
    native_vlan: NotRequired[int]
    duplex: NotRequired[str]
    vtp_management_domain: NotRequired[str]
    management_addresses: NotRequired[list[str]]


class ShowCdpNeighborsDetailResult(TypedDict):
    """Schema for 'show cdp neighbors detail' parsed output."""

    neighbors: list[CdpNeighborDetailEntry]
    total_entries: NotRequired[int]


@register(OS.CISCO_IOS, "show cdp neighbors detail")
@register(OS.CISCO_IOSXE, "show cdp neighbors detail")
class ShowCdpNeighborsDetailParser(BaseParser[ShowCdpNeighborsDetailResult]):
    """Parser for 'show cdp neighbors detail' on IOS/IOS-XE.

    Parses detailed CDP neighbor information including software version,
    VTP domain, native VLAN, duplex, and management addresses.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CDP})

    _DEVICE_ID_PATTERN = re.compile(r"Device ID:\s*(.+)")
    _IP_ADDRESS_PATTERN = re.compile(r"IP(?:v4)? [Aa]ddress:\s*(\S+)")
    _IPV6_ADDRESS_PATTERN = re.compile(r"IPv6 [Aa]ddress:\s*(\S+)")
    _PLATFORM_CAPABILITIES_PATTERN = re.compile(
        r"Platform:\s*(.+?),\s+Capabilities:\s*(.+)"
    )
    _PLATFORM_ONLY_PATTERN = re.compile(r"Platform:\s*(.+)")
    _INTERFACE_PATTERN = re.compile(
        r"Interface:\s*(\S+),\s+Port ID \(outgoing port\):\s*(\S+)"
    )
    _HOLDTIME_PATTERN = re.compile(r"Holdtime\s*:\s*(\d+)")
    _VERSION_MARKER = re.compile(r"^Version\s*:", re.MULTILINE)
    _ADV_VERSION_PATTERN = re.compile(r"advertisement version:\s*(\d+)")
    _NATIVE_VLAN_PATTERN = re.compile(r"Native VLAN:\s*(\d+)")
    _DUPLEX_PATTERN = re.compile(r"Duplex:\s*(\S+)")
    _VTP_DOMAIN_PATTERN = re.compile(r"VTP Management Domain:\s*'([^']*)'")
    _TOTAL_ENTRIES_PATTERN = re.compile(
        r"Total (?:cdp )?entries displayed\s*:\s*(\d+)", re.I
    )
    _SEPARATOR_PATTERN = SEPARATOR_DASH_RE
    _ENTRY_ADDR_HEADER = re.compile(r"^Entry address\(es\):")
    _MGMT_ADDR_HEADER = re.compile(r"^Management address\(es\):")

    @staticmethod
    def _flush_block(blocks: list[str], current_lines: list[str]) -> None:
        """Append accumulated lines as a block if any exist."""
        if current_lines:
            blocks.append("\n".join(current_lines))

    @classmethod
    def _split_into_blocks(cls, output: str) -> list[str]:
        """Split output into per-neighbor text blocks.

        Each block starts with 'Device ID:' and ends before the next
        separator line or end of output.
        """
        blocks: list[str] = []
        current_lines: list[str] = []
        in_block = False

        for line in output.splitlines():
            stripped = line.strip()

            if cls._DEVICE_ID_PATTERN.match(stripped):
                if in_block:
                    cls._flush_block(blocks, current_lines)
                current_lines = [line]
                in_block = True
            elif cls._SEPARATOR_PATTERN.match(stripped):
                if in_block:
                    cls._flush_block(blocks, current_lines)
                current_lines = []
                in_block = False
            elif in_block:
                current_lines.append(line)

        if in_block:
            cls._flush_block(blocks, current_lines)
        return blocks

    @classmethod
    def _extract_addresses(
        cls, block: str, header_pattern: re.Pattern[str]
    ) -> list[str]:
        """Extract IP addresses following a specific header in the block.

        Collects addresses on indented lines immediately after the header,
        stopping when a non-indented/non-address line is reached.
        """
        addresses: list[str] = []
        lines = block.splitlines()
        collecting = False

        for line in lines:
            stripped = line.strip()
            if header_pattern.match(stripped):
                collecting = True
                # Check if there's an address on the same line
                ip_match = cls._IP_ADDRESS_PATTERN.search(stripped)
                if ip_match:
                    addresses.append(ip_match.group(1))
                continue

            if collecting:
                ip_match = cls._IP_ADDRESS_PATTERN.match(stripped)
                ipv6_match = cls._IPV6_ADDRESS_PATTERN.match(stripped)
                if ip_match:
                    addresses.append(ip_match.group(1))
                elif ipv6_match:
                    addresses.append(ipv6_match.group(1))
                elif stripped:
                    collecting = False

        return addresses

    @classmethod
    def _extract_version(cls, block: str) -> str:
        """Extract software version string from block.

        The version spans from the line after 'Version :' until
        the next known field or blank line.
        """
        lines = block.splitlines()
        version_lines: list[str] = []
        collecting = False

        # Known field markers that end the version block
        end_markers = (
            "advertisement version:",
            "Protocol Hello:",
            "VTP Management Domain:",
            "Native VLAN:",
            "Duplex:",
            "Management address(es):",
            "Power Available TLV:",
            "Power request id:",
        )

        for line in lines:
            stripped = line.strip()

            if cls._VERSION_MARKER.match(stripped):
                collecting = True
                # Check for inline version text after "Version :"
                after_marker = stripped.split(":", 1)[1].strip()
                if after_marker:
                    version_lines.append(after_marker)
                continue

            if collecting:
                if not stripped:
                    # Empty line ends version only if we already have content
                    if version_lines:
                        break
                    continue
                if any(stripped.lower().startswith(m.lower()) for m in end_markers):
                    break
                version_lines.append(stripped)

        return "\n".join(version_lines)

    @classmethod
    def _extract_platform_capabilities(cls, block: str) -> tuple[str, str]:
        """Extract platform and capabilities strings from a block."""
        plat_cap_match = cls._PLATFORM_CAPABILITIES_PATTERN.search(block)
        if plat_cap_match:
            return plat_cap_match.group(1).strip(), plat_cap_match.group(2).strip()

        plat_match = cls._PLATFORM_ONLY_PATTERN.search(block)
        if plat_match:
            return plat_match.group(1).strip().rstrip(","), ""

        return "", ""

    @classmethod
    def _add_optional_fields(cls, entry: CdpNeighborDetailEntry, block: str) -> None:
        """Populate optional fields on the entry from the block text."""
        adv_match = cls._ADV_VERSION_PATTERN.search(block)
        if adv_match:
            entry["advertisement_version"] = int(adv_match.group(1))

        vlan_match = cls._NATIVE_VLAN_PATTERN.search(block)
        if vlan_match:
            entry["native_vlan"] = int(vlan_match.group(1))

        duplex_match = cls._DUPLEX_PATTERN.search(block)
        if duplex_match:
            entry["duplex"] = duplex_match.group(1)

        vtp_match = cls._VTP_DOMAIN_PATTERN.search(block)
        if vtp_match:
            entry["vtp_management_domain"] = vtp_match.group(1)

        mgmt_addresses = cls._extract_addresses(block, cls._MGMT_ADDR_HEADER)
        if mgmt_addresses:
            entry["management_addresses"] = mgmt_addresses

    @classmethod
    def _parse_block(cls, block: str) -> CdpNeighborDetailEntry | None:
        """Parse a single neighbor block into a structured entry."""
        device_match = cls._DEVICE_ID_PATTERN.search(block)
        if not device_match:
            return None

        intf_match = cls._INTERFACE_PATTERN.search(block)
        if not intf_match:
            return None

        platform, capabilities = cls._extract_platform_capabilities(block)
        hold_match = cls._HOLDTIME_PATTERN.search(block)

        entry: CdpNeighborDetailEntry = {
            "device_id": device_match.group(1).strip(),
            "entry_addresses": cls._extract_addresses(block, cls._ENTRY_ADDR_HEADER),
            "platform": platform,
            "capabilities": capabilities,
            "local_interface": canonical_interface_name(intf_match.group(1)),
            "port_id": canonical_interface_name(intf_match.group(2)),
            "hold_time": int(hold_match.group(1)) if hold_match else 0,
            "version": cls._extract_version(block),
        }

        cls._add_optional_fields(entry, block)
        return entry

    @classmethod
    def parse(cls, output: str) -> ShowCdpNeighborsDetailResult:
        """Parse 'show cdp neighbors detail' output on IOS/IOS-XE.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed CDP neighbor details as a list of entries.

        Raises:
            ValueError: If no neighbors found.
        """
        blocks = cls._split_into_blocks(output)
        neighbors: list[CdpNeighborDetailEntry] = []

        for block in blocks:
            entry = cls._parse_block(block)
            if entry is not None:
                neighbors.append(entry)

        if not neighbors:
            msg = "No CDP neighbor details found in output"
            raise ValueError(msg)

        result: ShowCdpNeighborsDetailResult = {"neighbors": neighbors}

        # Check for total entries
        total_match = cls._TOTAL_ENTRIES_PATTERN.search(output)
        if total_match:
            result["total_entries"] = int(total_match.group(1))

        return result
