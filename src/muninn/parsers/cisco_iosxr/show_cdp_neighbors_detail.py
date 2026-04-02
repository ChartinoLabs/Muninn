"""Parser for 'show cdp neighbors detail' command on Cisco IOS-XR."""

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
    port_id: str
    hold_time: int
    version: str
    advertisement_version: NotRequired[int]
    native_vlan: NotRequired[int]
    duplex: NotRequired[str]


class ShowCdpNeighborsDetailResult(TypedDict):
    """Schema for 'show cdp neighbors detail' parsed output."""

    neighbors: dict[str, dict[str, dict[str, CdpNeighborDetailEntry]]]


@register(OS.CISCO_IOSXR, "show cdp neighbors detail")
class ShowCdpNeighborsDetailParser(BaseParser[ShowCdpNeighborsDetailResult]):
    """Parser for 'show cdp neighbors detail' on IOS-XR.

    Parses detailed CDP neighbor information including software version,
    platform, capabilities, native VLAN, and duplex settings.

    Output is keyed as: local_interface -> device_id -> port_id -> entry.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CDP})

    _DEVICE_ID_PATTERN = re.compile(r"Device ID:\s*(.+)")
    _IP_ADDRESS_PATTERN = re.compile(r"IP(?:v4)? [Aa]ddress:\s*(\S+)")
    _PLATFORM_CAPABILITIES_PATTERN = re.compile(
        r"Platform:\s*(.+?),\s+Capabilities:\s*(.+)"
    )
    _PLATFORM_ONLY_PATTERN = re.compile(r"Platform:\s*(.+)")
    _INTERFACE_PATTERN = re.compile(
        r"Interface:\s*(\S+),?\s+Port ID \(outgoing port\):\s*(\S+)"
    )
    _HOLDTIME_PATTERN = re.compile(r"Holdtime\s*:\s*(\d+)")
    _VERSION_MARKER = re.compile(r"^Version\s*:", re.MULTILINE)
    _ADV_VERSION_PATTERN = re.compile(r"advertisement version:\s*(\d+)")
    _NATIVE_VLAN_PATTERN = re.compile(r"Native VLAN:\s*(\d+)")
    _DUPLEX_PATTERN = re.compile(r"Duplex:\s*(\S+)")
    _SEPARATOR_PATTERN = SEPARATOR_DASH_RE
    _ENTRY_ADDR_HEADER = re.compile(r"^Entry address\(es\):")

    _VERSION_END_MARKERS = (
        "advertisement version:",
        "Native VLAN:",
        "Duplex:",
    )

    @classmethod
    def _split_into_blocks(cls, output: str) -> list[str]:
        """Split output into per-neighbor text blocks.

        Splits on separator lines, then keeps only chunks that
        start with a Device ID line.
        """
        chunks = cls._SEPARATOR_PATTERN.split(output)
        return [
            chunk.strip() for chunk in chunks if cls._DEVICE_ID_PATTERN.search(chunk)
        ]

    @classmethod
    def _extract_entry_addresses(cls, block: str) -> list[str]:
        """Extract IP addresses following the Entry address(es) header."""
        addresses: list[str] = []
        collecting = False

        for line in block.splitlines():
            stripped = line.strip()
            if cls._ENTRY_ADDR_HEADER.match(stripped):
                collecting = True
                ip_match = cls._IP_ADDRESS_PATTERN.search(stripped)
                if ip_match:
                    addresses.append(ip_match.group(1))
                continue

            if collecting:
                ip_match = cls._IP_ADDRESS_PATTERN.match(stripped)
                if ip_match:
                    addresses.append(ip_match.group(1))
                elif stripped:
                    collecting = False

        return addresses

    @classmethod
    def _extract_version(cls, block: str) -> str:
        """Extract software version string from block."""
        version_lines: list[str] = []
        collecting = False

        for line in block.splitlines():
            stripped = line.strip()

            if cls._VERSION_MARKER.match(stripped):
                collecting = True
                after_marker = stripped.split(":", 1)[1].strip()
                if after_marker:
                    version_lines.append(after_marker)
                continue

            if collecting:
                if not stripped:
                    if version_lines:
                        break
                    continue
                if any(
                    stripped.lower().startswith(m.lower())
                    for m in cls._VERSION_END_MARKERS
                ):
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
    def _parse_block(cls, block: str) -> tuple[str, CdpNeighborDetailEntry] | None:
        """Parse a single neighbor block into (local interface key, entry)."""
        device_match = cls._DEVICE_ID_PATTERN.search(block)
        if not device_match:
            return None

        intf_match = cls._INTERFACE_PATTERN.search(block)
        if not intf_match:
            return None

        platform, capabilities = cls._extract_platform_capabilities(block)
        hold_match = cls._HOLDTIME_PATTERN.search(block)

        local_interface = canonical_interface_name(intf_match.group(1))
        port_id = canonical_interface_name(intf_match.group(2))

        entry: CdpNeighborDetailEntry = {
            "device_id": device_match.group(1).strip(),
            "entry_addresses": cls._extract_entry_addresses(block),
            "platform": platform,
            "capabilities": capabilities,
            "port_id": port_id,
            "hold_time": int(hold_match.group(1)) if hold_match else 0,
            "version": cls._extract_version(block),
        }

        adv_match = cls._ADV_VERSION_PATTERN.search(block)
        if adv_match:
            entry["advertisement_version"] = int(adv_match.group(1))

        vlan_match = cls._NATIVE_VLAN_PATTERN.search(block)
        if vlan_match:
            entry["native_vlan"] = int(vlan_match.group(1))

        duplex_match = cls._DUPLEX_PATTERN.search(block)
        if duplex_match:
            entry["duplex"] = duplex_match.group(1)

        return local_interface, entry

    @classmethod
    def parse(cls, output: str) -> ShowCdpNeighborsDetailResult:
        """Parse 'show cdp neighbors detail' output on IOS-XR.

        Returns:
            Parsed CDP neighbor details nested as
            ``local_interface -> device_id -> port_id -> entry``.

        Raises:
            ValueError: If no neighbors found in output.
        """
        blocks = cls._split_into_blocks(output)
        neighbors: dict[str, dict[str, dict[str, CdpNeighborDetailEntry]]] = {}

        for block in blocks:
            parsed = cls._parse_block(block)
            if parsed is None:
                continue
            local_if, entry = parsed
            device_id = entry["device_id"]
            port_key = entry["port_id"]
            by_local = neighbors.setdefault(local_if, {})
            by_device = by_local.setdefault(device_id, {})
            by_device[port_key] = entry

        if not neighbors:
            msg = "No CDP neighbor details found in output"
            raise ValueError(msg)

        return ShowCdpNeighborsDetailResult(neighbors=neighbors)
