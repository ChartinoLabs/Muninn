"""Parser for 'show cdp neighbors' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class CdpNeighborEntry(TypedDict):
    """Schema for a single CDP neighbor entry."""

    hold_time: int
    platform: str
    port_id: str
    capabilities: NotRequired[str]


class ShowCdpNeighborsResult(TypedDict):
    """Schema for 'show cdp neighbors' parsed output."""

    neighbors: dict[str, dict[str, CdpNeighborEntry]]
    total_entries: NotRequired[int]


@register(OS.CISCO_NXOS, "show cdp neighbors")
class ShowCdpNeighborsParser(BaseParser[ShowCdpNeighborsResult]):
    """Parser for 'show cdp neighbors' command on NX-OS.

    Parses CDP neighbor information showing connected devices.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CDP})

    # Pattern for entries where everything is on one line
    # swor96(SSI13110AAQ) Eth1/17 165 S I s N5K-C5010P-BF Eth1/19
    # PERIMETER           mgmt0          179    R S I     WS-C3750-48TS Fas1/0/9
    _SINGLE_LINE_PATTERN = re.compile(
        r"^(?P<device_id>\S+)\s+"
        r"(?P<local_intf>(?:Eth|mgmt|Gig|Fas|Ten|Po)\S*)\s+"
        r"(?P<hold_time>\d+)\s+"
        r"(?P<capability>(?:[A-Za-z]\s*)+?)\s+"
        r"(?P<platform>\S+)\s+"
        r"(?P<port_id>\S+)$"
    )

    # Pattern for wrapped device ID - just the device ID on its own line
    # N9K2_TEST.lab.com(SAL1819S6BE)
    _DEVICE_ID_ONLY_PATTERN = re.compile(r"^(?P<device_id>\S+)$")

    # Pattern for continuation line after wrapped device ID
    #                     Eth1/1         133    R S s     N9K-C9396PX   Eth1/1
    _CONTINUATION_PATTERN = re.compile(
        r"^\s+(?P<local_intf>(?:Eth|mgmt|Gig|Fas|Ten|Po)\S*)\s+"
        r"(?P<hold_time>\d+)\s+"
        r"(?P<capability>(?:[A-Za-z]\s*)+?)\s+"
        r"(?P<platform>\S+)\s+"
        r"(?P<port_id>\S+)$"
    )

    # Pattern for total entries line
    _TOTAL_PATTERN = re.compile(r"^Total entries displayed:\s*(?P<total>\d+)", re.I)

    # Pattern to detect if port_id looks like an interface
    _INTERFACE_PATTERN = re.compile(
        r"^(?:Gi(?:g(?:abit)?)?|Fa(?:s(?:t)?)?|Eth?|Te(?:n)?|Fo(?:r(?:ty)?)?|"
        r"Hu(?:n(?:dred)?)?|mgmt|Lo|Vlan|Po|Tu|Se|nve)(?:Ethernet)?\d",
        re.IGNORECASE,
    )

    @classmethod
    def _normalize_port_id(cls, port_id: str) -> str:
        """Normalize port_id if it looks like an interface name."""
        if cls._INTERFACE_PATTERN.match(port_id):
            return canonical_interface_name(port_id, os=OS.CISCO_NXOS)
        return port_id

    @classmethod
    def _normalize_capabilities(cls, cap_str: str) -> str | None:
        """Normalize capability string to space-separated format.

        Args:
            cap_str: Raw capability string (may have extra spaces).

        Returns:
            Space-separated capabilities or None if empty.
        """
        caps = cap_str.split()
        if not caps:
            return None
        return " ".join(caps)

    @classmethod
    def _is_skippable_line(cls, line: str) -> bool:
        """Return True if the line is a header/legend or blank."""
        stripped = line.strip()
        if not stripped:
            return True
        if "Device-ID" in line or "Capability Codes:" in line:
            return True
        return stripped.startswith(("R -", "S -", "V -", "s -"))

    @classmethod
    def _parse_total_entries(cls, line: str) -> int | None:
        """Parse the total entries line if present."""
        total_match = cls._TOTAL_PATTERN.match(line.strip())
        if total_match:
            return int(total_match.group("total"))
        return None

    @classmethod
    def _parse_entry_fields(
        cls,
        match: re.Match[str],
    ) -> tuple[str, CdpNeighborEntry]:
        """Parse common fields from a CDP neighbor match."""
        local_intf = canonical_interface_name(
            match.group("local_intf"), os=OS.CISCO_NXOS
        )
        hold_time = int(match.group("hold_time"))
        capability = cls._normalize_capabilities(match.group("capability"))
        platform = match.group("platform")
        port_id = cls._normalize_port_id(match.group("port_id"))

        entry: CdpNeighborEntry = {
            "hold_time": hold_time,
            "platform": platform,
            "port_id": port_id,
        }
        if capability:
            entry["capabilities"] = capability

        return local_intf, entry

    @classmethod
    def _add_neighbor(
        cls,
        neighbors: dict[str, dict[str, CdpNeighborEntry]],
        local_intf: str,
        device_id: str,
        entry: CdpNeighborEntry,
    ) -> None:
        if local_intf not in neighbors:
            neighbors[local_intf] = {}
        neighbors[local_intf][device_id] = entry

    @classmethod
    def parse(cls, output: str) -> ShowCdpNeighborsResult:
        """Parse 'show cdp neighbors' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed CDP neighbors keyed by local interface, then device_id.

        Raises:
            ValueError: If no neighbors found.
        """
        neighbors: dict[str, dict[str, CdpNeighborEntry]] = {}
        total_entries: int | None = None
        pending_device_id: str | None = None

        for line in output.splitlines():
            # Skip header and capability legend
            if cls._is_skippable_line(line):
                continue

            # Check for total entries line
            parsed_total = cls._parse_total_entries(line)
            if parsed_total is not None:
                total_entries = parsed_total
                continue

            # Try continuation pattern first (for wrapped device ID)
            if pending_device_id:
                cont_match = cls._CONTINUATION_PATTERN.match(line)
                if cont_match:
                    local_intf, entry = cls._parse_entry_fields(cont_match)
                    cls._add_neighbor(
                        neighbors,
                        local_intf,
                        pending_device_id,
                        entry,
                    )
                    pending_device_id = None
                    continue

            # Try single-line pattern
            single_match = cls._SINGLE_LINE_PATTERN.match(line.strip())
            if single_match:
                device_id = single_match.group("device_id")
                local_intf, entry = cls._parse_entry_fields(single_match)
                cls._add_neighbor(neighbors, local_intf, device_id, entry)
                pending_device_id = None
                continue

            # Try device ID only pattern (for wrapped entries)
            device_only_match = cls._DEVICE_ID_ONLY_PATTERN.match(line.strip())
            if device_only_match:
                pending_device_id = device_only_match.group("device_id")

        if not neighbors:
            msg = "No CDP neighbors found in output"
            raise ValueError(msg)

        result: ShowCdpNeighborsResult = {"neighbors": neighbors}
        if total_entries is not None:
            result["total_entries"] = total_entries

        return result
