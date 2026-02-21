"""Parser for 'show lldp neighbors' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class LldpNeighborEntry(TypedDict):
    """Schema for a single LLDP neighbor entry."""

    hold_time: int
    port_id: str
    capabilities: NotRequired[str]


class ShowLldpNeighborsResult(TypedDict):
    """Schema for 'show lldp neighbors' parsed output."""

    neighbors: dict[str, dict[str, LldpNeighborEntry]]
    total_entries: int


@register(OS.CISCO_IOS, "show lldp neighbors")
@register(OS.CISCO_IOSXE, "show lldp neighbors")
class ShowLldpNeighborsParser(BaseParser[ShowLldpNeighborsResult]):
    """Parser for 'show lldp neighbors' command.

    Parses LLDP neighbor information showing connected devices.
    """

    # Pattern for neighbor entries - handles variable spacing
    # Device ID           Local Intf     Hold-time  Capability      Port ID
    # 10.10.191.112       Gi1/0/44       171        B,T             7038.eeff.50a4
    # Polycom VVX 500     Gi1/0/2        120        T               0004.f2d1.2222
    # Device ID can contain spaces, so use non-greedy match up to local interface
    # Capability codes are single uppercase letters separated by commas (R, B, T, etc.)
    _NEIGHBOR_PATTERN = re.compile(
        r"^(?P<device_id>.+?)\s+"
        r"(?P<local_intf>(?:Gi|Fa|Te|Fo|Hu|Et|Po|Vl|Lo|Tu|Se|Mg)\S+)\s+"
        r"(?P<hold_time>\d+)\s+"
        r"(?:(?P<capability>[A-Z,]+)\s+)?"
        r"(?P<port_id>\S+)$"
    )

    # Pattern for wrapped long device names (no space between device_id and local_intf)
    # long_name_swt.josh-vGi0/2          120        R               Gi0/0
    _WRAPPED_NEIGHBOR_PATTERN = re.compile(
        r"^(?P<device_id>.+?)(?P<local_intf>(?:Gi|Fa|Te|Fo|Hu|Et|Po|Vl|Lo|Tu|Se|Mg)\S+)\s+"
        r"(?P<hold_time>\d+)\s+"
        r"(?:(?P<capability>[A-Z,]+)\s+)?"
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
            return canonical_interface_name(port_id, os=OS.CISCO_IOS)
        return port_id

    @classmethod
    def parse(cls, output: str) -> ShowLldpNeighborsResult:
        """Parse 'show lldp neighbors' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LLDP neighbors keyed by local interface, then device_id.

        Raises:
            ValueError: If no neighbors or total count found.
        """
        neighbors: dict[str, dict[str, LldpNeighborEntry]] = {}
        total_entries: int | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Check for total entries line
            total_match = cls._TOTAL_PATTERN.match(line)
            if total_match:
                total_entries = int(total_match.group("total"))
                continue

            # Try standard neighbor pattern first
            match = cls._NEIGHBOR_PATTERN.match(line)
            if not match:
                # Try wrapped pattern for long device names
                match = cls._WRAPPED_NEIGHBOR_PATTERN.match(line)

            if match:
                device_id = match.group("device_id")
                local_intf = canonical_interface_name(
                    match.group("local_intf"), os=OS.CISCO_IOS
                )
                hold_time = int(match.group("hold_time"))
                capability = match.group("capability")
                port_id = cls._normalize_port_id(match.group("port_id"))

                # Initialize interface dict if needed
                if local_intf not in neighbors:
                    neighbors[local_intf] = {}

                entry: LldpNeighborEntry = {
                    "hold_time": hold_time,
                    "port_id": port_id,
                }

                if capability:
                    entry["capabilities"] = capability

                neighbors[local_intf][device_id] = entry

        if not neighbors:
            msg = "No LLDP neighbors found in output"
            raise ValueError(msg)

        if total_entries is None:
            msg = "No total entries count found in output"
            raise ValueError(msg)

        return ShowLldpNeighborsResult(
            neighbors=neighbors,
            total_entries=total_entries,
        )
