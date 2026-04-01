"""Parser for 'show lldp neighbors' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class LldpNeighborEntry(TypedDict):
    """Schema for a single LLDP neighbor entry."""

    device_id: str
    hold_time: int
    capability: str
    port_id: str


class ShowLldpNeighborsResult(TypedDict):
    """Schema for 'show lldp neighbors' parsed output on Cisco IOS-XR.

    Keyed by local interface name (canonical form).
    """

    neighbors: dict[str, dict[str, LldpNeighborEntry]]


# IOS-XR LLDP neighbor table format:
#
# Device ID       Local Intf          Hold-time  Capability     Port ID
# ASR-OCC-P1      Gi0/0/0/0           120        R               Gi0/0/0/2
#
# Lines to skip: blank, header, separator, capability legend, total/timestamp.
_SKIP_PATTERNS = re.compile(
    r"^\s*$"
    r"|^Device\s+ID\s+"
    r"|^-{3,}"
    r"|^Capability\s+codes:"
    r"|^\s+\("
    r"|^Total\s+entries"
    r"|^\w{3}\s+\w{3}\s+\d+",
    re.IGNORECASE,
)

# IOS-XR local interface abbreviations: Gi, Te, Hu, Fo, Be, Lo, Mg, Nu, TenGigE, etc.
_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<device_id>\S+)\s+"
    r"(?P<local_intf>\S+)\s+"
    r"(?P<hold_time>\d+)\s+"
    r"(?P<capability>\S+)\s+"
    r"(?P<port_id>\S+)\s*$"
)

# Port ID that looks like an interface name and should be canonicalized.
_INTERFACE_PORT_ID_PATTERN = re.compile(
    r"^(?:Eth(?:ernet)?|Et|Gi|Te|Fo|Hu|Be|Lo|Mg|Nu|Po|Ma"
    r"|GigabitEthernet|TenGigE|FortyGigE|HundredGigE"
    r"|Bundle-Ether|MgmtEth|Loopback|Null)\d",
    re.IGNORECASE,
)


@register(OS.CISCO_IOSXR, "show lldp neighbors")
class ShowLldpNeighborsParser(BaseParser[ShowLldpNeighborsResult]):
    """Parser for 'show lldp neighbors' command on Cisco IOS-XR."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    @classmethod
    def _normalize_port_id(cls, port_id: str) -> str:
        """Normalize port_id if it looks like an interface name."""
        if _INTERFACE_PORT_ID_PATTERN.match(port_id):
            return canonical_interface_name(port_id, os=OS.CISCO_IOSXR)
        return port_id

    @classmethod
    def parse(cls, output: str) -> ShowLldpNeighborsResult:
        """Parse 'show lldp neighbors' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LLDP neighbors keyed by local interface, then device ID.

        Raises:
            ValueError: If no LLDP neighbors are found in the output.
        """
        neighbors: dict[str, dict[str, LldpNeighborEntry]] = {}

        for line in output.splitlines():
            if _SKIP_PATTERNS.match(line):
                continue

            match = _NEIGHBOR_PATTERN.match(line)
            if not match:
                continue

            local_intf = canonical_interface_name(
                match.group("local_intf"), os=OS.CISCO_IOSXR
            )
            device_id = match.group("device_id")
            port_id = cls._normalize_port_id(match.group("port_id"))
            hold_time = int(match.group("hold_time"))
            capability = match.group("capability")

            entry: LldpNeighborEntry = {
                "device_id": device_id,
                "hold_time": hold_time,
                "capability": capability,
                "port_id": port_id,
            }

            if local_intf not in neighbors:
                neighbors[local_intf] = {}
            neighbors[local_intf][device_id] = entry

        if not neighbors:
            msg = "No LLDP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowLldpNeighborsResult, {"neighbors": neighbors})
