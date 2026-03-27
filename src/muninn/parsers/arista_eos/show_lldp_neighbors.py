"""Parser for 'show lldp neighbors' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class LldpNeighborEntry(TypedDict):
    """Schema for a single LLDP neighbor entry."""

    hold_time: int
    port_id: str


class ShowLldpNeighborsResult(TypedDict):
    """Schema for 'show lldp neighbors' parsed output on Arista EOS."""

    neighbors: dict[str, dict[str, LldpNeighborEntry]]


# Arista EOS LLDP neighbor table format:
#
# Port       Neighbor Device ID             Neighbor Port ID           TTL
# Et1        localhost                      Ethernet1                  120
# Ma1/1      dc1-rack11-tor1.sjc            1/1                        120
#
# Some versions include a dashed separator line below the header.

# Lines to skip: blank, header, separator, table statistics
_SKIP_PATTERNS = re.compile(
    r"^\s*$"
    r"|^Port\s+"
    r"|^-{3,}"
    r"|^Last\s+table\s+change"
    r"|^Number\s+of\s+table\s+",
    re.IGNORECASE,
)

# EOS local interface abbreviations: Et, Ma, Po, Lo, Vl, Tu
_LOCAL_INTF_PREFIX = r"(?:Et|Ma|Po|Lo|Vl|Tu)"

_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<local_intf>{_LOCAL_INTF_PREFIX}\S+)\s+"
    r"(?P<device_id>\S+(?:\s+\S+)*?)\s+"
    r"(?P<port_id>\S+)\s+"
    r"(?P<ttl>\d+)\s*$"
)

# Port ID that looks like an interface name and should be canonicalized.
_INTERFACE_PORT_ID_PATTERN = re.compile(
    r"^(?:Eth(?:ernet)?|Et|Ma(?:nagement)?|Po(?:rt-Channel)?|"
    r"Lo(?:opback)?|Vl(?:an)?|Tu(?:nnel)?|Gi|Te|Fo|Hu)\d",
    re.IGNORECASE,
)


@register(OS.ARISTA_EOS, "show lldp neighbors")
class ShowLldpNeighborsParser(BaseParser[ShowLldpNeighborsResult]):
    """Parser for 'show lldp neighbors' command on Arista EOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    @classmethod
    def _normalize_port_id(cls, port_id: str) -> str:
        """Normalize port_id if it looks like an interface name."""
        if _INTERFACE_PORT_ID_PATTERN.match(port_id):
            return canonical_interface_name(port_id, os=OS.ARISTA_EOS)
        return port_id

    @classmethod
    def parse(cls, output: str) -> ShowLldpNeighborsResult:
        """Parse 'show lldp neighbors' output on Arista EOS.

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
                match.group("local_intf"), os=OS.ARISTA_EOS
            )
            device_id = match.group("device_id")
            port_id = cls._normalize_port_id(match.group("port_id"))
            hold_time = int(match.group("ttl"))

            entry: LldpNeighborEntry = {
                "hold_time": hold_time,
                "port_id": port_id,
            }

            if local_intf not in neighbors:
                neighbors[local_intf] = {}
            neighbors[local_intf][device_id] = entry

        if not neighbors:
            msg = "No LLDP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowLldpNeighborsResult, {"neighbors": neighbors})
