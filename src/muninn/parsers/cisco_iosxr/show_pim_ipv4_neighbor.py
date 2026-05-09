"""Parser for 'show pim ipv4 neighbor' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PimNeighborEntry(TypedDict):
    """Schema for a single PIM neighbor entry."""

    interface: str
    uptime: str
    expires: str
    dr_priority: int
    is_designated_router: bool
    bidir_capable: bool
    proxy_capable: bool
    ecmp_redirect_capable: bool
    is_self: bool


class ShowPimIpv4NeighborResult(TypedDict):
    """Schema for 'show pim ipv4 neighbor' parsed output on IOS-XR."""

    vrfs: dict[str, dict[str, PimNeighborEntry]]


# VRF context header: "PIM neighbors in VRF default"
_VRF_HEADER_PATTERN = re.compile(r"^PIM neighbors in VRF\s+(?P<vrf>\S+)\s*$")

# Neighbor row pattern for IOS-XR PIM neighbor table:
# 192.0.2.1*                   Bundle-Ether10.10      1d09h     00:01:29 1      B E
# 192.0.2.2                    Bundle-Ether10.20      02:26:23  00:01:26 1 (DR)
_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<address>{IPV4_ADDRESS})(?P<self_flag>\*)?\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<uptime>\S+)\s+"
    r"(?P<expires>\S+)\s+"
    r"(?P<dr_pri>\d+)\s*"
    r"(?P<dr_flag>\(DR\))?\s*"
    r"(?P<flags>[BPDE\s]*)$"
)

# Default VRF name when no explicit VRF header is present in the output.
_DEFAULT_VRF = "default"


@register(OS.CISCO_IOSXR, "show pim ipv4 neighbor")
class ShowPimIpv4NeighborParser(BaseParser["ShowPimIpv4NeighborResult"]):
    """Parser for 'show pim ipv4 neighbor' command on IOS-XR.

    Parses PIM neighbor adjacency information.  Neighbors are grouped by
    VRF (outermost key) and then keyed by neighbor IP address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MULTICAST})

    @classmethod
    def parse(cls, output: str) -> "ShowPimIpv4NeighborResult":
        """Parse 'show pim ipv4 neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data grouped by VRF, then keyed by neighbor
            IP address.

        Raises:
            ValueError: If no PIM neighbors found in output.
        """
        vrfs: dict[str, dict[str, PimNeighborEntry]] = {}
        current_vrf = _DEFAULT_VRF

        for line in output.splitlines():
            stripped = line.strip()

            vrf_match = _VRF_HEADER_PATTERN.match(stripped)
            if vrf_match is not None:
                current_vrf = vrf_match.group("vrf")
                vrfs.setdefault(current_vrf, {})
                continue

            neighbor_match = _NEIGHBOR_PATTERN.match(stripped)
            if neighbor_match is None:
                continue

            address = neighbor_match.group("address")
            flags = neighbor_match.group("flags").strip()
            flag_set = set(flags.split()) if flags else set()
            interface = canonical_interface_name(
                neighbor_match.group("interface"),
                os=OS.CISCO_IOSXR,
            )

            entry: PimNeighborEntry = {
                "interface": interface,
                "uptime": neighbor_match.group("uptime"),
                "expires": neighbor_match.group("expires"),
                "dr_priority": int(neighbor_match.group("dr_pri")),
                "is_designated_router": neighbor_match.group("dr_flag") is not None,
                "bidir_capable": "B" in flag_set,
                "proxy_capable": "P" in flag_set,
                "ecmp_redirect_capable": "E" in flag_set,
                "is_self": neighbor_match.group("self_flag") is not None,
            }

            vrfs.setdefault(current_vrf, {})[address] = entry

        if not any(vrfs.values()):
            msg = "No PIM neighbors found in output"
            raise ValueError(msg)

        return {"vrfs": vrfs}
