"""Parser for 'show pim ipv4 interface' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PimIpv4InterfaceEntry(TypedDict):
    """Schema for a single PIM IPv4 interface entry."""

    address: str
    pim_enabled: bool
    neighbor_count: int
    hello_interval: int
    dr_priority: int
    dr_address: str


class ShowPimIpv4InterfaceResult(TypedDict):
    """Schema for 'show pim ipv4 interface' parsed output on IOS-XR."""

    vrfs: dict[str, dict[str, PimIpv4InterfaceEntry]]


# VRF section header: "PIM interfaces in VRF <name>"
_VRF_HEADER_PATTERN = re.compile(r"^PIM interfaces in VRF\s+(?P<vrf>\S+)\s*$")

# Data row pattern for IOS-XR show pim ipv4 interface:
# 192.0.2.1             BVI10                         on   11    30     1     192.0.2.2
_INTERFACE_PATTERN = re.compile(
    rf"^(?P<address>{IPV4_ADDRESS})\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<pim_enabled>on|off)\s+"
    r"(?P<neighbor_count>\d+)\s+"
    r"(?P<hello_interval>\d+)\s+"
    r"(?P<dr_priority>\d+)\s+"
    rf"(?P<dr_address>{IPV4_ADDRESS})\s*$"
)

# Default VRF name applied when no explicit VRF header has been seen yet.
_DEFAULT_VRF = "default"


@register(OS.CISCO_IOSXR, "show pim ipv4 interface")
class ShowPimIpv4InterfaceParser(BaseParser["ShowPimIpv4InterfaceResult"]):
    """Parser for 'show pim ipv4 interface' command on IOS-XR.

    Parses PIM IPv4 interface information including neighbor counts,
    hello intervals, DR priority, and designated router address.
    Results are grouped by VRF, then keyed by canonical interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MULTICAST})

    @classmethod
    def parse(cls, output: str) -> "ShowPimIpv4InterfaceResult":
        """Parse 'show pim ipv4 interface' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed PIM interface data grouped by VRF, then keyed by
            canonical interface name.

        Raises:
            ValueError: If no PIM interfaces found in output.
        """
        vrfs: dict[str, dict[str, PimIpv4InterfaceEntry]] = {}
        current_vrf: str | None = None

        for line in output.splitlines():
            stripped = line.strip()

            vrf_match = _VRF_HEADER_PATTERN.match(stripped)
            if vrf_match is not None:
                current_vrf = vrf_match.group("vrf")
                vrfs.setdefault(current_vrf, {})
                continue

            row_match = _INTERFACE_PATTERN.match(stripped)
            if row_match is None:
                continue

            vrf_name = current_vrf if current_vrf is not None else _DEFAULT_VRF
            vrf_entries = vrfs.setdefault(vrf_name, {})

            interface = canonical_interface_name(
                row_match.group("interface"),
                os=OS.CISCO_IOSXR,
            )
            vrf_entries[interface] = PimIpv4InterfaceEntry(
                address=row_match.group("address"),
                pim_enabled=row_match.group("pim_enabled") == "on",
                neighbor_count=int(row_match.group("neighbor_count")),
                hello_interval=int(row_match.group("hello_interval")),
                dr_priority=int(row_match.group("dr_priority")),
                dr_address=row_match.group("dr_address"),
            )

        if not any(vrfs.values()):
            msg = "No PIM interfaces found in output"
            raise ValueError(msg)

        return cast("ShowPimIpv4InterfaceResult", {"vrfs": vrfs})
