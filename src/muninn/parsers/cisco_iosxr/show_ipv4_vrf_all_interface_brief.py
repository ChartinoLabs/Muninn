"""Parser for 'show ipv4 vrf all interface brief' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class Ipv4VrfInterfaceBriefEntry(TypedDict):
    """Single interface entry in 'show ipv4 vrf all interface brief'."""

    ip_address: str
    interface_status: str
    protocol_status: str
    vrf_name: str


class ShowIpv4VrfAllInterfaceBriefResult(TypedDict):
    """Schema for 'show ipv4 vrf all interface brief' parsed output.

    Dict-of-dicts keyed by interface name.
    """

    interfaces: dict[str, Ipv4VrfInterfaceBriefEntry]


@register(OS.CISCO_IOSXR, "show ipv4 vrf all interface brief")
class ShowIpv4VrfAllInterfaceBriefParser(
    BaseParser[ShowIpv4VrfAllInterfaceBriefResult],
):
    """Parser for 'show ipv4 vrf all interface brief' command on Cisco IOS-XR.

    Parses the tabular output into a dict-of-dicts keyed by interface name.
    Each entry contains the IP address, interface status, protocol status,
    and VRF name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
            ParserTag.VRF,
        }
    )

    # Matches data lines in the interface brief table.
    # Columns: Interface  IP-Address  Status  Protocol  Vrf-Name
    # VRF names prefixed with ** indicate the default/global VRF on some platforms.
    _INTF_LINE = re.compile(
        r"^\s*(?P<interface>\S+)"
        r"\s+(?P<ip_address>\d+\.\d+\.\d+\.\d+)"
        r"\s+(?P<status>\S+)"
        r"\s+(?P<protocol>\S+)"
        r"\s+(?:\*\*)?(?P<vrf>\S+)"
        r"\s*$",
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpv4VrfAllInterfaceBriefResult:
        """Parse 'show ipv4 vrf all interface brief' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface brief information keyed by interface name.

        Raises:
            ValueError: If no interface entries can be parsed from the output.
        """
        interfaces: dict[str, Ipv4VrfInterfaceBriefEntry] = {}

        for line in output.splitlines():
            match = cls._INTF_LINE.match(line)
            if not match:
                continue

            name = canonical_interface_name(match.group("interface"), os=OS.CISCO_IOSXR)
            entry = Ipv4VrfInterfaceBriefEntry(
                ip_address=match.group("ip_address"),
                interface_status=match.group("status"),
                protocol_status=match.group("protocol"),
                vrf_name=match.group("vrf"),
            )
            interfaces[name] = entry

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return cast(ShowIpv4VrfAllInterfaceBriefResult, {"interfaces": interfaces})
