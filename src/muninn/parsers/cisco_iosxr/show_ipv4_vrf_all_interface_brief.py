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


class ShowIpv4VrfAllInterfaceBriefResult(TypedDict):
    """Schema for 'show ipv4 vrf all interface brief' parsed output.

    Outer dict keys are VRF names; inner dicts are keyed by interface name.
    """

    vrfs: dict[str, dict[str, Ipv4VrfInterfaceBriefEntry]]


@register(OS.CISCO_IOSXR, "show ipv4 vrf all interface brief")
class ShowIpv4VrfAllInterfaceBriefParser(
    BaseParser[ShowIpv4VrfAllInterfaceBriefResult],
):
    """Parser for 'show ipv4 vrf all interface brief' command on Cisco IOS-XR.

    Parses the tabular output into a nested dict keyed first by VRF name and
    then by interface name. Each entry contains the IP address and the
    interface and protocol status.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
            ParserTag.VRF,
        }
    )

    # Matches data lines in the interface brief table.
    # Columns: Interface  IP-Address  Status  Protocol  Vrf-Name
    # VRF names may be prefixed with ``**`` on IOS-XR; the marker is
    # stripped from the VRF name.
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
            Parsed interface brief information keyed by VRF name and then
            by interface name.

        Raises:
            ValueError: If no interface entries can be parsed from the output.
        """
        vrfs: dict[str, dict[str, Ipv4VrfInterfaceBriefEntry]] = {}

        for line in output.splitlines():
            match = cls._INTF_LINE.match(line)
            if not match:
                continue

            name = canonical_interface_name(match.group("interface"), os=OS.CISCO_IOSXR)
            entry = Ipv4VrfInterfaceBriefEntry(
                ip_address=match.group("ip_address"),
                interface_status=match.group("status"),
                protocol_status=match.group("protocol"),
            )
            vrf_name = match.group("vrf")
            vrfs.setdefault(vrf_name, {})[name] = entry

        if not vrfs:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return cast(ShowIpv4VrfAllInterfaceBriefResult, {"vrfs": vrfs})
