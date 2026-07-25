"""Parser for 'show mpls interfaces' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MplsInterfaceEntry(TypedDict):
    """Schema for a single MPLS interface entry."""

    ldp: bool
    tunnel: bool
    static: bool
    enabled: bool


ShowMplsInterfacesResult = dict[str, MplsInterfaceEntry]

# Matches a data line in the MPLS interfaces table.
# Example:
#   HundredGigE0/0/0/1.10     No       No       No       Yes
_INTF_LINE = re.compile(
    r"^\s*(?P<interface>\S+)"
    r"\s+(?P<ldp>Yes|No)"
    r"\s+(?P<tunnel>Yes|No)"
    r"\s+(?P<static>Yes|No)"
    r"\s+(?P<enabled>Yes|No)"
    r"\s*$",
    re.IGNORECASE,
)

_YES = "yes"


@register(OS.CISCO_IOSXR, "show mpls interfaces")
@register(OS.CISCO_IOSXR, "show mpls interface")
class ShowMplsInterfacesParser(BaseParser["ShowMplsInterfacesResult"]):
    """Parser for 'show mpls interfaces' / 'show mpls interface' on IOS-XR.

    Parses the MPLS interface table into a dict keyed by canonical
    interface name with LDP, tunnel, static, and enabled status.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> "ShowMplsInterfacesResult":
        """Parse 'show mpls interfaces' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by canonical interface name with MPLS status fields.

        Raises:
            ValueError: If no MPLS interface entries found in output.
        """
        result: ShowMplsInterfacesResult = {}

        for line in output.splitlines():
            match = _INTF_LINE.match(line)
            if match is None:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_IOSXR
            )
            result[interface] = MplsInterfaceEntry(
                ldp=match.group("ldp").lower() == _YES,
                tunnel=match.group("tunnel").lower() == _YES,
                static=match.group("static").lower() == _YES,
                enabled=match.group("enabled").lower() == _YES,
            )

        if not result:
            msg = "No MPLS interface entries found in output"
            raise ValueError(msg)

        return result
