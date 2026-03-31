"""Parser for 'show ip interface brief' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IpInterfaceBriefEntry(TypedDict):
    """Schema for a single interface entry in 'show ip interface brief' output."""

    ip_address: str
    interface_status: str
    protocol_status: str
    vrf_name: str


class ShowIpInterfaceBriefResult(TypedDict):
    """Schema for 'show ip interface brief' parsed output.

    Dict-of-dicts keyed by interface name.
    """

    interfaces: dict[str, IpInterfaceBriefEntry]


@register(OS.CISCO_IOSXR, "show ip interface brief")
class ShowIpInterfaceBriefParser(BaseParser[ShowIpInterfaceBriefResult]):
    """Parser for 'show ip interface brief' command on Cisco IOS-XR.

    Parses the tabular IP interface summary output into a dict-of-dicts
    keyed by interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Matches a data line in the IP interface brief table.
    # Columns: Interface  IP-Address  Status  Protocol  Vrf-Name
    _INTF_LINE = re.compile(
        r"^\s*(?P<name>\S+)"
        r"\s+(?P<ip_address>\S+)"
        r"\s+(?P<status>Up|Down|Shutdown)"
        r"\s+(?P<protocol>Up|Down)"
        r"\s+(?P<vrf>\S+)"
        r"\s*$",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpInterfaceBriefResult:
        """Parse 'show ip interface brief' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IP interface brief information keyed by interface name.

        Raises:
            ValueError: If no interface entries can be parsed from the output.
        """
        interfaces: dict[str, IpInterfaceBriefEntry] = {}

        for line in output.splitlines():
            match = cls._INTF_LINE.match(line)
            if not match:
                continue

            name = canonical_interface_name(match.group("name"), os=OS.CISCO_IOSXR)
            entry = IpInterfaceBriefEntry(
                ip_address=match.group("ip_address"),
                interface_status=match.group("status").capitalize(),
                protocol_status=match.group("protocol").capitalize(),
                vrf_name=match.group("vrf"),
            )
            interfaces[name] = entry

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return cast(ShowIpInterfaceBriefResult, {"interfaces": interfaces})
