"""Parser for 'show ip interface brief' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IpInterfaceBriefEntry(TypedDict):
    """Schema for a single interface entry from 'show ip interface brief'."""

    ip_address: NotRequired[str]
    status: str
    protocol: str
    mtu: int


class ShowIpInterfaceBriefResult(TypedDict):
    """Schema for 'show ip interface brief' parsed output on Arista EOS."""

    interfaces: dict[str, IpInterfaceBriefEntry]


@register(OS.ARISTA_EOS, "show ip interface brief")
class ShowIpInterfaceBriefParser(BaseParser[ShowIpInterfaceBriefResult]):
    """Parser for 'show ip interface brief' command on Arista EOS.

    Parses interface name, IP address, status, protocol, and MTU.
    Output is keyed by interface name using a dict-of-dicts pattern.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    _HEADER_PATTERN = re.compile(
        r"^\s*Interface\s+IP Address\s+Status\s+Protocol\s+MTU"
    )

    # Example lines:
    # Loopback0              1.1.1.1/32         up         up             65535
    # Management1            unassigned         down       down            1500
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<ip_address>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<protocol>\S+)\s+"
        r"(?P<mtu>\d+)\s*$"
    )

    _UNASSIGNED = "unassigned"

    @classmethod
    def parse(cls, output: str) -> ShowIpInterfaceBriefResult:
        """Parse 'show ip interface brief' output on Arista EOS.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed interface data keyed by interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, IpInterfaceBriefEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or cls._HEADER_PATTERN.match(stripped):
                continue

            match = cls._INTERFACE_PATTERN.match(stripped)
            if not match:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.ARISTA_EOS
            )
            ip_address = match.group("ip_address")
            status = match.group("status")
            protocol = match.group("protocol")
            mtu = int(match.group("mtu"))

            entry: IpInterfaceBriefEntry = {
                "status": status,
                "protocol": protocol,
                "mtu": mtu,
            }

            if ip_address.lower() != cls._UNASSIGNED:
                entry["ip_address"] = ip_address

            interfaces[interface] = entry

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(ShowIpInterfaceBriefResult, {"interfaces": interfaces})
