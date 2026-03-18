"""Parser for 'show ip interface brief' command on IOS and IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.utils import canonical_interface_name


class InterfaceBriefEntry(TypedDict):
    """Schema for a single interface entry."""

    ip_address: str
    ok: str
    method: str
    status: str
    protocol: str


class ShowIpInterfaceBriefResult(TypedDict):
    """Schema for 'show ip interface brief' parsed output."""

    interfaces: dict[str, InterfaceBriefEntry]


@register(OS.CISCO_IOS, "show ip interface brief")
@register(OS.CISCO_IOSXE, "show ip interface brief")
class ShowIpInterfaceBriefParser(BaseParser[ShowIpInterfaceBriefResult]):
    """Parser for 'show ip interface brief' command.

    Parses interface IP addressing and status information.
    """

    # Pattern for interface entries
    # Interface              IP-Address      OK? Method Status                Protocol
    # GigabitEthernet0/0/0   10.105.44.23    YES other  up                    up
    # ucse1/0/0              10.19.14.1      YES other  administratively down down
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        rf"(?P<ip_address>{IPV4_ADDRESS}|unassigned)\s+"
        r"(?P<ok>YES|NO)\s+"
        r"(?P<method>\S+)\s+"
        r"(?P<status>up|down|administratively down|deleted)\s+"
        r"(?P<protocol>up|down)$",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpInterfaceBriefResult:
        """Parse 'show ip interface brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data keyed by interface name.

        Raises:
            ValueError: If no interfaces found.
        """
        interfaces: dict[str, InterfaceBriefEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._INTERFACE_PATTERN.match(line)
            if match:
                interface = canonical_interface_name(
                    match.group("interface"), os=OS.CISCO_IOSXE
                )
                interfaces[interface] = InterfaceBriefEntry(
                    ip_address=match.group("ip_address"),
                    ok=match.group("ok").upper(),
                    method=match.group("method"),
                    status=match.group("status").lower(),
                    protocol=match.group("protocol").lower(),
                )

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowIpInterfaceBriefResult(interfaces=interfaces)
