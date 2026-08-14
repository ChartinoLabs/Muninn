"""Parser for 'show interface ip brief' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class InterfaceBriefEntry(TypedDict):
    """Schema for a single interface entry."""

    ip_address: str
    ok: str
    method: str
    status: str
    protocol: str


class ShowInterfaceIpBriefResult(TypedDict):
    """Schema for 'show interface ip brief' parsed output."""

    interfaces: dict[str, InterfaceBriefEntry]


@register(OS.CISCO_FTD, "show interface ip brief")
class ShowInterfaceIpBriefParser(BaseParser[ShowInterfaceIpBriefResult]):
    """Parser for 'show interface ip brief' command.

    Parses interface IP addressing and status information on Cisco FTD.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # Pattern for interface entries
    # Interface  IP-Address  OK?  Method Status  Protocol
    # Port-channel1.111  172.16.1.5  YES  manual up  up
    # Port-channel3.212  unassigned  YES  unset  admin down  down
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        rf"(?P<ip_address>{IPV4_ADDRESS}|unassigned)\s+"
        r"(?P<ok>YES|NO)\s+"
        r"(?P<method>\S+)\s+"
        r"(?P<status>up|down|admin down|administratively down)\s+"
        r"(?P<protocol>up|down)\s*$",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceIpBriefResult:
        """Parse 'show interface ip brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data keyed by interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, InterfaceBriefEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._INTERFACE_PATTERN.match(line)
            if match:
                interface = match.group("interface")
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

        return ShowInterfaceIpBriefResult(interfaces=interfaces)
