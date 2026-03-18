"""Parser for 'show interface snmp-ifindex' command on NX-OS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceSnmpIfindexEntry(TypedDict):
    """Schema for a single interface SNMP ifIndex entry."""

    ifindex: int


class ShowInterfaceSnmpIfindexResult(TypedDict):
    """Schema for 'show interface snmp-ifindex' parsed output."""

    interfaces: dict[str, InterfaceSnmpIfindexEntry]


@register(OS.CISCO_NXOS, "show interface snmp-ifindex")
class ShowInterfaceSnmpIfindexParser(BaseParser[ShowInterfaceSnmpIfindexResult]):
    """Parser for 'show interface snmp-ifindex' command on NX-OS.

    Parses the SNMP ifIndex table mapping interface names to their
    persistent ifIndex values.

    Example output::

        ---------------------------------------------------------------
        Interface            IFMIB Ifindex
        ---------------------------------------------------------------
        mgmt0                83886080 (0x05000000)
        Eth1/1               436207616 (0x1a000000)
        Eth1/2               436211712 (0x1a001000)
        Lo0                  335544320 (0x14000000)
        Vlan1                150994945 (0x09000001)
        Po10                 369098762 (0x16000002)
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # Matches lines like: Eth1/1  436207616 (0x1a000000)
    # The hex value in parentheses is optional on some platforms.
    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+(?P<ifindex>\d+)(?:\s+\(0x[0-9a-fA-F]+\))?\s*$"
    )

    # Header/separator lines to skip
    _SKIP_PATTERN = re.compile(r"^(?:-+|Interface\s+)", re.IGNORECASE)

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceSnmpIfindexResult:
        """Parse 'show interface snmp-ifindex' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface-to-ifIndex mapping keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found in the output.
        """
        interfaces: dict[str, InterfaceSnmpIfindexEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or cls._SKIP_PATTERN.match(stripped):
                continue

            match = cls._ROW_PATTERN.match(stripped)
            if not match:
                continue

            interface_name = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_NXOS
            )
            ifindex = int(match.group("ifindex"))

            interfaces[interface_name] = InterfaceSnmpIfindexEntry(ifindex=ifindex)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowInterfaceSnmpIfindexResult(interfaces=interfaces)
