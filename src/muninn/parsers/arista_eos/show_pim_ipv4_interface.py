"""Parser for 'show pim ipv4 interface' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PimInterfaceEntry(TypedDict):
    """Schema for a single PIM interface entry."""

    address: str
    mode: str
    neighbor_count: int
    hello_interval: int
    dr_priority: int
    dr_address: str
    packets_queued: int
    packets_dropped: int


ShowPimIpv4InterfaceResult = dict[str, PimInterfaceEntry]


@register(OS.ARISTA_EOS, "show pim ipv4 interface")
class ShowPimIpv4InterfaceParser(BaseParser[ShowPimIpv4InterfaceResult]):
    """Parser for 'show pim ipv4 interface' command on Arista EOS.

    Parses PIM IPv4 interface information including neighbor counts,
    hello intervals, and designated router details.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MULTICAST})

    # Data line: address, interface, mode, neighbor_count, hello_intvl,
    #            dr_pri, dr_address, pkts_queued, pkts_dropped
    _ENTRY_PATTERN = re.compile(
        r"^(?P<address>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<interface>\S+)\s+"
        r"(?P<mode>\S+)\s+"
        r"(?P<neighbor_count>\d+)\s+"
        r"(?P<hello_interval>\d+)\s+"
        r"(?P<dr_priority>\d+)\s+"
        r"(?P<dr_address>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<packets_queued>\d+)\s+"
        r"(?P<packets_dropped>\d+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowPimIpv4InterfaceResult:
        """Parse 'show pim ipv4 interface' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of PIM interface entries keyed by canonical interface name.

        Raises:
            ValueError: If no PIM interface entries found.
        """
        result: ShowPimIpv4InterfaceResult = {}

        for line in output.splitlines():
            match = cls._ENTRY_PATTERN.match(line.strip())
            if not match:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.ARISTA_EOS
            )

            entry = PimInterfaceEntry(
                address=match.group("address"),
                mode=match.group("mode"),
                neighbor_count=int(match.group("neighbor_count")),
                hello_interval=int(match.group("hello_interval")),
                dr_priority=int(match.group("dr_priority")),
                dr_address=match.group("dr_address"),
                packets_queued=int(match.group("packets_queued")),
                packets_dropped=int(match.group("packets_dropped")),
            )

            result[interface] = entry

        if not result:
            msg = "No PIM interface entries found in output"
            raise ValueError(msg)

        return cast(ShowPimIpv4InterfaceResult, result)
