"""Parser for 'show ip ospf interface brief' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class OspfInterfaceEntry(TypedDict):
    """Schema for a single OSPF interface entry."""

    instance: int
    vrf: str
    area: str
    ip_address: str
    cost: int
    state: str
    neighbor_count: int


class ShowIpOspfInterfaceBriefResult(TypedDict):
    """Schema for 'show ip ospf interface brief' parsed output on Arista EOS."""

    interfaces: dict[str, OspfInterfaceEntry]


@register(OS.ARISTA_EOS, "show ip ospf interface brief")
class ShowIpOspfInterfaceBriefParser(
    BaseParser[ShowIpOspfInterfaceBriefResult],
):
    """Parser for 'show ip ospf interface brief' command on Arista EOS.

    Parses OSPF interface summary including area, cost, state, and
    neighbor counts. Returns a dict-of-dicts keyed by interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    # Matches data lines in the table output.
    # Example: Lo0  1  default  0.0.0.10  192.0.2.1/32  10  DR  0
    _ENTRY_PATTERN = re.compile(
        r"^\s*(?P<interface>\S+)\s+"
        r"(?P<instance>\d+)\s+"
        r"(?P<vrf>\S+)\s+"
        r"(?P<area>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<ip_address>\S+)\s+"
        r"(?P<cost>\d+)\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<nbrs>\d+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfInterfaceBriefResult:
        """Parse 'show ip ospf interface brief' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed OSPF interface entries keyed by canonical interface name.

        Raises:
            ValueError: If no OSPF interface entries found.
        """
        interfaces: dict[str, OspfInterfaceEntry] = {}

        for line in output.splitlines():
            match = cls._ENTRY_PATTERN.match(line)
            if not match:
                continue

            raw_name = match.group("interface")
            name = canonical_interface_name(raw_name, os=OS.ARISTA_EOS)

            interfaces[name] = OspfInterfaceEntry(
                instance=int(match.group("instance")),
                vrf=match.group("vrf"),
                area=match.group("area"),
                ip_address=match.group("ip_address"),
                cost=int(match.group("cost")),
                state=match.group("state"),
                neighbor_count=int(match.group("nbrs")),
            )

        if not interfaces:
            msg = "No OSPF interface entries found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfInterfaceBriefResult, {"interfaces": interfaces})
