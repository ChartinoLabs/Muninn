"""Parser for 'show interfaces brief' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceBriefEntry(TypedDict):
    """Schema for a single interface entry in 'show interfaces brief' output."""

    interface_state: str
    line_protocol_state: str
    encapsulation_type: str
    mtu: int
    bandwidth_kbps: int


class ShowInterfacesBriefResult(TypedDict):
    """Schema for 'show interfaces brief' parsed output.

    Dict-of-dicts keyed by interface name.
    """

    interfaces: dict[str, InterfaceBriefEntry]


@register(OS.CISCO_IOSXR, "show interfaces brief")
class ShowInterfacesBriefParser(BaseParser[ShowInterfacesBriefResult]):
    """Parser for 'show interfaces brief' command on Cisco IOS-XR.

    Parses the tabular interface summary output into a dict-of-dicts
    keyed by interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Matches a data line in the interface brief table.
    # Columns: IntfName  IntfState  LinePState  EncapType  MTU  BW
    # Interface names and states may contain hyphens, slashes, dots, colons.
    _INTF_LINE = re.compile(
        r"^\s*(?P<name>\S+)"
        r"\s+(?P<intf_state>up|down|admin-down)"
        r"\s+(?P<line_state>up|down|admin-down)"
        r"\s+(?P<encap>\S+)"
        r"\s+(?P<mtu>\d+)"
        r"\s+(?P<bw>\d+)"
        r"\s*$",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesBriefResult:
        """Parse 'show interfaces brief' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface brief information keyed by interface name.

        Raises:
            ValueError: If no interface entries can be parsed from the output.
        """
        interfaces: dict[str, InterfaceBriefEntry] = {}

        for line in output.splitlines():
            match = cls._INTF_LINE.match(line)
            if not match:
                continue

            name = canonical_interface_name(match.group("name"), os=OS.CISCO_IOSXR)
            entry = InterfaceBriefEntry(
                interface_state=match.group("intf_state"),
                line_protocol_state=match.group("line_state"),
                encapsulation_type=match.group("encap"),
                mtu=int(match.group("mtu")),
                bandwidth_kbps=int(match.group("bw")),
            )
            interfaces[name] = entry

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return cast(ShowInterfacesBriefResult, {"interfaces": interfaces})
