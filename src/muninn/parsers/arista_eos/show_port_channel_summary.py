"""Parser for 'show port-channel summary' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PortChannelMember(TypedDict):
    """Schema for a port-channel member interface."""

    flags: str


class PortChannelEntry(TypedDict):
    """Schema for a single port-channel entry."""

    group: int
    status: str
    protocol: str
    protocol_flags: str
    members: dict[str, PortChannelMember]


class ShowPortChannelSummaryResult(TypedDict):
    """Schema for 'show port-channel summary' parsed output."""

    port_channels: dict[str, PortChannelEntry]


# Port-channel status flag to human-readable status mapping.
_PO_STATUS_MAP: dict[str, str] = {
    "U": "up",
    "D": "down",
}


@register(OS.ARISTA_EOS, "show port-channel summary")
class ShowPortChannelSummaryParser(BaseParser[ShowPortChannelSummaryResult]):
    """Parser for 'show port-channel summary' command on Arista EOS.

    Parses port-channel summary including member interfaces and their flags.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
            ParserTag.LAG,
        }
    )

    # Port-channel line:
    #    Po105(D)           LACP(aF*)    Et5(D)
    #    Po2000(U)          LACP(a)      Et54/1(PG+)
    _PORT_CHANNEL_PATTERN = re.compile(
        r"^\s+Po(?P<group>\d+)\((?P<status>[A-Z])\)\s+"
        r"(?P<protocol>[A-Z]+)\((?P<proto_flags>[^)]*)\)\s+"
        r"(?P<members>.*)$"
    )

    # Continuation line (indented member ports with no port-channel name).
    _CONTINUATION_PATTERN = re.compile(r"^\s{20,}(?P<members>.+)$")

    # Individual member port: Et5(D), Et54/1(PG+), Et1(siI)
    _MEMBER_PATTERN = re.compile(r"(?P<interface>Et\S+?)\((?P<flags>[^)]+)\)")

    @classmethod
    def _parse_members(cls, members_str: str) -> dict[str, PortChannelMember]:
        """Parse member ports string into dictionary.

        Args:
            members_str: Raw member ports string.

        Returns:
            Dictionary of member interfaces keyed by canonical interface name.
        """
        members: dict[str, PortChannelMember] = {}

        for match in cls._MEMBER_PATTERN.finditer(members_str):
            interface = canonical_interface_name(
                match.group("interface"), os=OS.ARISTA_EOS
            )
            flags = match.group("flags")
            members[interface] = PortChannelMember(flags=flags)

        return members

    @classmethod
    def parse(cls, output: str) -> ShowPortChannelSummaryResult:
        """Parse 'show port-channel summary' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed port-channel summary data keyed by port-channel name.

        Raises:
            ValueError: If no port-channels found in output.
        """
        port_channels: dict[str, PortChannelEntry] = {}
        current_po: str | None = None

        for line in output.splitlines():
            # Try to match a new port-channel line
            po_match = cls._PORT_CHANNEL_PATTERN.match(line)
            if po_match:
                group = int(po_match.group("group"))
                name = canonical_interface_name(f"Po{group}", os=OS.ARISTA_EOS)
                status_flag = po_match.group("status")
                protocol = po_match.group("protocol")
                proto_flags = po_match.group("proto_flags")
                members_str = po_match.group("members")

                status = _PO_STATUS_MAP.get(status_flag, status_flag.lower())
                members = cls._parse_members(members_str)

                port_channels[name] = PortChannelEntry(
                    group=group,
                    status=status,
                    protocol=protocol,
                    protocol_flags=proto_flags,
                    members=members,
                )
                current_po = name
                continue

            # Try to match continuation line (wrapped member ports)
            cont_match = cls._CONTINUATION_PATTERN.match(line)
            if cont_match and current_po:
                members_str = cont_match.group("members")
                additional_members = cls._parse_members(members_str)
                port_channels[current_po]["members"].update(additional_members)
                continue

        if not port_channels:
            msg = "No port-channels found in output"
            raise ValueError(msg)

        return ShowPortChannelSummaryResult(port_channels=port_channels)
