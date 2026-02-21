"""Parser for 'show port-channel summary' command on NX-OS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class PortChannelMember(TypedDict):
    """Schema for a port-channel member interface."""

    status: str
    flags: str


class PortChannelEntry(TypedDict):
    """Schema for a single port-channel entry."""

    group: int
    mode: str
    status: str
    type: str
    protocol: str
    members: dict[str, PortChannelMember]


class ShowPortChannelSummaryResult(TypedDict):
    """Schema for 'show port-channel summary' parsed output."""

    port_channels: dict[str, PortChannelEntry]


# Member flag to status mapping
_MEMBER_STATUS_MAP: dict[str, str] = {
    "P": "up",
    "D": "down",
    "H": "hot_standby",
    "s": "suspended",
    "r": "module_removed",
    "I": "individual",
    "b": "bfd_wait",
    "p": "delay_lacp",
    "M": "min_links_not_met",
}


@register(OS.CISCO_NXOS, "show port-channel summary")
class ShowPortChannelSummaryParser(BaseParser[ShowPortChannelSummaryResult]):
    """Parser for 'show port-channel summary' command on NX-OS.

    Parses port-channel summary including member interfaces and their status.
    """

    # Pattern for port-channel line
    # 1     Po1(RU)     Eth      LACP      Eth1/1(P)    Eth1/2(P)
    # 131   Po131(SU)   Eth      LACP      Eth1/1(P)
    # 135   Po135(SD)   Eth      NONE      --
    _PORT_CHANNEL_PATTERN = re.compile(
        r"^(?P<group>\d+)\s+"
        r"(?P<name>Po\d+)\((?P<flags>[A-Z]+)\)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<protocol>LACP|NONE)\s+"
        r"(?P<members>.*)$"
    )

    # Pattern for continuation line (indented member ports)
    #                                      Eth1/46(P)   Eth1/47(D)   Eth1/48(P)
    _CONTINUATION_PATTERN = re.compile(r"^\s{20,}(?P<members>.+)$")

    # Pattern for individual member port with status
    # Eth1/1(P), Eth1/42(D), Eth1/5(H)
    _MEMBER_PATTERN = re.compile(r"(?P<interface>Eth\S+)\((?P<flag>[A-Za-z])\)")

    @classmethod
    def _parse_port_channel_flags(cls, flags: str) -> tuple[str, str]:
        """Parse port-channel status flags into mode and status.

        Args:
            flags: Raw flags string (e.g., "RU", "SU", "SD").

        Returns:
            Tuple of (mode, status).
        """
        mode = "routed" if "R" in flags else "switched"
        status = "up" if "U" in flags else "down"
        return mode, status

    @classmethod
    def _parse_members(cls, members_str: str) -> dict[str, PortChannelMember]:
        """Parse member ports string into dictionary.

        Args:
            members_str: Raw member ports string.

        Returns:
            Dictionary of member interfaces keyed by canonical interface name.
        """
        members: dict[str, PortChannelMember] = {}

        # Handle empty members (shown as "--")
        if not members_str or members_str.strip() == "--":
            return members

        for match in cls._MEMBER_PATTERN.finditer(members_str):
            interface = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_NXOS
            )
            flag = match.group("flag")
            status = _MEMBER_STATUS_MAP.get(flag, flag.lower())

            members[interface] = PortChannelMember(
                status=status,
                flags=flag,
            )

        return members

    @classmethod
    def _is_skippable_line(cls, line: str) -> bool:
        """Check if line should be skipped (header, legend, separator)."""
        stripped = line.strip()
        if not stripped:
            return True
        # Skip flag legend lines
        if stripped.startswith(
            ("Flags:", "I -", "s -", "b -", "S -", "U -", "p -", "M -")
        ):
            return True
        # Skip lines that are continuations of flag descriptions
        if stripped.startswith(("D -", "H -", "r -", "R -")):
            return True
        # Skip separator lines
        if stripped.startswith("---"):
            return True
        # Skip column header
        if "Group" in stripped and "Port-" in stripped:
            return True
        if stripped == "Channel":
            return True
        return False

    @classmethod
    def parse(cls, output: str) -> ShowPortChannelSummaryResult:
        """Parse 'show port-channel summary' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed port-channel summary data keyed by port-channel name.

        Raises:
            ValueError: If no port-channels found.
        """
        port_channels: dict[str, PortChannelEntry] = {}
        current_po: str | None = None

        for line in output.splitlines():
            if cls._is_skippable_line(line):
                continue

            # Try to match a new port-channel line
            po_match = cls._PORT_CHANNEL_PATTERN.match(line)
            if po_match:
                group = int(po_match.group("group"))
                name = canonical_interface_name(
                    po_match.group("name"), os=OS.CISCO_NXOS
                )
                flags = po_match.group("flags")
                po_type = po_match.group("type")
                protocol = po_match.group("protocol")
                members_str = po_match.group("members")

                mode, status = cls._parse_port_channel_flags(flags)
                members = cls._parse_members(members_str)

                port_channels[name] = PortChannelEntry(
                    group=group,
                    mode=mode,
                    status=status,
                    type=po_type,
                    protocol=protocol,
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
