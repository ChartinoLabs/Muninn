"""Parser for 'show etherchannel summary' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class MemberPort(TypedDict):
    """Schema for a single port-channel member port."""

    status: str
    interface: str


class PortChannelEntry(TypedDict):
    """Schema for a single port-channel group entry."""

    port_channel: str
    port_channel_status: str
    layer: str
    protocol: NotRequired[str]
    members: NotRequired[dict[str, MemberPort]]


class ShowEtherchannelSummaryResult(TypedDict):
    """Schema for 'show etherchannel summary' parsed output."""

    num_channel_groups: int
    num_aggregators: int
    port_channels: dict[str, PortChannelEntry]


_STATUS_MAP: dict[str, str] = {
    "D": "down",
    "U": "in-use",
}

_LAYER_MAP: dict[str, str] = {
    "R": "Layer3",
    "S": "Layer2",
}

_GROUP_LINE_PATTERN = re.compile(
    r"^(?P<group>\d+)\s+"
    r"(?P<po_status>\S+\([A-Za-z]+\))\s+"
    r"(?P<protocol>\S+)"
    r"(?P<ports>.*)",
)

_NUM_CHANNEL_GROUPS_PATTERN = re.compile(
    r"Number of channel-groups in use:\s*(?P<value>\d+)",
)

_NUM_AGGREGATORS_PATTERN = re.compile(
    r"Number of aggregators:\s*(?P<value>\d+)",
)

_CONTINUATION_PORT_PATTERN = re.compile(
    r"^\s+\S+\([^)]+\)",
)


def _parse_port_channel_status(raw: str) -> tuple[str, str, str]:
    """Extract port-channel name, layer, and status from e.g. 'Po1(SU)'.

    Returns:
        Tuple of (port_channel_name, layer, status).
    """
    match = re.match(r"(\S+?)\(([A-Za-z]+)\)", raw)
    if not match:
        msg = f"Cannot parse port-channel status: {raw}"
        raise ValueError(msg)
    name = match.group(1)
    flags = match.group(2)
    layer = _LAYER_MAP.get(flags[0], flags[0])
    status = _STATUS_MAP.get(flags[1], flags[1])
    return name, layer, status


def _parse_member_ports(text: str) -> dict[str, MemberPort]:
    """Parse member port entries like 'Gi2(bndl) Gi3(P)' into a dict."""
    members: dict[str, MemberPort] = {}
    for match in re.finditer(r"(\S+?)\(([^)]+)\)", text):
        raw_iface = match.group(1)
        port_status = match.group(2)
        iface = canonical_interface_name(raw_iface)
        members[iface] = MemberPort(
            interface=iface,
            status=port_status,
        )
    return members


def _build_group_entry(match: re.Match[str]) -> tuple[str, PortChannelEntry]:
    """Build a PortChannelEntry from a group line regex match.

    Returns:
        Tuple of (group_id, entry).
    """
    group = match.group("group")
    po_name, layer, status = _parse_port_channel_status(
        match.group("po_status"),
    )
    protocol = match.group("protocol")
    ports_text = match.group("ports")

    entry = PortChannelEntry(
        port_channel=po_name,
        port_channel_status=status,
        layer=layer,
    )

    if protocol != "-":
        entry["protocol"] = protocol

    members = _parse_member_ports(ports_text)
    if members:
        entry["members"] = members

    return group, entry


def _add_continuation_ports(
    port_channels: dict[str, PortChannelEntry],
    group: str,
    line: str,
) -> None:
    """Add member ports from a continuation line to an existing group."""
    members = _parse_member_ports(line)
    if members:
        existing = port_channels[group].get("members", {})
        existing.update(members)
        port_channels[group]["members"] = existing


def _validate_required_fields(
    num_channel_groups: int | None,
    num_aggregators: int | None,
) -> tuple[int, int]:
    """Validate that required summary fields were found.

    Returns:
        Tuple of (num_channel_groups, num_aggregators).

    Raises:
        ValueError: If required fields are missing.
    """
    missing = []
    if num_channel_groups is None:
        missing.append("num_channel_groups")
    if num_aggregators is None:
        missing.append("num_aggregators")
    if missing:
        msg = f"Missing required fields: {', '.join(missing)}"
        raise ValueError(msg)
    return num_channel_groups, num_aggregators


@register(OS.CISCO_IOS, "show etherchannel summary")
class ShowEtherchannelSummaryParser(BaseParser[ShowEtherchannelSummaryResult]):
    """Parser for 'show etherchannel summary' command.

    Example output:
        Group  Port-channel  Protocol    Ports
        1      Po1(SU)         LACP      Te6/4(P)       Te3/5(P)
        3      Po3(SU)         LACP      Te4/2(P)       Te2/2(P)
    """

    @classmethod
    def parse(cls, output: str) -> ShowEtherchannelSummaryResult:
        """Parse 'show etherchannel summary' output.

        Args:
            output: Raw CLI output from 'show etherchannel summary' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        num_channel_groups: int | None = None
        num_aggregators: int | None = None
        port_channels: dict[str, PortChannelEntry] = {}
        current_group: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = _NUM_CHANNEL_GROUPS_PATTERN.search(stripped)
            if match:
                num_channel_groups = int(match.group("value"))
                continue

            match = _NUM_AGGREGATORS_PATTERN.search(stripped)
            if match:
                num_aggregators = int(match.group("value"))
                continue

            match = _GROUP_LINE_PATTERN.match(stripped)
            if match:
                group, entry = _build_group_entry(match)
                port_channels[group] = entry
                current_group = group
                continue

            if current_group is not None and _CONTINUATION_PORT_PATTERN.match(line):
                _add_continuation_ports(port_channels, current_group, stripped)

        groups, aggregators = _validate_required_fields(
            num_channel_groups, num_aggregators
        )

        return ShowEtherchannelSummaryResult(
            num_channel_groups=groups,
            num_aggregators=aggregators,
            port_channels=port_channels,
        )
