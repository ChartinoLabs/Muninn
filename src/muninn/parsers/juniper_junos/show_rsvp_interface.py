"""Parser for 'show rsvp interface' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RsvpInterfaceEntry(TypedDict):
    """Schema for a single RSVP interface entry.

    Attributes:
        interface: Interface name (e.g., ``ae0.0``).
        state: Interface state (e.g., ``Up``, ``Down``).
        active_reservations: Number of active RSVP reservations.
        subscription_percent: Subscription percentage.
        static_bandwidth_bps: Static bandwidth in bits per second.
        available_bandwidth_bps: Available bandwidth in bits per second.
        reserved_bandwidth_bps: Reserved bandwidth in bits per second.
        highwater_mark_bps: Highwater mark in bits per second.
    """

    interface: str
    state: str
    active_reservations: int
    subscription_percent: int
    static_bandwidth_bps: float
    available_bandwidth_bps: float
    reserved_bandwidth_bps: float
    highwater_mark_bps: float


class ShowRsvpInterfaceResult(TypedDict):
    """Schema for 'show rsvp interface' parsed output.

    Top-level dict-of-dicts keyed by interface name.
    """

    interfaces: dict[str, RsvpInterfaceEntry]


_BW_MULTIPLIERS: dict[str, float] = {
    "bps": 1.0,
    "kbps": 1e3,
    "mbps": 1e6,
    "gbps": 1e9,
    "tbps": 1e12,
}

# Pattern for bandwidth values like "400Gbps", "1.49104Mbps", "0bps"
_BW_PATTERN = re.compile(r"^(?P<value>[\d.]+)(?P<unit>[A-Za-z]+)$")

# Junos 'show rsvp interface' data line format:
# ae0.0                  Up      10    95%  400Gbps     380Gbps     200kbps     251kbps
_INTERFACE_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<active_resv>\d+)\s+"
    r"(?P<subscription>\d+)%\s+"
    r"(?P<static_bw>\S+)\s+"
    r"(?P<avail_bw>\S+)\s+"
    r"(?P<reserved_bw>\S+)\s+"
    r"(?P<highwater>\S+)\s*$"
)


def _parse_bandwidth(value: str) -> float:
    """Convert a Junos bandwidth string to bits per second.

    Args:
        value: Bandwidth string (e.g., ``400Gbps``, ``1.49104Mbps``, ``0bps``).

    Returns:
        Bandwidth in bits per second.

    Raises:
        ValueError: If the bandwidth string cannot be parsed.
    """
    match = _BW_PATTERN.match(value)
    if match is None:
        msg = f"Cannot parse bandwidth value: {value!r}"
        raise ValueError(msg)

    numeric = float(match.group("value"))
    unit = match.group("unit").lower()

    if unit not in _BW_MULTIPLIERS:
        msg = f"Unknown bandwidth unit: {match.group('unit')!r}"
        raise ValueError(msg)

    return numeric * _BW_MULTIPLIERS[unit]


@register(OS.JUNIPER_JUNOS, "show rsvp interface")
class ShowRsvpInterfaceParser(BaseParser[ShowRsvpInterfaceResult]):
    """Parser for 'show rsvp interface' command on Juniper Junos.

    Parses RSVP interface information including bandwidth allocation,
    reservation counts, and subscription levels. Interfaces are keyed
    by their name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> ShowRsvpInterfaceResult:
        """Parse 'show rsvp interface' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data keyed by interface name.

        Raises:
            ValueError: If no RSVP interfaces found in output.
        """
        interfaces: dict[str, RsvpInterfaceEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = _INTERFACE_PATTERN.match(stripped)
            if match is None:
                continue

            interface = match.group("interface")
            interfaces[interface] = RsvpInterfaceEntry(
                interface=interface,
                state=match.group("state"),
                active_reservations=int(match.group("active_resv")),
                subscription_percent=int(match.group("subscription")),
                static_bandwidth_bps=_parse_bandwidth(match.group("static_bw")),
                available_bandwidth_bps=_parse_bandwidth(match.group("avail_bw")),
                reserved_bandwidth_bps=_parse_bandwidth(match.group("reserved_bw")),
                highwater_mark_bps=_parse_bandwidth(match.group("highwater")),
            )

        if not interfaces:
            msg = "No RSVP interfaces found in output"
            raise ValueError(msg)

        return cast(ShowRsvpInterfaceResult, {"interfaces": interfaces})
