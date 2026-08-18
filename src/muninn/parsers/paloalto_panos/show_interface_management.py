"""Parser for 'show interface management' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS_COLON
from muninn.registry import register
from muninn.tags import ParserTag


class ShowInterfaceManagementCounters(TypedDict):
    """Counter statistics for the management interface."""

    bytes_received: int
    bytes_transmitted: int
    packets_received: int
    packets_transmitted: int
    receive_errors: int
    transmit_errors: int
    receive_packets_dropped: int
    transmit_packets_dropped: int
    multicast_packets_received: int


class ShowInterfaceManagementResult(TypedDict):
    """Schema for 'show interface management' parsed output."""

    name: str
    runtime_speed: str
    runtime_duplex: str
    runtime_state: str
    configured_speed: str
    configured_duplex: str
    configured_state: str
    mac_address: str
    ip_address: NotRequired[str]
    netmask: NotRequired[str]
    default_gateway: NotRequired[str]
    ipv6_address: NotRequired[str]
    ipv6_link_local_address: NotRequired[str]
    ipv6_default_gateway: NotRequired[str]
    counters: ShowInterfaceManagementCounters


_RUNTIME_LINK = re.compile(
    r"Runtime link speed/duplex/state:\s+"
    r"(?P<speed>\S+)/(?P<duplex>\S+)/(?P<state>\S+)"
)

_CONFIGURED_LINK = re.compile(
    r"Configured link speed/duplex/state:\s+"
    r"(?P<speed>\S+)/(?P<duplex>\S+)/(?P<state>\S+)"
)

_MAC = re.compile(rf"Port MAC address\s+(?P<mac>{MAC_ADDRESS_COLON})")

_IP_ADDRESS = re.compile(rf"Ip address:\s+(?P<ip>{IPV4_ADDRESS})")
_NETMASK = re.compile(rf"Netmask:\s+(?P<netmask>{IPV4_ADDRESS})")
_GATEWAY = re.compile(rf"Default gateway:\s+(?P<gw>{IPV4_ADDRESS})")

_IPV6_ADDRESS = re.compile(r"^Ipv6 address:[ \t]+(?P<addr>\S+)", re.MULTILINE)
_IPV6_LINK_LOCAL = re.compile(
    r"^Ipv6 link local address:[ \t]+(?P<addr>\S+)", re.MULTILINE
)
_IPV6_GATEWAY = re.compile(r"^Ipv6 default gateway:[ \t]+(?P<gw>\S+)", re.MULTILINE)

# Counter patterns: label -> dict key
_COUNTER_MAP: dict[str, str] = {
    "bytes received": "bytes_received",
    "bytes transmitted": "bytes_transmitted",
    "packets received": "packets_received",
    "packets transmitted": "packets_transmitted",
    "receive errors": "receive_errors",
    "transmit errors": "transmit_errors",
    "receive packets dropped": "receive_packets_dropped",
    "transmit packets dropped": "transmit_packets_dropped",
    "multicast packets received": "multicast_packets_received",
}

_COUNTER_LINE = re.compile(r"^(?P<label>[a-z ]+?)\s{2,}(?P<value>\d+)\s*$")

_UNKNOWN_VALUES = frozenset({"unknown", ""})


@register(OS.PALOALTO_PANOS, "show interface management")
class ShowInterfaceManagementParser(BaseParser[ShowInterfaceManagementResult]):
    """Parser for 'show interface management' command on Palo Alto PAN-OS.

    Parses link status (speed/duplex/state), MAC address, IP configuration,
    IPv6 configuration, and logical interface counters for the management
    interface.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceManagementResult:
        """Parse 'show interface management' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed management interface data.

        Raises:
            ValueError: If required fields are not found in output.
        """
        result: dict[str, object] = {"name": "Management Interface"}

        cls._parse_link_status(output, result)
        cls._parse_addressing(output, result)
        cls._parse_counters(output, result)

        return cast(ShowInterfaceManagementResult, result)

    @classmethod
    def _parse_link_status(cls, output: str, result: dict[str, object]) -> None:
        """Extract runtime/configured link speed, duplex, and state."""
        match = _RUNTIME_LINK.search(output)
        if not match:
            msg = "No runtime link status found in output"
            raise ValueError(msg)
        result["runtime_speed"] = match.group("speed")
        result["runtime_duplex"] = match.group("duplex")
        result["runtime_state"] = match.group("state")

        match = _CONFIGURED_LINK.search(output)
        if not match:
            msg = "No configured link status found in output"
            raise ValueError(msg)
        result["configured_speed"] = match.group("speed")
        result["configured_duplex"] = match.group("duplex")
        result["configured_state"] = match.group("state")

        match = _MAC.search(output)
        if not match:
            msg = "No MAC address found in output"
            raise ValueError(msg)
        result["mac_address"] = match.group("mac")

    @classmethod
    def _parse_addressing(cls, output: str, result: dict[str, object]) -> None:
        """Extract IP, netmask, gateway, and IPv6 fields (omitting unknowns)."""
        match = _IP_ADDRESS.search(output)
        if match:
            result["ip_address"] = match.group("ip")

        match = _NETMASK.search(output)
        if match:
            result["netmask"] = match.group("netmask")

        match = _GATEWAY.search(output)
        if match:
            result["default_gateway"] = match.group("gw")

        # IPv6 fields: omit if value is "unknown" or empty
        for pattern, key in (
            (_IPV6_ADDRESS, "ipv6_address"),
            (_IPV6_LINK_LOCAL, "ipv6_link_local_address"),
            (_IPV6_GATEWAY, "ipv6_default_gateway"),
        ):
            match = pattern.search(output)
            if match:
                value = match.group(1)
                if value not in _UNKNOWN_VALUES:
                    result[key] = value

    @classmethod
    def _parse_counters(cls, output: str, result: dict[str, object]) -> None:
        """Extract logical interface counters."""
        counters: dict[str, int] = {}
        for line in output.splitlines():
            stripped = line.strip()
            match = _COUNTER_LINE.match(stripped)
            if not match:
                continue
            label = match.group("label")
            if label in _COUNTER_MAP:
                counters[_COUNTER_MAP[label]] = int(match.group("value"))

        expected_count = len(_COUNTER_MAP)
        if len(counters) != expected_count:
            msg = f"Expected {expected_count} counters, found {len(counters)}"
            raise ValueError(msg)

        result["counters"] = counters
