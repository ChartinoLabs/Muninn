"""Parser for 'show ip dhcp binding' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class DhcpBindingEntry(TypedDict):
    """Schema for a single DHCP binding entry."""

    client_id: str
    lease_expiration: str
    type: str
    state: NotRequired[str]


class ShowIpDhcpBindingResult(TypedDict):
    """Schema for 'show ip dhcp binding' parsed output.

    Keyed by IP address.
    """

    bindings: dict[str, DhcpBindingEntry]


@register(OS.CISCO_IOS, "show ip dhcp binding")
class ShowIpDhcpBindingParser(BaseParser[ShowIpDhcpBindingResult]):
    """Parser for 'show ip dhcp binding' command.

    Parses DHCP binding table entries showing IP address, client ID/hardware
    address, lease expiration, type, and optional state.

    Example output::

        IP address       Client-ID/           Lease expiration  Type
                         Hardware address/
                         User name
        10.100.88.26     01aa.aaaa.aaaa.aa     Infinite          Manual
        10.100.88.197    01dd.dddd.dddd.dd     Infinite          Manual
    """

    tags: ClassVar[frozenset[str]] = frozenset({"dhcp"})

    # Matches a DHCP binding row:
    # IP address, client-ID/MAC, lease expiration, type, and optional state/interface
    _BINDING_PATTERN = re.compile(
        r"^(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"(?P<client_id>\S+)\s+"
        r"(?P<lease_expiration>Infinite|"
        r"\w+\s+\d+\s+\d+\s+\d+:\d+\s+[AP]M)\s+"
        r"(?P<type>\S+)"
        r"(?:\s+(?P<state>\S+))?"
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpDhcpBindingResult:
        """Parse 'show ip dhcp binding' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed DHCP binding entries keyed by IP address.

        Raises:
            ValueError: If no DHCP binding entries found.
        """
        bindings: dict[str, DhcpBindingEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._BINDING_PATTERN.match(line)
            if match:
                ip_address = match.group("ip_address")
                client_id = match.group("client_id").lower()
                lease_expiration = match.group("lease_expiration")
                binding_type = match.group("type")
                state = match.group("state")

                entry: DhcpBindingEntry = {
                    "client_id": client_id,
                    "lease_expiration": lease_expiration,
                    "type": binding_type,
                }

                if state and state != "--":
                    entry["state"] = state

                bindings[ip_address] = entry

        if not bindings:
            msg = "No DHCP binding entries found in output"
            raise ValueError(msg)

        return ShowIpDhcpBindingResult(bindings=bindings)
