"""Parser for 'show platform software nat ipalias' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register


class IpAliasEntry(TypedDict):
    """Schema for a single IP alias entry."""

    table_id: int


class ShowPlatformSoftwareNatIpaliasResult(TypedDict):
    """Schema for 'show platform software nat ipalias' parsed output."""

    ip_address: dict[str, IpAliasEntry]


# Matches data lines: "80.0.0.11           0"
_ENTRY = re.compile(rf"^(?P<ip>{IPV4_ADDRESS})\s+(?P<table_id>\d+)\s*$")

# Header line to skip
_HEADER = re.compile(r"^IP\s+Address\s+Table\s+ID", re.IGNORECASE)


@register(OS.CISCO_IOSXE, "show platform software nat ipalias")
class ShowPlatformSoftwareNatIpaliasParser(
    BaseParser[ShowPlatformSoftwareNatIpaliasResult],
):
    """Parser for 'show platform software nat ipalias' command.

    Example output::

        IP Address          Table ID
        80.0.0.11           0
    """

    tags: ClassVar[frozenset[str]] = frozenset({"nat", "platform"})

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareNatIpaliasResult:
        """Parse 'show platform software nat ipalias' output.

        Args:
            output: Raw CLI output from 'show platform software nat ipalias'.

        Returns:
            Parsed IP alias data keyed by IP address.

        Raises:
            ValueError: If no IP alias entries are found.
        """
        ip_addresses: dict[str, IpAliasEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _HEADER.match(stripped):
                continue

            match = _ENTRY.match(stripped)
            if match:
                ip = match.group("ip")
                table_id = int(match.group("table_id"))
                ip_addresses[ip] = IpAliasEntry(table_id=table_id)

        if not ip_addresses:
            msg = "No IP alias entries found in output"
            raise ValueError(msg)

        return ShowPlatformSoftwareNatIpaliasResult(ip_address=ip_addresses)
