"""Parser for 'show ip' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IpEntry(TypedDict):
    """Schema for a single IP address entry."""

    nameif: str
    ip_address: str
    subnet_mask: str
    method: str


class ShowIpResult(TypedDict):
    """Schema for 'show ip' parsed output."""

    system_addresses: dict[str, IpEntry]
    current_addresses: dict[str, IpEntry]


@register(OS.CISCO_FTD, "show ip")
class ShowIpParser(BaseParser[ShowIpResult]):
    """Parser for 'show ip' command on Cisco FTD.

    Parses system and current IP address tables showing interface IP
    configuration including nameif, IP address, subnet mask, and method.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    _IP_OCTET = r"\d{1,3}(?:\.\d{1,3}){3}"

    # Full entry: Interface  Name  IP  Mask  Method
    _ENTRY_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<nameif>\S+)\s+"
        rf"(?P<ip_address>{_IP_OCTET})\s+"
        rf"(?P<subnet_mask>{_IP_OCTET})\s+"
        r"(?P<method>\S+)\s*$"
    )

    # Continuation line (wrapped IP/mask/method from previous line)
    _CONTINUATION_PATTERN = re.compile(
        r"^\s+"
        rf"(?P<ip_address>{_IP_OCTET})\s+"
        rf"(?P<subnet_mask>{_IP_OCTET})\s+"
        r"(?P<method>\S+)\s*$"
    )

    # Partial line: interface + nameif only, IP wraps to next line
    _PARTIAL_PATTERN = re.compile(r"^(?P<interface>\S+)\s+(?P<nameif>\S+)\s*$")

    @classmethod
    def _parse_section(cls, lines: list[str]) -> dict[str, IpEntry]:
        """Parse a single section of the show ip output.

        Args:
            lines: Lines belonging to one section (after the header).

        Returns:
            Dict of interface name to IpEntry.
        """
        entries: dict[str, IpEntry] = {}
        pending_interface: str | None = None
        pending_nameif: str | None = None

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("Interface"):
                pending_interface = None
                pending_nameif = None
                continue

            # Try full entry on one line
            match = cls._ENTRY_PATTERN.match(stripped)
            if match:
                pending_interface = None
                pending_nameif = None
                entries[match.group("interface")] = IpEntry(
                    nameif=match.group("nameif"),
                    ip_address=match.group("ip_address"),
                    subnet_mask=match.group("subnet_mask"),
                    method=match.group("method"),
                )
                continue

            # Try continuation line (uses raw line for leading whitespace)
            if pending_interface is not None:
                cont_match = cls._CONTINUATION_PATTERN.match(line)
                if cont_match:
                    entries[pending_interface] = IpEntry(
                        nameif=pending_nameif or "",
                        ip_address=cont_match.group("ip_address"),
                        subnet_mask=cont_match.group("subnet_mask"),
                        method=cont_match.group("method"),
                    )
                    pending_interface = None
                    pending_nameif = None
                    continue

            # Try partial line (interface + nameif, IP wraps)
            partial_match = cls._PARTIAL_PATTERN.match(stripped)
            if partial_match:
                pending_interface = partial_match.group("interface")
                pending_nameif = partial_match.group("nameif")
                continue

            # Unrecognized line resets pending state
            pending_interface = None
            pending_nameif = None

        return entries

    @classmethod
    def parse(cls, output: str) -> ShowIpResult:
        """Parse 'show ip' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IP address entries for system and current sections.

        Raises:
            ValueError: If no IP entries found in output.
        """
        system_lines: list[str] = []
        current_lines: list[str] = []
        active: list[str] | None = None

        for line in output.splitlines():
            if line.startswith("System IP Addresses"):
                active = system_lines
                continue
            if line.startswith("Current IP Addresses"):
                active = current_lines
                continue
            if active is not None:
                active.append(line)

        system_addresses = cls._parse_section(system_lines)
        current_addresses = cls._parse_section(current_lines)

        if not system_addresses and not current_addresses:
            msg = "No IP address entries found in output"
            raise ValueError(msg)

        return ShowIpResult(
            system_addresses=system_addresses,
            current_addresses=current_addresses,
        )
