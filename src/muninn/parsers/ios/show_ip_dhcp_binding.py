"""Parser for 'show ip dhcp binding' command on IOS/IOS-XE."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class DhcpBindingEntry(TypedDict):
    """Schema for a single DHCP binding entry."""

    client_id: str
    lease_expiration: str
    type: str
    state: NotRequired[str]
    interface: NotRequired[str]


class ShowIpDhcpBindingResult(TypedDict):
    """Schema for 'show ip dhcp binding' parsed output.

    Keyed by IP address. ``vrf`` is set when the output lists the bindings of
    a VRF pool (``Bindings from VRF pool <vrf>:``).
    """

    vrf: NotRequired[str]
    bindings: dict[str, DhcpBindingEntry]


@register(OS.CISCO_IOS, "show ip dhcp binding")
@register(OS.CISCO_IOSXE, "show ip dhcp binding")
@register(OS.CISCO_IOSXE, r"show ip dhcp binding vrf (?P<vrf>\S+)")
class ShowIpDhcpBindingParser(BaseParser[ShowIpDhcpBindingResult]):
    """Parser for 'show ip dhcp binding' command.

    Parses DHCP binding table entries showing IP address, client ID/hardware
    address, lease expiration, type, and optional state and interface. Long
    client IDs wrapped onto indented continuation lines are joined.

    Example output::

        IP address       Client-ID/           Lease expiration  Type
                         Hardware address/
                         User name
        10.100.88.26     01aa.aaaa.aaaa.aa     Infinite          Manual
        10.100.88.197    01dd.dddd.dddd.dd     Infinite          Manual
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.DHCP})

    # Matches a DHCP binding row:
    # IP address, client-ID/MAC, lease expiration, type, and optional state/interface
    _BINDING_PATTERN = re.compile(
        r"^(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"(?P<client_id>\S+)\s+"
        r"(?P<lease_expiration>Infinite|"
        r"\w+\s+\d+\s+\d+\s+\d+:\d+\s+[AP]M)\s+"
        r"(?P<type>\S+)"
        r"(?:\s+(?P<state>\S+))?"
        r"(?:\s+(?P<interface>\S+))?"
    )
    # Wrapped tail of a long client ID, e.g. "    6335.612e.6337.3737."
    _CLIENT_ID_CONT_PATTERN = re.compile(r"^\s+(?P<cont>[0-9a-fA-F.]+)\s*$")
    _HEADER_PATTERN = re.compile(
        r"^Bindings from (?:VRF pool (?P<vrf>\S+)|all pools .*):$"
    )

    @classmethod
    def _parse_row(cls, match: re.Match[str]) -> DhcpBindingEntry:
        """Build a binding entry from a matched table row."""
        entry: DhcpBindingEntry = {
            "client_id": match.group("client_id").lower(),
            "lease_expiration": match.group("lease_expiration"),
            "type": match.group("type"),
        }
        state = match.group("state")
        if state and state != "--":
            entry["state"] = state
        interface = match.group("interface")
        if interface and interface != "--":
            entry["interface"] = canonical_interface_name(interface, os=OS.CISCO_IOS)
        return entry

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
        result: ShowIpDhcpBindingResult = {"bindings": {}}
        bindings = result["bindings"]
        header_seen = False
        last: DhcpBindingEntry | None = None

        for line in output.splitlines():
            stripped = line.strip()
            match = cls._BINDING_PATTERN.match(stripped)
            if match:
                last = cls._parse_row(match)
                bindings[match.group("ip_address")] = last
                continue

            cont = cls._CLIENT_ID_CONT_PATTERN.match(line)
            if cont and last is not None:
                last["client_id"] += cont.group("cont").lower()
                continue

            header = cls._HEADER_PATTERN.match(stripped)
            if header:
                header_seen = True
                if header.group("vrf"):
                    result["vrf"] = header.group("vrf")

        # A header with no rows is a valid "no bindings" table.
        if not bindings and not header_seen:
            msg = "No DHCP binding entries found in output"
            raise ValueError(msg)

        return result
