"""Parser for 'show dhcp ipv4 proxy binding' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class ProxyBindingEntry(TypedDict):
    """Schema for a single DHCPv4 proxy client binding."""

    ip_address: str
    state: str
    lease_remaining_seconds: int
    sublabel: str


class ProxyBindingVrf(TypedDict):
    """Bindings in one VRF, keyed by interface then client MAC address."""

    interfaces: dict[str, dict[str, ProxyBindingEntry]]


class ShowDhcpIpv4ProxyBindingResult(TypedDict):
    """Schema for 'show dhcp ipv4 proxy binding' parsed output."""

    vrfs: dict[str, ProxyBindingVrf]


@register(OS.CISCO_IOSXR, "show dhcp ipv4 proxy binding")
@register(
    OS.CISCO_IOSXR,
    r"show dhcp ipv4 proxy binding interface (?P<interface>[A-Za-z-]+ ?\d\S*)",
    doc_template="show dhcp ipv4 proxy binding interface <interface>",
)
class ShowDhcpIpv4ProxyBindingParser(BaseParser[ShowDhcpIpv4ProxyBindingResult]):
    """Parser for 'show dhcp ipv4 proxy binding' on Cisco IOS-XR.

    Columns are split on whitespace rather than fixed widths because long
    interface names overflow into the VRF column. A blank VRF cell is
    keyed as ``default`` rather than dropping the row.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.DHCP})

    # 58ac.7881.ab02  0.0.0.0  SELECTING  6  Gi0/0/0/0.2002  DHCP-VRF  0x0
    _ROW_RE = re.compile(
        rf"^(?P<mac>{MAC_ADDRESS})\s+"
        rf"(?P<ip>{IPV4_ADDRESS})\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<lease>\d+)\s+"
        r"(?P<interface>\S+)\s+"
        r"(?:(?P<vrf>\S+)\s+)?"
        r"(?P<sublabel>0x[0-9a-fA-F]+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowDhcpIpv4ProxyBindingResult:
        """Parse 'show dhcp ipv4 proxy binding' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Bindings keyed by VRF, interface, then client MAC address.

        Raises:
            ValueError: If no binding rows are found.
        """
        vrfs: dict[str, ProxyBindingVrf] = {}

        for line in output.splitlines():
            match = cls._ROW_RE.match(line.strip())
            if not match:
                continue
            interface = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_IOSXR
            )
            vrf = vrfs.setdefault(match.group("vrf") or "default", {"interfaces": {}})
            vrf["interfaces"].setdefault(interface, {})[match.group("mac").lower()] = {
                "ip_address": match.group("ip"),
                "state": match.group("state"),
                "lease_remaining_seconds": int(match.group("lease")),
                "sublabel": match.group("sublabel"),
            }

        if not vrfs:
            msg = "No DHCPv4 proxy bindings found in output"
            raise ValueError(msg)

        return cast(ShowDhcpIpv4ProxyBindingResult, {"vrfs": vrfs})
