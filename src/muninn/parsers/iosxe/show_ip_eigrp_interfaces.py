"""Parser for 'show ip eigrp interfaces' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class EigrpInterfaceEntry(TypedDict):
    """Schema for a single EIGRP interface entry."""

    peers: int
    xmit_q_unreliable: int
    xmit_q_reliable: int
    peer_q_unreliable: int
    peer_q_reliable: int
    mean_srtt: int
    pacing_time_unreliable: int
    pacing_time_reliable: int
    mcast_flow_timer: int
    pending_routes: int


class _HeaderInfo(TypedDict):
    """Parsed header metadata."""

    as_number: int
    address_family: str
    named_mode: bool
    vrf: NotRequired[str]
    name: NotRequired[str]


class ShowIpEigrpInterfacesResult(TypedDict):
    """Schema for 'show ip eigrp interfaces' parsed output."""

    as_number: int
    address_family: str
    named_mode: bool
    vrf: NotRequired[str]
    name: NotRequired[str]
    interfaces: dict[str, EigrpInterfaceEntry]


_HEADER_PATTERN = re.compile(
    r"EIGRP-(?P<address_family>IPv4|IPv6)\s+"
    r"(?:VR\((?P<name>\w+)\)\s+Address-Family\s+)?"
    r"Interfaces\s+for\s+AS\(\s*(?P<as_number>\S+)\)"
    r"(?:\s*VRF\((?P<vrf>\S+)\))?"
)

_VRF_LINE_PATTERN = re.compile(r"^\s*VRF\((?P<vrf>\S+)\)\s*$")

_ROW_PATTERN = re.compile(
    r"^(?P<interface>\S+\d\S*)\s+"
    r"(?P<peers>\d+)\s+"
    r"(?P<xmit_q_unreliable>\d+)"
    r"/(?P<xmit_q_reliable>\d+)\s+"
    r"(?P<peer_q_unreliable>\d+)"
    r"/(?P<peer_q_reliable>\d+)\s+"
    r"(?P<mean_srtt>\d+)\s+"
    r"(?P<pacing_t_unreliable>\d+)"
    r"/(?P<pacing_t_reliable>\d+)\s+"
    r"(?P<mcast_flow_timer>\d+)\s+"
    r"(?P<pend_routes>\d+)\s*$"
)


def _parse_header(
    match: re.Match[str],
) -> _HeaderInfo:
    """Extract header metadata from a header regex match."""
    info = _HeaderInfo(
        as_number=int(match.group("as_number")),
        address_family=match.group("address_family").lower(),
        named_mode=match.group("name") is not None,
    )
    name = match.group("name")
    if name is not None:
        info["name"] = name
    vrf = match.group("vrf")
    if vrf:
        info["vrf"] = vrf
    return info


def _build_entry(
    match: re.Match[str],
) -> EigrpInterfaceEntry:
    """Build an EigrpInterfaceEntry from a row match."""
    return EigrpInterfaceEntry(
        peers=int(match.group("peers")),
        xmit_q_unreliable=int(match.group("xmit_q_unreliable")),
        xmit_q_reliable=int(match.group("xmit_q_reliable")),
        peer_q_unreliable=int(match.group("peer_q_unreliable")),
        peer_q_reliable=int(match.group("peer_q_reliable")),
        mean_srtt=int(match.group("mean_srtt")),
        pacing_time_unreliable=int(match.group("pacing_t_unreliable")),
        pacing_time_reliable=int(match.group("pacing_t_reliable")),
        mcast_flow_timer=int(match.group("mcast_flow_timer")),
        pending_routes=int(match.group("pend_routes")),
    )


def _process_line(
    stripped: str,
    header: _HeaderInfo | None,
    vrf: str | None,
    interfaces: dict[str, EigrpInterfaceEntry],
) -> tuple[_HeaderInfo | None, str | None]:
    """Process a single line, returning updated header and vrf."""
    hdr = _HEADER_PATTERN.search(stripped)
    if hdr:
        return _parse_header(hdr), vrf

    vrf_match = _VRF_LINE_PATTERN.match(stripped)
    if vrf_match:
        return header, vrf_match.group("vrf")

    row = _ROW_PATTERN.match(stripped)
    if row:
        iface = canonical_interface_name(
            row.group("interface"),
            os=OS.CISCO_IOSXE,
        )
        interfaces[iface] = _build_entry(row)

    return header, vrf


def _build_result(
    header: _HeaderInfo | None,
    vrf: str | None,
    interfaces: dict[str, EigrpInterfaceEntry],
) -> ShowIpEigrpInterfacesResult:
    """Validate parsed data and build the result dict."""
    if header is None:
        msg = "No EIGRP interface header found in output"
        raise ValueError(msg)

    if not interfaces:
        msg = "No EIGRP interface entries found"
        raise ValueError(msg)

    result = ShowIpEigrpInterfacesResult(
        as_number=header["as_number"],
        address_family=header["address_family"],
        named_mode=header["named_mode"],
        interfaces=interfaces,
    )

    if "name" in header:
        result["name"] = header["name"]

    resolved_vrf = vrf or header.get("vrf")
    if resolved_vrf is not None:
        result["vrf"] = resolved_vrf

    return result


@register(OS.CISCO_IOSXE, "show ip eigrp interfaces")
@register(OS.CISCO_IOSXE, "show ipv6 eigrp interfaces")
class ShowIpEigrpInterfacesParser(
    BaseParser[ShowIpEigrpInterfacesResult],
):
    """Parser for 'show ip eigrp interfaces' command.

    Example output::

        EIGRP-IPv4 Interfaces for AS(1)
        Gi1  1  0/0  0/0  20  0/0  84  0
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.EIGRP,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpEigrpInterfacesResult:
        """Parse 'show ip eigrp interfaces' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed EIGRP interface data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        header: _HeaderInfo | None = None
        vrf: str | None = None
        interfaces: dict[str, EigrpInterfaceEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            header, vrf = _process_line(stripped, header, vrf, interfaces)

        return _build_result(header, vrf, interfaces)
