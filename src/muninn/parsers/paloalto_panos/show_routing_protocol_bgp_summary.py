"""Parser for 'show routing protocol bgp summary' on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class BgpNeighborEntry(TypedDict):
    """Schema for a single BGP neighbor entry."""

    neighbor_name: str
    neighbor_as: int
    state: str
    address_family: NotRequired[str]
    accepted_pfx: NotRequired[int]
    advertised_pfx: NotRequired[int]


class ShowRoutingProtocolBgpSummaryResult(TypedDict):
    """Schema for 'show routing protocol bgp summary' parsed output."""

    router_id: str
    virtual_router: str
    local_as: int
    reject_default_route: bool
    redist_default_route: str
    install_bgp_routes: bool
    graceful_restart: str
    as_size: int
    local_member_as: int
    cluster_id: str
    default_local_preference: int
    always_compare_med: bool
    aggregate_regardless_med: bool
    deterministic_med_processing: bool
    accept_orf: bool
    accept_cisco_style_prefix: bool
    mp_bgp_enable: bool
    afi_safi_ipv4_unicast: bool
    rib_out_current: int
    rib_out_peak: int
    peers: dict[str, BgpNeighborEntry]


# Regex patterns for parsing the output
_PEER_RE = re.compile(
    r"^\s*peer\s+(?P<name>.+?):\s+"
    r"AS\s+(?P<as>\d+),\s+"
    r"(?P<state>\S+),\s+"
    r"IP\s+(?P<ip>\S+)"
)
_AFI_RE = re.compile(
    r"^\s*(?P<afi>\S+)\s+pfx:\s+"
    r"Accepted pfx:\s+(?P<accepted>\d+),\s+"
    r"Advertised pfx:\s+(?P<advertised>\d+)"
)
_RIB_OUT_RE = re.compile(
    r"^\s*rib-out entries:\s+current\s+(?P<current>\d+),\s+peak\s+(?P<peak>\d+)"
)

# Map of CLI field labels to (result key, type converter)
_YES_NO = {"yes": True, "no": False}
_SCALAR_FIELDS: dict[str, tuple[str, type]] = {
    "router id": ("router_id", str),
    "virtual router": ("virtual_router", str),
    "Local AS": ("local_as", int),
    "reject default route": ("reject_default_route", bool),
    "redist default route": ("redist_default_route", str),
    "Install BGP routes": ("install_bgp_routes", bool),
    "Graceful Restart": ("graceful_restart", str),
    "AS size": ("as_size", int),
    "Local member AS": ("local_member_as", int),
    "Cluster id": ("cluster_id", str),
    "Default local preference": ("default_local_preference", int),
    "Always compare MED": ("always_compare_med", bool),
    "Aggregate regardless MED": ("aggregate_regardless_med", bool),
    "Deterministic MED processing": ("deterministic_med_processing", bool),
    "Accept ORF": ("accept_orf", bool),
    "Accept CISCO style prefix": ("accept_cisco_style_prefix", bool),
    "mp-bgp-enable": ("mp_bgp_enable", bool),
    "afi-safi-ipv4-unicast": ("afi_safi_ipv4_unicast", bool),
}

# Build a single regex that matches any of the scalar field labels
_SCALAR_RE = re.compile(
    r"^\s*(?P<label>"
    + "|".join(re.escape(label) for label in _SCALAR_FIELDS)
    + r"):\s+(?P<value>\S+)"
)


@register(OS.PALOALTO_PANOS, "show routing protocol bgp summary")
class ShowRoutingProtocolBgpSummaryParser(
    BaseParser[ShowRoutingProtocolBgpSummaryResult],
):
    """Parser for 'show routing protocol bgp summary' on Palo Alto PAN-OS.

    Parses the BGP summary output into a dict containing top-level BGP
    attributes and a ``peers`` dict-of-dicts keyed by peer IP address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.BGP,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowRoutingProtocolBgpSummaryResult:
        """Parse 'show routing protocol bgp summary' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict with top-level BGP attributes and peers keyed by IP.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, object] = {}
        peers: dict[str, BgpNeighborEntry] = {}
        last_peer_ip = ""

        for line in output.splitlines():
            last_peer_ip = _parse_line(line, result, peers, last_peer_ip)

        if not peers:
            msg = "No BGP neighbors found in output"
            raise ValueError(msg)

        result["peers"] = peers
        return cast(ShowRoutingProtocolBgpSummaryResult, result)


def _parse_line(
    line: str,
    result: dict[str, object],
    peers: dict[str, BgpNeighborEntry],
    last_peer_ip: str,
) -> str:
    """Parse a single line and update result/peers. Returns last_peer_ip."""
    match = _SCALAR_RE.match(line)
    if match:
        _apply_scalar(match, result)
        return last_peer_ip

    match = _RIB_OUT_RE.match(line)
    if match:
        result["rib_out_current"] = int(match.group("current"))
        result["rib_out_peak"] = int(match.group("peak"))
        return last_peer_ip

    match = _PEER_RE.match(line)
    if match:
        peer_ip = match.group("ip")
        peers[peer_ip] = BgpNeighborEntry(
            neighbor_name=match.group("name"),
            neighbor_as=int(match.group("as")),
            state=match.group("state"),
        )
        return peer_ip

    match = _AFI_RE.match(line)
    if match and last_peer_ip:
        peers[last_peer_ip]["address_family"] = match.group("afi")
        peers[last_peer_ip]["accepted_pfx"] = int(match.group("accepted"))
        peers[last_peer_ip]["advertised_pfx"] = int(match.group("advertised"))

    return last_peer_ip


def _apply_scalar(match: re.Match[str], result: dict[str, object]) -> None:
    """Apply a matched scalar field to the result dict."""
    label = match.group("label")
    raw = match.group("value")
    key, typ = _SCALAR_FIELDS[label]
    if typ is bool:
        result[key] = _YES_NO[raw]
    elif typ is int:
        result[key] = int(raw)
    else:
        result[key] = raw
