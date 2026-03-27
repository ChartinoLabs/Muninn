"""Parser for 'show routing protocol bgp summary' on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class BgpNeighborEntry(TypedDict):
    """Schema for a single BGP neighbor entry."""

    router_id: str
    virtual_router: str
    local_as: int
    neighbor_name: str
    neighbor_as: int
    state: str
    address_family: NotRequired[str]
    accepted_pfx: NotRequired[int]
    advertised_pfx: NotRequired[int]


ShowRoutingProtocolBgpSummaryResult = dict[str, BgpNeighborEntry]


# Regex patterns for parsing the output
_ROUTER_ID_RE = re.compile(r"^\s*router id:\s+(?P<value>\S+)")
_VIRTUAL_ROUTER_RE = re.compile(r"^\s*virtual router:\s+(?P<value>\S+)")
_LOCAL_AS_RE = re.compile(r"^\s*Local AS:\s+(?P<value>\d+)")
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


@register(OS.PALOALTO_PANOS, "show routing protocol bgp summary")
class ShowRoutingProtocolBgpSummaryParser(
    BaseParser[ShowRoutingProtocolBgpSummaryResult],
):
    """Parser for 'show routing protocol bgp summary' on Palo Alto PAN-OS.

    Parses the BGP summary output into a dict-of-dicts keyed by peer IP
    address, containing neighbor identity, AS numbers, state, and prefix
    counts.
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
            Dict keyed by peer IP address with BGP neighbor details.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, BgpNeighborEntry] = {}
        router_id = ""
        virtual_router = ""
        local_as = 0

        # Track the last peer IP so AFI lines can attach to it
        last_peer_ip = ""

        for line in output.splitlines():
            # Match router id
            match = _ROUTER_ID_RE.match(line)
            if match:
                router_id = match.group("value")
                continue

            # Match virtual router
            match = _VIRTUAL_ROUTER_RE.match(line)
            if match:
                virtual_router = match.group("value")
                continue

            # Match local AS
            match = _LOCAL_AS_RE.match(line)
            if match:
                local_as = int(match.group("value"))
                continue

            # Match peer line
            match = _PEER_RE.match(line)
            if match:
                peer_ip = match.group("ip")
                last_peer_ip = peer_ip
                entry: BgpNeighborEntry = {
                    "router_id": router_id,
                    "virtual_router": virtual_router,
                    "local_as": local_as,
                    "neighbor_name": match.group("name"),
                    "neighbor_as": int(match.group("as")),
                    "state": match.group("state"),
                }
                result[peer_ip] = entry
                continue

            # Match AFI/prefix line (belongs to the preceding peer)
            match = _AFI_RE.match(line)
            if match and last_peer_ip:
                result[last_peer_ip]["address_family"] = match.group("afi")
                result[last_peer_ip]["accepted_pfx"] = int(match.group("accepted"))
                result[last_peer_ip]["advertised_pfx"] = int(match.group("advertised"))
                continue

        if not result:
            msg = "No BGP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowRoutingProtocolBgpSummaryResult, result)
