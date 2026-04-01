"""Parser for 'show ip bgp' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PathEntry(TypedDict):
    """Schema for a single BGP path entry."""

    status_codes: str
    next_hop: NotRequired[str]
    metric: NotRequired[int]
    local_pref: NotRequired[int]
    weight: NotRequired[int]
    as_path: NotRequired[str]
    origin: str


class RouteEntry(TypedDict):
    """Schema for a single BGP route (network prefix)."""

    paths: list[PathEntry]


class VrfEntry(TypedDict):
    """Schema for a single VRF."""

    router_id: str
    local_as: str
    routes: dict[str, RouteEntry]


class ShowIpBgpResult(TypedDict):
    """Schema for 'show ip bgp' parsed output on Arista EOS."""

    vrfs: dict[str, VrfEntry]


_VRF_HEADER_RE = re.compile(r"^BGP routing table information for VRF (?P<vrf>\S+)$")
_ROUTER_ID_RE = re.compile(
    r"^Router identifier (?P<router_id>\S+),\s*local AS number (?P<local_as>\S+)$"
)
_COLUMN_HEADER_RE = re.compile(
    r"^\s*Network\s+Next\s+Hop\s+Metric\s+LocPref\s+Weight\s+Path"
)

# Route lines start with a space followed by status codes like "* >", "* #"
_ROUTE_LINE_RE = re.compile(
    r"^\s"
    r"(?P<status>\S(?:\s\S)?)"  # status codes, e.g. "* >" or "* #"
    r"\s+"
    r"(?P<network>\S+)"  # network/prefix
    r"\s+"
    r"(?P<next_hop>\S+)"  # next hop or "-"
    r"\s+"
    r"(?P<metric>\S+)"  # metric or "-"
    r"\s+"
    r"(?P<local_pref>\S+)"  # local pref or "-"
    r"\s+"
    r"(?P<weight>\S+)"  # weight or "-"
    r"\s+"
    r"(?P<path_and_origin>.+)$"  # AS path + origin code
)

_HYPHEN_PLACEHOLDER = "-"


def _parse_path_and_origin(raw: str) -> tuple[str | None, str]:
    """Split the trailing path+origin field into (as_path, origin).

    The origin code (i, e, ?) is always the last token. Everything
    before it is the AS path, which may be empty.

    Returns:
        Tuple of (as_path or None, origin).
    """
    tokens = raw.split()
    if not tokens:
        return (None, "")
    origin = tokens[-1]
    as_path = " ".join(tokens[:-1]) if len(tokens) > 1 else None
    return (as_path, origin)


def _build_path_entry(match: re.Match[str]) -> PathEntry:
    """Construct a PathEntry from a regex match of a route line."""
    status = match.group("status").replace(" ", "")
    next_hop_raw = match.group("next_hop")
    metric_raw = match.group("metric")
    local_pref_raw = match.group("local_pref")
    weight_raw = match.group("weight")
    as_path, origin = _parse_path_and_origin(match.group("path_and_origin"))

    entry: PathEntry = {
        "status_codes": status,
        "origin": origin,
    }

    if next_hop_raw != _HYPHEN_PLACEHOLDER:
        entry["next_hop"] = next_hop_raw

    if metric_raw != _HYPHEN_PLACEHOLDER:
        entry["metric"] = int(metric_raw)

    if local_pref_raw != _HYPHEN_PLACEHOLDER:
        entry["local_pref"] = int(local_pref_raw)

    if weight_raw != _HYPHEN_PLACEHOLDER:
        entry["weight"] = int(weight_raw)

    if as_path is not None:
        entry["as_path"] = as_path

    return entry


def _parse_vrf_block(lines: list[str]) -> VrfEntry | None:
    """Parse a single VRF block into a VrfEntry.

    Args:
        lines: Lines belonging to one VRF section (after the VRF header).

    Returns:
        Parsed VrfEntry, or None if required header info is missing.
    """
    router_id: str | None = None
    local_as: str | None = None
    routes: dict[str, RouteEntry] = {}
    in_table = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Router identifier line
        rid_match = _ROUTER_ID_RE.match(stripped)
        if rid_match:
            router_id = rid_match.group("router_id")
            local_as = rid_match.group("local_as")
            continue

        # Column header signals start of route table
        if _COLUMN_HEADER_RE.match(line):
            in_table = True
            continue

        if not in_table:
            continue

        # Route data line
        route_match = _ROUTE_LINE_RE.match(line)
        if route_match:
            network = route_match.group("network")
            path_entry = _build_path_entry(route_match)
            if network not in routes:
                routes[network] = {"paths": []}
            routes[network]["paths"].append(path_entry)

    if router_id is None or local_as is None:
        return None

    return {
        "router_id": router_id,
        "local_as": local_as,
        "routes": routes,
    }


@register(OS.ARISTA_EOS, "show ip bgp")
class ShowIpBgpParser(BaseParser["ShowIpBgpResult"]):
    """Parser for 'show ip bgp' command on Arista EOS.

    Parses BGP routing table entries across one or more VRFs,
    including status codes, next hop, metric, local preference,
    weight, AS path, and origin code.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpResult:
        """Parse 'show ip bgp' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BGP routing table information.

        Raises:
            ValueError: If no VRF sections can be parsed.
        """
        lines = output.splitlines()
        vrfs: dict[str, VrfEntry] = {}

        # Split into VRF sections
        vrf_sections: list[tuple[str, list[str]]] = []
        current_vrf: str | None = None
        current_lines: list[str] = []

        for line in lines:
            vrf_match = _VRF_HEADER_RE.match(line.strip())
            if vrf_match:
                if current_vrf is not None:
                    vrf_sections.append((current_vrf, current_lines))
                current_vrf = vrf_match.group("vrf")
                current_lines = []
            else:
                current_lines.append(line)

        # Append final section
        if current_vrf is not None:
            vrf_sections.append((current_vrf, current_lines))

        for vrf_name, section_lines in vrf_sections:
            parsed = _parse_vrf_block(section_lines)
            if parsed is not None:
                vrfs[vrf_name] = parsed

        if not vrfs:
            msg = "No BGP VRF sections found in output"
            raise ValueError(msg)

        return {"vrfs": vrfs}
