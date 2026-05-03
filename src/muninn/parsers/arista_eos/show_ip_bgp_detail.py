"""Parser for 'show ip bgp detail' command on Arista EOS."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, IPV4_PREFIX
from muninn.registry import register
from muninn.tags import ParserTag


class ContributingRoute(TypedDict):
    """Schema for a single contributing route under an aggregated path."""

    proto: str
    origin: str
    as_path: str
    communities: NotRequired[str]


class BgpPathEntry(TypedDict):
    """Schema for a single BGP path within a prefix."""

    as_path: str
    next_hop: str
    peer: str
    router_id: str
    origin: str
    metric: int
    local_preference: int
    igp_metric: int
    weight: int
    received: str
    flags: list[str]
    best_path: bool
    communities: NotRequired[str]
    extended_communities: NotRequired[str]
    rx_path_id: NotRequired[str]
    rx_safi: NotRequired[str]
    contributing_routes: NotRequired[dict[str, ContributingRoute]]


class BgpPrefixEntry(TypedDict):
    """Schema for a single BGP prefix."""

    path_count: int
    paths: dict[str, BgpPathEntry]


class BgpVrfEntry(TypedDict):
    """Schema for a single VRF in the BGP detail output."""

    router_id: str
    local_as: int
    prefixes: dict[str, BgpPrefixEntry]


class ShowIpBgpDetailResult(TypedDict):
    """Schema for 'show ip bgp detail' parsed output on Arista EOS."""

    vrfs: dict[str, BgpVrfEntry]


# --- Compiled regex patterns ---

_VRF_HEADER_RE = re.compile(
    r"^BGP routing table information for VRF\s+(?P<vrf>\S+)\s*$"
)
_ROUTER_ID_RE = re.compile(
    rf"^Router identifier\s+(?P<router_id>{IPV4_ADDRESS}),\s+"
    r"local AS number\s+(?P<local_as>\d+)\s*$"
)
_PREFIX_RE = re.compile(
    rf"^BGP routing table entry for\s+(?P<prefix>{IPV4_PREFIX}|{IPV4_ADDRESS})\s*$"
)
_PATHS_COUNT_RE = re.compile(r"^\s*Paths:\s+(?P<count>\d+)\s+available\s*$")
_ORIGIN_LINE_RE = re.compile(
    r"^\s+Origin\s+(?P<origin>\S+),\s+"
    r"metric\s+(?P<metric>\d+),\s+"
    r"localpref\s+(?P<localpref>\d+),\s+"
    r"IGP metric\s+(?P<igp_metric>\d+),\s+"
    r"weight\s+(?P<weight>\d+),\s+"
    r"received\s+(?P<received>\S+)\s+ago,\s+"
    r"(?P<flags>.+?)\s*$"
)
_NEXT_HOP_RE = re.compile(
    rf"^\s+(?P<next_hop>{IPV4_ADDRESS})\s+from\s+(?P<peer>{IPV4_ADDRESS})\s+"
    rf"\((?P<router_id>{IPV4_ADDRESS})\)\s*$"
)
_COMMUNITY_RE = re.compile(r"^\s+Community:\s+(?P<communities>.+?)\s*$")
_EXT_COMMUNITY_RE = re.compile(
    r"^\s+Extended Community:\s+(?P<ext_communities>.+?)\s*$"
)
_RX_PATH_ID_RE = re.compile(r"^\s+Rx path id:\s+(?P<rx_path_id>\S+)\s*$")
_RX_SAFI_RE = re.compile(r"^\s+Rx SAFI:\s+(?P<rx_safi>\S+)\s*$")
_CONTRIBUTING_ROUTES_RE = re.compile(r"^\s+\d+\s+Contributing routes:")
_CONTRIBUTING_ROUTE_RE = re.compile(
    rf"^\s{{8}}(?P<prefix>{IPV4_PREFIX}|{IPV4_ADDRESS})\s+"
    r"Proto:\s+(?P<proto>\S+)\s+"
    r"Origin:\s+(?P<origin>\S+)\s+"
    r"AS Path:\s+(?P<as_path>.+?)\s*$"
)
_CONTRIBUTING_ROUTE_COMMUNITY_RE = re.compile(
    r"^\s{10}Community:\s+(?P<communities>.+?)\s*$"
)
# AS path line: indented line that is not a known attribute line
_AS_PATH_LINE_RE = re.compile(r"^  (?P<as_path>\S.*)$")


def _split_flags(flags: str) -> list[str]:
    """Split a comma-separated flags string into a list of trimmed flags."""
    return [f.strip() for f in flags.split(",") if f.strip()]


class _PathAccumulator:
    """Mutable accumulator for fields parsed from a single path block."""

    __slots__ = (
        "as_path",
        "next_hop",
        "peer",
        "router_id",
        "origin",
        "metric",
        "local_preference",
        "igp_metric",
        "weight",
        "received",
        "flags",
        "best_path",
        "communities",
        "ext_communities",
        "rx_path_id",
        "rx_safi",
        "contributing_routes",
    )

    def __init__(self) -> None:
        self.as_path: str | None = None
        self.next_hop: str | None = None
        self.peer: str | None = None
        self.router_id: str | None = None
        self.origin: str | None = None
        self.metric: int = 0
        self.local_preference: int = 0
        self.igp_metric: int = 0
        self.weight: int = 0
        self.received: str = ""
        self.flags: list[str] = []
        self.best_path: bool = False
        self.communities: str | None = None
        self.ext_communities: str | None = None
        self.rx_path_id: str | None = None
        self.rx_safi: str | None = None
        self.contributing_routes: dict[str, ContributingRoute] = {}

    def to_entry(self) -> BgpPathEntry:
        """Build a BgpPathEntry from accumulated state."""
        entry: BgpPathEntry = {
            "as_path": self.as_path or "",
            "next_hop": self.next_hop or "",
            "peer": self.peer or "",
            "router_id": self.router_id or "",
            "origin": self.origin or "",
            "metric": self.metric,
            "local_preference": self.local_preference,
            "igp_metric": self.igp_metric,
            "weight": self.weight,
            "received": self.received,
            "flags": self.flags,
            "best_path": self.best_path,
        }
        _d = cast(dict[str, Any], entry)
        optional: dict[str, Any] = {
            "communities": self.communities,
            "extended_communities": self.ext_communities,
            "rx_path_id": self.rx_path_id,
            "rx_safi": self.rx_safi,
        }
        for k, v in optional.items():
            if v is not None:
                _d[k] = v
        if self.contributing_routes:
            _d["contributing_routes"] = self.contributing_routes
        return entry


def _try_parse_origin(line: str, acc: _PathAccumulator) -> bool:
    """Parse an Origin attributes line. Returns True if matched."""
    m = _ORIGIN_LINE_RE.match(line)
    if not m:
        return False
    acc.origin = m.group("origin")
    acc.metric = int(m.group("metric"))
    acc.local_preference = int(m.group("localpref"))
    acc.igp_metric = int(m.group("igp_metric"))
    acc.weight = int(m.group("weight"))
    acc.received = m.group("received")
    acc.flags = _split_flags(m.group("flags"))
    acc.best_path = "best" in acc.flags
    return True


def _try_parse_next_hop(line: str, acc: _PathAccumulator) -> bool:
    """Parse a next-hop line. Returns True if matched."""
    m = _NEXT_HOP_RE.match(line)
    if not m:
        return False
    acc.next_hop = m.group("next_hop")
    acc.peer = m.group("peer")
    acc.router_id = m.group("router_id")
    return True


def _try_parse_attributes(line: str, acc: _PathAccumulator) -> bool:
    """Parse community, extended community, Rx path id, or Rx SAFI lines.

    Returns True if matched.
    """
    m = _COMMUNITY_RE.match(line)
    if m:
        acc.communities = m.group("communities")
        return True
    m = _EXT_COMMUNITY_RE.match(line)
    if m:
        acc.ext_communities = m.group("ext_communities")
        return True
    m = _RX_PATH_ID_RE.match(line)
    if m:
        acc.rx_path_id = m.group("rx_path_id")
        return True
    m = _RX_SAFI_RE.match(line)
    if m:
        acc.rx_safi = m.group("rx_safi")
        return True
    return False


def _is_known_attribute_line(line: str) -> bool:
    """Return True if the line matches a known path attribute pattern."""
    return bool(
        _ORIGIN_LINE_RE.match(line)
        or _NEXT_HOP_RE.match(line)
        or _COMMUNITY_RE.match(line)
        or _EXT_COMMUNITY_RE.match(line)
        or _RX_PATH_ID_RE.match(line)
        or _RX_SAFI_RE.match(line)
        or _CONTRIBUTING_ROUTES_RE.match(line)
    )


def _extract_as_path(raw_as: str) -> str:
    """Extract AS path from a raw AS path string, stripping annotations."""
    # Remove parenthetical annotations like "(aggregated by ...)"
    # or "(Received from a RR-client)"
    paren_idx = raw_as.find(" (")
    if paren_idx >= 0:
        return raw_as[:paren_idx].strip()
    return raw_as


def _try_start_new_path(
    line: str,
    acc: _PathAccumulator | None,
    paths: list[_PathAccumulator],
) -> _PathAccumulator | None:
    """Try to detect an AS path line that starts a new path block.

    Returns a new accumulator if a new path started, otherwise None.
    """
    m = _AS_PATH_LINE_RE.match(line)
    if not m or _is_known_attribute_line(line):
        return None

    # Flush previous path if it has a next hop
    if acc is not None and acc.next_hop is not None:
        paths.append(acc)

    new_acc = _PathAccumulator()
    new_acc.as_path = _extract_as_path(m.group("as_path").strip())
    return new_acc


def _parse_contributing_block(
    lines: list[str], start: int
) -> tuple[dict[str, ContributingRoute], int]:
    """Parse a contributing routes block starting at lines[start].

    Returns (parsed routes, index of first line past the block).
    """
    routes: dict[str, ContributingRoute] = {}
    i = start
    last_prefix: str | None = None
    while i < len(lines):
        line = lines[i]
        if not line.startswith("        "):
            break
        m = _CONTRIBUTING_ROUTE_RE.match(line)
        if m:
            prefix = m.group("prefix")
            route: ContributingRoute = {
                "proto": m.group("proto"),
                "origin": m.group("origin"),
                "as_path": m.group("as_path").strip(),
            }
            routes[prefix] = route
            last_prefix = prefix
            i += 1
            continue
        cm = _CONTRIBUTING_ROUTE_COMMUNITY_RE.match(line)
        if cm and last_prefix is not None:
            cast(dict[str, Any], routes[last_prefix])["communities"] = cm.group(
                "communities"
            )
            i += 1
            continue
        # Indented line that doesn't match a contributing-route shape — stop.
        break
    return routes, i


def _parse_path_lines(lines: list[str]) -> list[_PathAccumulator]:
    """Parse path lines for a single prefix into accumulators."""
    paths: list[_PathAccumulator] = []
    acc: _PathAccumulator | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if _CONTRIBUTING_ROUTES_RE.match(line):
            if acc is not None:
                routes, next_i = _parse_contributing_block(lines, i + 1)
                acc.contributing_routes = routes
                i = next_i
            else:
                i += 1
            continue

        new_acc = _try_start_new_path(line, acc, paths)
        if new_acc is not None:
            acc = new_acc
            i += 1
            continue

        if acc is None:
            i += 1
            continue

        if _try_parse_next_hop(line, acc):
            i += 1
            continue
        if _try_parse_origin(line, acc):
            i += 1
            continue
        _try_parse_attributes(line, acc)
        i += 1

    if acc is not None and acc.next_hop is not None:
        paths.append(acc)

    return paths


def _build_path_key(acc: _PathAccumulator, used: set[str]) -> str:
    """Build a unique natural key for a path entry.

    Prefers next_hop, falls back to next_hop+rx_path_id when collisions exist.
    """
    base = acc.next_hop or ""
    if acc.rx_path_id is not None:
        candidate = f"{base}#{acc.rx_path_id}"
    else:
        candidate = base
    if candidate not in used:
        return candidate
    # Fall back to numeric suffix to guarantee uniqueness without losing data.
    n = 2
    while f"{candidate}#{n}" in used:
        n += 1
    return f"{candidate}#{n}"


@register(OS.ARISTA_EOS, "show ip bgp detail")
class ShowIpBgpDetailParser(BaseParser["ShowIpBgpDetailResult"]):
    """Parser for 'show ip bgp detail' command on Arista EOS.

    Parses BGP routing table detail output including paths, AS paths,
    communities, and path attributes across multiple VRFs.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpDetailResult:
        """Parse 'show ip bgp detail' output on Arista EOS.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP detail data keyed by VRF and prefix.

        Raises:
            ValueError: If no VRF data found in output.
        """
        vrfs: dict[str, BgpVrfEntry] = {}
        current_vrf: str | None = None
        current_router_id: str = ""
        current_local_as: int = 0
        current_prefix: str | None = None
        current_path_count: int = 0
        path_lines: list[str] = []

        lines = output.splitlines()
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            m = _VRF_HEADER_RE.match(stripped)
            if m:
                _flush_prefix(
                    vrfs,
                    current_vrf,
                    current_router_id,
                    current_local_as,
                    current_prefix,
                    current_path_count,
                    path_lines,
                )
                current_vrf = m.group("vrf")
                current_router_id = ""
                current_local_as = 0
                current_prefix = None
                path_lines = []
                continue

            m = _ROUTER_ID_RE.match(stripped)
            if m:
                current_router_id = m.group("router_id")
                current_local_as = int(m.group("local_as"))
                continue

            m = _PREFIX_RE.match(stripped)
            if m:
                _flush_prefix(
                    vrfs,
                    current_vrf,
                    current_router_id,
                    current_local_as,
                    current_prefix,
                    current_path_count,
                    path_lines,
                )
                current_prefix = m.group("prefix")
                current_path_count = 0
                path_lines = []
                continue

            m = _PATHS_COUNT_RE.match(line)
            if m:
                current_path_count = int(m.group("count"))
                continue

            if current_prefix is not None:
                path_lines.append(line)

        _flush_prefix(
            vrfs,
            current_vrf,
            current_router_id,
            current_local_as,
            current_prefix,
            current_path_count,
            path_lines,
        )

        if not vrfs:
            msg = "No VRF data found in 'show ip bgp detail' output"
            raise ValueError(msg)

        return {"vrfs": vrfs}


def _flush_prefix(
    vrfs: dict[str, BgpVrfEntry],
    vrf_name: str | None,
    router_id: str,
    local_as: int,
    prefix: str | None,
    path_count: int,
    lines: list[str],
) -> None:
    """Parse accumulated prefix lines and add to the vrfs dict."""
    if not (vrf_name and prefix and lines):
        return

    if vrf_name not in vrfs:
        vrfs[vrf_name] = {
            "router_id": router_id,
            "local_as": local_as,
            "prefixes": {},
        }

    parsed = _parse_path_lines(lines)
    paths_dict: dict[str, BgpPathEntry] = {}
    used_keys: set[str] = set()
    for acc in parsed:
        key = _build_path_key(acc, used_keys)
        used_keys.add(key)
        paths_dict[key] = acc.to_entry()

    if paths_dict:
        vrfs[vrf_name]["prefixes"][prefix] = {
            "path_count": path_count,
            "paths": paths_dict,
        }
