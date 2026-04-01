"""Parser for 'show ip bgp detail' command on Arista EOS."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


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
    flags: str
    best_path: bool
    communities: NotRequired[str]
    extended_communities: NotRequired[str]
    rx_path_id: NotRequired[str]
    rx_safi: NotRequired[str]


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
    r"^Router identifier\s+(?P<router_id>\S+),\s+"
    r"local AS number\s+(?P<local_as>\d+)\s*$"
)
_PREFIX_RE = re.compile(r"^BGP routing table entry for\s+(?P<prefix>\S+)\s*$")
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
    r"^\s+(?P<next_hop>\S+)\s+from\s+(?P<peer>\S+)\s+\((?P<router_id>\S+)\)\s*$"
)
_COMMUNITY_RE = re.compile(r"^\s+Community:\s+(?P<communities>.+?)\s*$")
_EXT_COMMUNITY_RE = re.compile(
    r"^\s+Extended Community:\s+(?P<ext_communities>.+?)\s*$"
)
_RX_PATH_ID_RE = re.compile(r"^\s+Rx path id:\s+(?P<rx_path_id>\S+)\s*$")
_RX_SAFI_RE = re.compile(r"^\s+Rx SAFI:\s+(?P<rx_safi>\S+)\s*$")
_CONTRIBUTING_ROUTES_RE = re.compile(r"^\s+\d+\s+Contributing routes:")
# AS path line: indented line that is not a known attribute line
_AS_PATH_LINE_RE = re.compile(r"^  (?P<as_path>\S.*)$")


def _is_best_path(flags: str) -> bool:
    """Determine if a path is the best path from the flags string."""
    flag_parts = [f.strip().rstrip(",") for f in flags.split(",")]
    return "best" in flag_parts


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
        self.flags: str = ""
        self.best_path: bool = False
        self.communities: str | None = None
        self.ext_communities: str | None = None
        self.rx_path_id: str | None = None
        self.rx_safi: str | None = None

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
        if self.communities is not None:
            _d["communities"] = self.communities
        if self.ext_communities is not None:
            _d["extended_communities"] = self.ext_communities
        if self.rx_path_id is not None:
            _d["rx_path_id"] = self.rx_path_id
        if self.rx_safi is not None:
            _d["rx_safi"] = self.rx_safi
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
    raw_flags = m.group("flags")
    acc.flags = raw_flags.strip()
    acc.best_path = _is_best_path(raw_flags)
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
    paths: list[BgpPathEntry],
) -> _PathAccumulator | None:
    """Try to detect an AS path line that starts a new path block.

    Returns a new accumulator if a new path started, otherwise None.
    """
    m = _AS_PATH_LINE_RE.match(line)
    if not m or _is_known_attribute_line(line):
        return None

    # Flush previous path if it has a next hop
    if acc is not None and acc.next_hop is not None:
        paths.append(acc.to_entry())

    new_acc = _PathAccumulator()
    new_acc.as_path = _extract_as_path(m.group("as_path").strip())
    return new_acc


def _filter_contributing_routes(lines: list[str]) -> list[str]:
    """Remove contributing routes sections from path lines."""
    filtered: list[str] = []
    skip = False
    for line in lines:
        if _CONTRIBUTING_ROUTES_RE.match(line):
            skip = True
            continue
        if skip:
            if line.startswith("        "):
                continue
            skip = False
        filtered.append(line)
    return filtered


def _parse_path_lines(lines: list[str]) -> list[BgpPathEntry]:
    """Parse path lines for a single prefix into a list of BgpPathEntry dicts."""
    paths: list[BgpPathEntry] = []
    acc: _PathAccumulator | None = None
    filtered = _filter_contributing_routes(lines)

    for line in filtered:
        new_acc = _try_start_new_path(line, acc, paths)
        if new_acc is not None:
            acc = new_acc
            continue

        if acc is None:
            continue

        if _try_parse_next_hop(line, acc):
            continue
        if _try_parse_origin(line, acc):
            continue
        _try_parse_attributes(line, acc)

    # Flush last path
    if acc is not None and acc.next_hop is not None:
        paths.append(acc.to_entry())

    return paths


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

            # VRF header
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

            # Router identifier line
            m = _ROUTER_ID_RE.match(stripped)
            if m:
                current_router_id = m.group("router_id")
                current_local_as = int(m.group("local_as"))
                continue

            # New prefix entry
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

            # Path count
            m = _PATHS_COUNT_RE.match(line)
            if m:
                current_path_count = int(m.group("count"))
                continue

            # Accumulate path lines (preserve original indentation)
            if current_prefix is not None:
                path_lines.append(line)

        # Flush last prefix
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

    parsed_paths = _parse_path_lines(lines)
    paths_dict: dict[str, BgpPathEntry] = {}
    for idx, path_entry in enumerate(parsed_paths, start=1):
        paths_dict[str(idx)] = path_entry

    if paths_dict:
        vrfs[vrf_name]["prefixes"][prefix] = {
            "path_count": path_count,
            "paths": paths_dict,
        }
