"""Parser for 'show bgp vrf all ipv4 unicast detail' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PathEntry(TypedDict):
    """Schema for a single BGP path within a prefix."""

    next_hop: str
    metric: NotRequired[int]
    local_preference: NotRequired[int]
    weight: int
    origin: str
    as_path: NotRequired[str]
    communities: NotRequired[str]
    extended_communities: NotRequired[str]
    originator_id: NotRequired[str]
    cluster_list: NotRequired[str]
    peer_id: NotRequired[str]
    source_id: NotRequired[str]
    status: str
    best_path: bool
    multipath: NotRequired[bool]


class PrefixEntry(TypedDict):
    """Schema for a single BGP prefix."""

    version: int
    paths: dict[str, PathEntry]


class VrfEntry(TypedDict):
    """Schema for a single VRF."""

    router_id: str
    local_as: int
    prefixes: dict[str, PrefixEntry]


class ShowBgpVrfAllIpv4UnicastDetailResult(TypedDict):
    """Schema for 'show bgp vrf all ipv4 unicast detail' parsed output."""

    vrfs: dict[str, VrfEntry]


# --- Compiled regex patterns ---
_VRF_HEADER_RE = re.compile(
    r"^BGP routing table information for VRF\s+(?P<vrf>\S+),"
    r"\s+address family\s+(?P<af>.+?)\s*$"
)
_ROUTER_ID_RE = re.compile(
    r"^BGP table version is\s+\d+,\s*[Rr]outer\s+ID:\s+(?P<router_id>\S+)\s*$"
)
_LOCAL_AS_RE = re.compile(r"^\*?Local\s+AS\s+number\s*:\s*(?P<local_as>\d+)\s*$")
_NETWORK_RE = re.compile(r"^BGP routing table entry for\s+(?P<prefix>\S+),")
_VERSION_RE = re.compile(r"version\s+(?P<version>\d+)")
_NEXT_HOP_WITH_SOURCE_RE = re.compile(
    r"^\s*(?P<next_hop>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:\s+\((?:metric\s+\d+|inaccessible)\))?.*from\s+(?P<source_id>\S+)"
)
_NEXT_HOP_BARE_RE = re.compile(r"^\s*(?P<nh>(?:\d{1,3}\.){3}\d{1,3})\s*$")
_ORIGIN_RE = re.compile(
    r"^\s*Origin\s+(?P<origin>\S+),"
    r"(?:\s*(?:metric\s+(?P<metric>\d+)|MED\s+not\s+set),?)?"
    r"\s*localpref\s+(?P<localpref>\d+),"
    r"\s*weight\s+(?P<weight>\d+)"
)
_COMMUNITY_RE = re.compile(r"^\s*Community:\s+(?P<communities>.+?)\s*$")
_EXT_COMMUNITY_RE = re.compile(
    r"^\s*Extended Community:\s+(?P<ext_communities>.+?)\s*$"
)
_ORIGINATOR_RE = re.compile(r"^\s*Originator:\s+(?P<originator>\S+)")
_CLUSTER_LIST_RE = re.compile(r"^\s*Cluster list:\s+(?P<cluster_list>.+?)\s*$")
_PEER_ID_RE = re.compile(r".*,\s+from\s+(?P<peer_id>\S+)")
_BEST_PATH_RE = re.compile(r"best.*path", re.IGNORECASE)
_MULTIPATH_RE = re.compile(r"multipath", re.IGNORECASE)
_PATH_STATUS_RE = re.compile(r"^\s*Path type:\s+(?P<status>.+?),")
_PATH_TYPE_LINE_RE = re.compile(r"^\s*Path type:")
_AS_PATH_RE = re.compile(r"^\s*AS-Path:\s+(?P<as_path>.+?)\s*$")
_AS_PATH_NONE_RE = re.compile(r"^\s*AS-Path:\s+NONE\s*$")

_NOISE_PREFIXES = ("Load for ", "Time source ")


def _is_noise(line: str) -> bool:
    """Return True if line is a device prompt or noise."""
    stripped = line.strip()
    if not stripped:
        return True
    if "#show " in stripped.lower() or stripped.endswith("#"):
        return True
    return any(stripped.startswith(p) for p in _NOISE_PREFIXES)


class _PathState:
    """Mutable accumulator for fields parsed from a path block."""

    __slots__ = (
        "next_hop",
        "source_id",
        "metric",
        "local_preference",
        "weight",
        "origin",
        "as_path",
        "communities",
        "ext_communities",
        "originator_id",
        "cluster_list",
        "peer_id",
        "status",
        "best_path",
        "multipath",
    )

    def __init__(self) -> None:
        self.next_hop: str | None = None
        self.source_id: str | None = None
        self.metric: int | None = None
        self.local_preference: int | None = None
        self.weight: int = 0
        self.origin: str = ""
        self.as_path: str | None = None
        self.communities: str | None = None
        self.ext_communities: str | None = None
        self.originator_id: str | None = None
        self.cluster_list: str | None = None
        self.peer_id: str | None = None
        self.status: str = ""
        self.best_path: bool = False
        self.multipath: bool = False


def _try_parse_next_hop(line: str, state: _PathState) -> bool:
    """Attempt to parse a next-hop line. Returns True if matched."""
    m = _NEXT_HOP_WITH_SOURCE_RE.match(line)
    if m:
        state.next_hop = m.group("next_hop")
        state.source_id = m.group("source_id")
        return True
    m = _NEXT_HOP_BARE_RE.match(line)
    if m:
        state.next_hop = m.group("nh")
        return True
    return False


def _parse_path_type_line(line: str, state: _PathState) -> None:
    """Extract status, best_path, multipath, and peer_id from a Path type line."""
    m = _PATH_STATUS_RE.match(line)
    if m:
        state.status = m.group("status").strip()
    if _BEST_PATH_RE.search(line):
        state.best_path = True
    if _MULTIPATH_RE.search(line):
        state.multipath = True
    m = _PEER_ID_RE.match(line)
    if m:
        state.peer_id = m.group("peer_id").rstrip(",.")


def _parse_origin_line(line: str, state: _PathState) -> None:
    """Extract origin, metric, localpref, and weight from an Origin line."""
    m = _ORIGIN_RE.match(line)
    if m:
        state.origin = m.group("origin")
        if m.group("metric"):
            state.metric = int(m.group("metric"))
        state.local_preference = int(m.group("localpref"))
        state.weight = int(m.group("weight"))


def _try_parse_attribute(line: str, state: _PathState) -> bool:
    """Try to parse community, ext community, originator, or cluster list.

    Returns True if any matched.
    """
    m = _COMMUNITY_RE.match(line)
    if m:
        state.communities = m.group("communities").strip()
        return True
    m = _EXT_COMMUNITY_RE.match(line)
    if m:
        state.ext_communities = m.group("ext_communities").strip()
        return True
    m = _ORIGINATOR_RE.match(line)
    if m:
        state.originator_id = m.group("originator")
        return True
    m = _CLUSTER_LIST_RE.match(line)
    if m:
        state.cluster_list = m.group("cluster_list").strip()
        return True
    return False


_OPTIONAL_PATH_FIELDS: list[tuple[str, str]] = [
    ("metric", "metric"),
    ("local_preference", "local_preference"),
    ("as_path", "as_path"),
    ("communities", "communities"),
    ("ext_communities", "extended_communities"),
    ("originator_id", "originator_id"),
    ("cluster_list", "cluster_list"),
    ("peer_id", "peer_id"),
    ("source_id", "source_id"),
]


def _build_path_entry(state: _PathState) -> PathEntry:
    """Build a PathEntry from accumulated state."""
    entry: PathEntry = {
        "next_hop": state.next_hop or "",
        "weight": state.weight,
        "origin": state.origin,
        "status": state.status,
        "best_path": state.best_path,
    }
    for attr, key in _OPTIONAL_PATH_FIELDS:
        value = getattr(state, attr)
        if value is not None:
            entry[key] = value  # type: ignore[literal-required]
    if state.multipath:
        entry["multipath"] = True
    return entry


def _parse_path_block(lines: list[str]) -> PathEntry | None:
    """Parse a single path block into a PathEntry.

    A path block starts with 'Path type:' and contains AS-Path,
    next-hop, Origin, and optional community/originator/cluster lines.
    """
    state = _PathState()

    for line in lines:
        if not line.strip():
            continue

        if _PATH_TYPE_LINE_RE.match(line):
            _parse_path_type_line(line, state)
            continue

        if state.next_hop is None and _try_parse_next_hop(line, state):
            continue

        if _AS_PATH_NONE_RE.match(line):
            continue
        m = _AS_PATH_RE.match(line)
        if m:
            state.as_path = m.group("as_path").strip()
            continue

        if _ORIGIN_RE.match(line):
            _parse_origin_line(line, state)
            continue

        _try_parse_attribute(line, state)

    if state.next_hop is None:
        return None

    return _build_path_entry(state)


def _split_path_blocks(lines: list[str]) -> list[list[str]]:
    """Split prefix detail lines into individual path blocks.

    Each path block starts with a 'Path type:' line. All lines between
    consecutive 'Path type:' lines belong to the same path.
    """
    blocks: list[list[str]] = []
    current: list[str] = []

    for line in lines:
        if _PATH_TYPE_LINE_RE.match(line) and current:
            blocks.append(current)
            current = [line]
        else:
            current.append(line)

    if current:
        blocks.append(current)

    return blocks


class _ParserState:
    """Mutable state for the top-level parse loop."""

    __slots__ = (
        "vrfs",
        "current_vrf",
        "current_router_id",
        "current_local_as",
        "current_prefix",
        "current_version",
        "prefix_lines",
    )

    def __init__(self) -> None:
        self.vrfs: dict[str, VrfEntry] = {}
        self.current_vrf: str | None = None
        self.current_router_id: str = ""
        self.current_local_as: int = 0
        self.current_prefix: str | None = None
        self.current_version: int = 0
        self.prefix_lines: list[str] = []

    def flush_prefix(self) -> None:
        """Flush the current prefix block into vrfs."""
        if not (self.current_vrf and self.current_prefix and self.prefix_lines):
            return
        _flush_prefix(
            self.vrfs,
            self.current_vrf,
            self.current_router_id,
            self.current_local_as,
            self.current_prefix,
            self.current_version,
            self.prefix_lines,
        )


def _handle_vrf_header(line: str, state: _ParserState) -> bool:
    """Handle a VRF header line. Returns True if matched."""
    m = _VRF_HEADER_RE.match(line)
    if not m:
        return False
    state.flush_prefix()
    state.current_prefix = None
    state.prefix_lines = []
    state.current_vrf = m.group("vrf")
    state.current_router_id = ""
    state.current_local_as = 0
    return True


def _handle_metadata_line(line: str, state: _ParserState) -> bool:
    """Handle Router ID or Local AS lines. Returns True if matched."""
    m = _ROUTER_ID_RE.match(line)
    if m:
        state.current_router_id = m.group("router_id")
        return True
    m = _LOCAL_AS_RE.match(line)
    if m:
        state.current_local_as = int(m.group("local_as"))
        return True
    return False


def _handle_network_line(line: str, state: _ParserState) -> bool:
    """Handle a BGP routing table entry line. Returns True if matched."""
    m = _NETWORK_RE.match(line)
    if not m:
        return False
    state.flush_prefix()
    state.current_prefix = m.group("prefix")
    vm = _VERSION_RE.search(line)
    state.current_version = int(vm.group("version")) if vm else 0
    state.prefix_lines = []
    return True


@register(OS.CISCO_NXOS, "show bgp vrf all ipv4 unicast detail")
class ShowBgpVrfAllIpv4UnicastDetailParser(
    BaseParser["ShowBgpVrfAllIpv4UnicastDetailResult"],
):
    """Parser for 'show bgp vrf all ipv4 unicast detail' on NX-OS.

    Example output::

        BGP routing table information for VRF default, address family IPv4 Unicast
        BGP table version is 35, Router ID: 10.0.0.1
        *Local AS number: 65000
        BGP routing table entry for 10.1.0.0/24, version 5
        Paths: (1 available, best #1)
          Path type: local, path is valid, is best path, no labeled nexthop
            AS-Path: NONE
              0.0.0.0 (metric 0) from 0.0.0.0 (10.0.0.1)
                Origin IGP, MED not set, localpref 100, weight 32768
    """

    @classmethod
    def parse(cls, output: str) -> ShowBgpVrfAllIpv4UnicastDetailResult:
        """Parse 'show bgp vrf all ipv4 unicast detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP detail data keyed by VRF and prefix.

        Raises:
            ValueError: If no VRF data found in output.
        """
        state = _ParserState()

        for line in output.splitlines():
            if _is_noise(line):
                continue
            if _handle_vrf_header(line, state):
                continue
            if _handle_metadata_line(line, state):
                continue
            if _handle_network_line(line, state):
                continue
            if state.current_prefix is not None:
                state.prefix_lines.append(line)

        state.flush_prefix()

        if not state.vrfs:
            msg = "No VRF data found in 'show bgp vrf all ipv4 unicast detail' output"
            raise ValueError(msg)

        return {"vrfs": state.vrfs}


def _flush_prefix(
    vrfs: dict[str, VrfEntry],
    vrf_name: str,
    router_id: str,
    local_as: int,
    prefix: str,
    version: int,
    lines: list[str],
) -> None:
    """Parse accumulated prefix lines and add to vrfs dict."""
    if vrf_name not in vrfs:
        vrfs[vrf_name] = {
            "router_id": router_id,
            "local_as": local_as,
            "prefixes": {},
        }

    paths: dict[str, PathEntry] = {}
    path_blocks = _split_path_blocks(lines)
    path_index = 1

    for block in path_blocks:
        entry = _parse_path_block(block)
        if entry is not None:
            paths[str(path_index)] = entry
            path_index += 1

    if paths:
        vrfs[vrf_name]["prefixes"][prefix] = {
            "version": version,
            "paths": paths,
        }
