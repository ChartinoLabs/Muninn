"""Parser for 'show bgp all detail' / 'show ip bgp all detail' on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PathEntry(TypedDict):
    """Schema for a single BGP path within a route entry."""

    as_path: str
    next_hop: str
    origin: str
    valid: bool
    best: bool
    metric: NotRequired[int]
    localpref: NotRequired[int]
    weight: NotRequired[int]
    sourced: NotRequired[bool]
    external: NotRequired[bool]
    internal: NotRequired[bool]
    received_only: NotRequired[bool]
    backup_repair: NotRequired[bool]
    from_peer: NotRequired[str]
    router_id: NotRequired[str]
    via: NotRequired[str]
    next_hop_metric: NotRequired[int]
    refresh_epoch: NotRequired[int]
    community: NotRequired[str]
    extended_community: NotRequired[str]
    originator: NotRequired[str]
    cluster_list: NotRequired[str]
    mpls_labels_in: NotRequired[str]
    mpls_labels_out: NotRequired[str]
    rx_pathid: NotRequired[str]
    tx_pathid: NotRequired[str]
    recursive_via: NotRequired[str]
    additional_path: NotRequired[bool]


class RouteTableEntry(TypedDict):
    """Schema for a single BGP routing table entry (prefix)."""

    version: int
    paths_available: int
    best_path: NotRequired[int]
    table: NotRequired[str]
    not_advertised_to_ebgp: NotRequired[bool]
    no_best_path: NotRequired[bool]
    advertised_to_update_groups: NotRequired[list[int]]
    not_advertised_to_any_peer: NotRequired[bool]
    flag: NotRequired[str]
    paths: list[PathEntry]


class RdSection(TypedDict):
    """Schema for a route distinguisher section."""

    rd: str
    default_vrf: NotRequired[str]
    routes: dict[str, RouteTableEntry]


class AddressFamilySection(TypedDict):
    """Schema for a single address family section."""

    route_distinguishers: NotRequired[dict[str, RdSection]]
    routes: NotRequired[dict[str, RouteTableEntry]]


class ShowBgpAllDetailResult(TypedDict):
    """Schema for 'show bgp all detail' parsed output on IOS-XE."""

    address_families: dict[str, AddressFamilySection]


# --- Compiled regex patterns ---

_AF_HEADER_RE = re.compile(r"^\s*For address family:\s+(.+?)\s*$")

_RD_RE = re.compile(
    r"^\s*Route Distinguisher:\s+(?P<rd>\S+)"
    r"(?:\s+\(default for vrf (?P<vrf>\S+)\))?\s*$"
)

_ROUTE_ENTRY_RE = re.compile(
    r"^\s*BGP routing table entry for\s+"
    r"(?:(?P<rd_prefix>\S+:\S+):)?(?P<prefix>\S+),\s+"
    r"version\s+(?P<version>\d+)\s*$"
)

_PATHS_RE = re.compile(
    r"^\s*Paths:\s+\((?P<count>\d+)\s+available"
    r"(?:,\s+best\s+#(?P<best>\d+))?"
    r"(?:,\s+table\s+(?P<table>\S+))?"
    r"(?:,\s+no best path)?"
    r"(?:,\s+(?P<not_ebgp>not advertised to EBGP peer))?"
    r"\)\s*$"
)

_FLAG_RE = re.compile(r"^\s*Flag:\s+(?P<flag>\S+)\s*$")

_ADVERTISED_GROUPS_RE = re.compile(r"^\s*Advertised to update-groups:\s*$")

_NOT_ADVERTISED_RE = re.compile(r"^\s*Not advertised to any peer\s*$")

_REFRESH_EPOCH_RE = re.compile(r"^\s*Refresh Epoch\s+(?P<epoch>\d+)\s*$")

_NEXTHOP_RE = re.compile(
    r"^\s+(?P<nexthop>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?:\s+\(metric\s+(?P<nh_metric>\d+)\))?"
    r"(?:\s+\(via\s+(?P<via>[^)]+)\))?"
    r"\s+from\s+(?P<from>\S+)"
    r"\s+\((?P<rid>\S+)\)\s*$"
)

_ORIGIN_RE = re.compile(
    r"^\s+Origin\s+(?P<origin>\S+)"
    r"(?:,\s+metric\s+(?P<metric>\d+))?"
    r"(?:,\s+localpref\s+(?P<localpref>\d+))?"
    r"(?:,\s+weight\s+(?P<weight>\d+))?"
    r"(?P<flags>(?:,\s+\S+)*)\s*$"
)

_COMMUNITY_RE = re.compile(r"^\s+Community:\s+(?P<community>.+?)\s*$")

_EXT_COMMUNITY_RE = re.compile(r"^\s+Extended Community:\s+(?P<ext>.+?)\s*$")

_ORIGINATOR_RE = re.compile(
    r"^\s+Originator:\s+(?P<originator>\S+),"
    r"\s+Cluster list:\s+(?P<cluster>.+?)\s*$"
)

_MPLS_LABELS_RE = re.compile(r"^\s+mpls labels in/out\s+(?P<in>\S+)/(?P<out>\S+)\s*$")

_PATHID_RE = re.compile(
    r"^\s+rx pathid:\s+(?P<rx>\S+),"
    r"\s+tx pathid:\s+(?P<tx>\S+)\s*$"
)

_ADDITIONAL_PATH_RE = re.compile(r"^\s+Additional-path\s*$")

_RECURSIVE_VIA_RE = re.compile(r",?\s*recursive-via-(\S+)")

_TIMESTAMP_RE = re.compile(r"^\[.*\]\s*\+\+\+")

# Minimum leading spaces for AS path lines
_AS_PATH_MIN_INDENT = 2
# Maximum leading spaces for AS path lines (next-hop lines have more)
_AS_PATH_MAX_INDENT = 12


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is a prompt or noise line."""
    if not stripped:
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    return stripped.startswith("Load for ") or stripped.startswith("Time source ")


def _is_timestamp_line(stripped: str) -> bool:
    """Return True if the line is a log timestamp line."""
    return bool(_TIMESTAMP_RE.match(stripped))


def _parse_origin_flags(origin_match: re.Match[str]) -> PathEntry:
    """Build a PathEntry from an Origin line regex match."""
    flags_raw = origin_match.group("flags") or ""
    flag_tokens = {f.strip().rstrip(",") for f in flags_raw.split(",") if f.strip()}

    entry: PathEntry = {
        "as_path": "",
        "next_hop": "",
        "origin": origin_match.group("origin"),
        "valid": "valid" in flag_tokens,
        "best": "best" in flag_tokens,
    }

    _set_origin_optional_fields(entry, origin_match, flag_tokens)
    return entry


def _set_origin_optional_fields(
    entry: PathEntry,
    m: re.Match[str],
    flag_tokens: set[str],
) -> None:
    """Set optional fields on a PathEntry from Origin line data."""
    if m.group("metric"):
        entry["metric"] = int(m.group("metric"))
    if m.group("localpref"):
        entry["localpref"] = int(m.group("localpref"))
    if m.group("weight"):
        entry["weight"] = int(m.group("weight"))
    _set_flag_booleans(entry, flag_tokens)


def _set_flag_booleans(entry: PathEntry, flag_tokens: set[str]) -> None:
    """Set boolean flag fields on a PathEntry."""
    if "sourced" in flag_tokens:
        entry["sourced"] = True
    if "external" in flag_tokens:
        entry["external"] = True
    if "internal" in flag_tokens:
        entry["internal"] = True
    if "backup/repair" in flag_tokens:
        entry["backup_repair"] = True


def _parse_as_path_line(line: str) -> tuple[str, bool]:
    """Parse an AS path line, returning (as_path, received_only)."""
    stripped = line.strip()
    received_only = False

    if stripped.endswith(", (received-only)"):
        received_only = True
        stripped = stripped[: -len(", (received-only)")].strip()
    elif stripped.endswith(", (received & used)"):
        stripped = stripped[: -len(", (received & used)")].strip()

    return stripped, received_only


def _parse_update_groups(lines: list[str], idx: int) -> tuple[list[int], int]:
    """Parse update group numbers from indented lines."""
    groups: list[int] = []
    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue
        tokens = line.split()
        if tokens and all(t.isdigit() for t in tokens):
            groups.extend(int(t) for t in tokens)
            idx += 1
        else:
            break
    return groups, idx


def _extract_recursive_via(text: str) -> str | None:
    """Extract recursive-via value from a text string."""
    m = _RECURSIVE_VIA_RE.search(text)
    return m.group(1) if m else None


def _strip_recursive_via(text: str) -> str:
    """Remove recursive-via annotation from a text string."""
    return _RECURSIVE_VIA_RE.sub("", text).strip().rstrip(",")


def _is_section_boundary(line: str, stripped: str) -> bool:
    """Return True if the line marks a section boundary."""
    return bool(
        _ROUTE_ENTRY_RE.match(line)
        or _AF_HEADER_RE.match(stripped)
        or _RD_RE.match(stripped)
    )


def _build_entry_from_nexthop(
    nh_match: re.Match[str],
    origin_match: re.Match[str],
    as_path: str,
    received_only: bool,
) -> PathEntry:
    """Build a PathEntry from next-hop and origin regex matches."""
    entry = _parse_origin_flags(origin_match)
    entry["as_path"] = as_path
    entry["next_hop"] = nh_match.group("nexthop")
    entry["from_peer"] = nh_match.group("from")
    entry["router_id"] = nh_match.group("rid")
    if received_only:
        entry["received_only"] = True
    if nh_match.group("nh_metric"):
        entry["next_hop_metric"] = int(nh_match.group("nh_metric"))
    if nh_match.group("via"):
        entry["via"] = nh_match.group("via")
    return entry


def _handle_nexthop_line(
    lines: list[str],
    idx: int,
    nh_match: re.Match[str],
    as_path: str,
    received_only: bool,
) -> tuple[PathEntry | None, int]:
    """Process a next-hop line and its following Origin line."""
    idx += 1
    if idx >= len(lines):
        return None, idx
    om = _ORIGIN_RE.match(lines[idx])
    if not om:
        return None, idx
    entry = _build_entry_from_nexthop(nh_match, om, as_path, received_only)
    return entry, idx + 1


def _handle_community_line(m: re.Match[str], entry: PathEntry) -> None:
    """Process a Community line."""
    entry["community"] = m.group("community")


def _handle_ext_community_line(m: re.Match[str], entry: PathEntry) -> None:
    """Process an Extended Community line."""
    raw = m.group("ext")
    recursive_via = _extract_recursive_via(raw)
    clean = _strip_recursive_via(raw)
    if clean:
        entry["extended_community"] = clean
    if recursive_via:
        entry["recursive_via"] = recursive_via


def _handle_originator_line(m: re.Match[str], entry: PathEntry) -> None:
    """Process an Originator/Cluster list line."""
    raw_cluster = m.group("cluster")
    recursive_via = _extract_recursive_via(raw_cluster)
    entry["originator"] = m.group("originator")
    entry["cluster_list"] = _strip_recursive_via(raw_cluster)
    if recursive_via:
        entry["recursive_via"] = recursive_via


# Pattern-handler table for path detail lines
_DETAIL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_COMMUNITY_RE, "community"),
    (_EXT_COMMUNITY_RE, "ext_community"),
    (_ORIGINATOR_RE, "originator"),
    (_MPLS_LABELS_RE, "mpls"),
    (_PATHID_RE, "pathid"),
    (_ADDITIONAL_PATH_RE, "additional"),
)


def _parse_path_detail_line(line: str, stripped: str, entry: PathEntry) -> None:
    """Parse a detail line belonging to a path entry."""
    for pattern, handler_key in _DETAIL_PATTERNS:
        m = pattern.match(line)
        if not m:
            continue
        _dispatch_detail_handler(handler_key, m, entry)
        return

    # Fallback: check for recursive-via on other lines
    if ", recursive-via-" in stripped:
        recursive_via = _extract_recursive_via(stripped)
        if recursive_via:
            entry["recursive_via"] = recursive_via


def _dispatch_detail_handler(key: str, m: re.Match[str], entry: PathEntry) -> None:
    """Dispatch to the appropriate detail line handler."""
    if key == "community":
        _handle_community_line(m, entry)
    elif key == "ext_community":
        _handle_ext_community_line(m, entry)
    elif key == "originator":
        _handle_originator_line(m, entry)
    elif key == "mpls":
        entry["mpls_labels_in"] = m.group("in")
        entry["mpls_labels_out"] = m.group("out")
    elif key == "pathid":
        entry["rx_pathid"] = m.group("rx")
        entry["tx_pathid"] = m.group("tx")
    elif key == "additional":
        entry["additional_path"] = True


def _is_as_path_start(line: str, stripped: str) -> bool:
    """Return True if line starts an AS path block."""
    if not stripped:
        return False
    leading = len(line) - len(line.lstrip())
    if leading < _AS_PATH_MIN_INDENT or leading > _AS_PATH_MAX_INDENT:
        return False
    first_token = stripped.split(",")[0].split()[0]
    return first_token == "Local" or first_token.isdigit()  # nosec B105


def _is_path_boundary(line: str, stripped: str) -> bool:
    """Return True if a line marks the end of a single path block."""
    return bool(
        _is_section_boundary(line, stripped)
        or _REFRESH_EPOCH_RE.match(stripped)
        or _is_as_path_start(line, stripped)
    )


def _parse_single_path(
    lines: list[str],
    idx: int,
    as_path: str,
    received_only: bool,
) -> tuple[PathEntry | None, int]:
    """Parse a single BGP path block after the AS path line.

    Returns (path_entry, next_line_index).
    """
    entry: PathEntry | None = None

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if not stripped:
            idx += 1
            continue

        if _is_path_boundary(line, stripped):
            break

        m = _NEXTHOP_RE.match(line)
        if m:
            entry, idx = _handle_nexthop_line(lines, idx, m, as_path, received_only)
            continue

        if entry is not None:
            _parse_path_detail_line(line, stripped, entry)
            idx += 1
            continue

        idx += 1

    return entry, idx


def _parse_route_paths(lines: list[str], idx: int) -> tuple[list[PathEntry], int]:
    """Parse all paths for a route entry. Returns (paths, next_idx)."""
    paths: list[PathEntry] = []

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if not stripped:
            idx += 1
            continue

        if _is_section_boundary(line, stripped):
            break

        m = _REFRESH_EPOCH_RE.match(stripped)
        if m:
            entry, idx = _parse_path_with_epoch(lines, idx, m)
            if entry is not None:
                paths.append(entry)
            continue

        if _is_as_path_start(line, stripped):
            entry, idx = _parse_path_without_epoch(lines, idx)
            if entry is not None:
                paths.append(entry)
            continue

        idx += 1

    return paths, idx


def _parse_path_with_epoch(
    lines: list[str], idx: int, m: re.Match[str]
) -> tuple[PathEntry | None, int]:
    """Parse a path block that starts with Refresh Epoch."""
    refresh_epoch = int(m.group("epoch"))
    idx += 1
    idx, as_path, received_only = _read_as_path(lines, idx)
    entry, idx = _parse_single_path(lines, idx, as_path, received_only)
    if entry is not None:
        entry["refresh_epoch"] = refresh_epoch
    return entry, idx


def _parse_path_without_epoch(
    lines: list[str], idx: int
) -> tuple[PathEntry | None, int]:
    """Parse a path block without a Refresh Epoch header."""
    as_path, received_only = _parse_as_path_line(lines[idx])
    idx += 1
    return _parse_single_path(lines, idx, as_path, received_only)


def _read_as_path(lines: list[str], idx: int) -> tuple[int, str, bool]:
    """Read the AS path line after a Refresh Epoch.

    Returns (next_idx, as_path, received_only).
    """
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            idx += 1
            continue
        if _is_as_path_start(line, stripped):
            as_path, received_only = _parse_as_path_line(line)
            return idx + 1, as_path, received_only
        break
    return idx, "", False


def _parse_paths_info(lines: list[str], idx: int, route: RouteTableEntry) -> int:
    """Parse the Paths: line for a route entry. Returns next idx."""
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue
        pm = _PATHS_RE.match(stripped)
        if pm:
            route["paths_available"] = int(pm.group("count"))
            if pm.group("best"):
                route["best_path"] = int(pm.group("best"))
            else:
                route["no_best_path"] = True
            if pm.group("table"):
                route["table"] = pm.group("table")
            if pm.group("not_ebgp"):
                route["not_advertised_to_ebgp"] = True
            return idx + 1
        idx += 1
    return idx


def _parse_route_metadata(lines: list[str], idx: int, route: RouteTableEntry) -> int:
    """Parse flags, advertised groups, and then paths.

    Returns next idx after parsing the route body.
    """
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue

        if _is_section_boundary(lines[idx], stripped):
            break

        idx = _try_route_metadata_line(lines, idx, stripped, route)
        if route["paths"]:
            break

    return idx


def _try_route_metadata_line(
    lines: list[str],
    idx: int,
    stripped: str,
    route: RouteTableEntry,
) -> int:
    """Handle a single metadata line within a route entry."""
    fm = _FLAG_RE.match(stripped)
    if fm:
        route["flag"] = fm.group("flag")
        return idx + 1

    if _ADVERTISED_GROUPS_RE.match(stripped):
        idx += 1
        groups, idx = _parse_update_groups(lines, idx)
        if groups:
            route["advertised_to_update_groups"] = groups
        return idx

    if _NOT_ADVERTISED_RE.match(stripped):
        route["not_advertised_to_any_peer"] = True
        return idx + 1

    if _REFRESH_EPOCH_RE.match(stripped) or _is_as_path_start(lines[idx], stripped):
        paths, idx = _parse_route_paths(lines, idx)
        route["paths"] = paths
        return idx

    return idx + 1


def _parse_route_entry(lines: list[str], idx: int) -> tuple[str, RouteTableEntry, int]:
    """Parse a BGP routing table entry block.

    Returns (prefix, route_entry, next_idx).
    """
    m = _ROUTE_ENTRY_RE.match(lines[idx])
    if not m:
        msg = f"Expected BGP routing table entry at line {idx}"
        raise ValueError(msg)

    route: RouteTableEntry = {
        "version": int(m.group("version")),
        "paths_available": 0,
        "paths": [],
    }
    idx = _parse_paths_info(lines, idx + 1, route)
    idx = _parse_route_metadata(lines, idx, route)
    return m.group("prefix"), route, idx


def _parse_af_section(lines: list[str], idx: int) -> tuple[AddressFamilySection, int]:
    """Parse an address family section. Returns (section, next_idx)."""
    af_section: AddressFamilySection = {}
    routes: dict[str, RouteTableEntry] = {}
    rd_sections: dict[str, RdSection] = {}
    current_routes: dict[str, RouteTableEntry] = routes

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if _is_noise_line(stripped) or _is_timestamp_line(stripped):
            idx += 1
            continue

        if _AF_HEADER_RE.match(stripped):
            break

        m = _RD_RE.match(stripped)
        if m:
            rd_key = m.group("rd")
            rd_entry: RdSection = {"rd": rd_key, "routes": {}}
            if m.group("vrf"):
                rd_entry["default_vrf"] = m.group("vrf")
            rd_sections[rd_key] = rd_entry
            current_routes = rd_entry["routes"]
            idx += 1
            continue

        if _ROUTE_ENTRY_RE.match(line):
            prefix, route_entry, idx = _parse_route_entry(lines, idx)
            current_routes[prefix] = route_entry
            continue

        idx += 1

    if rd_sections:
        af_section["route_distinguishers"] = rd_sections
    elif routes:
        af_section["routes"] = routes

    return af_section, idx


def _af_has_data(af: AddressFamilySection) -> bool:
    """Return True if the address family has meaningful data."""
    if af.get("route_distinguishers"):
        return True
    return bool(af.get("routes"))


@register(OS.CISCO_IOSXE, "show bgp all detail")
@register(OS.CISCO_IOSXE, "show ip bgp all detail")
class ShowBgpAllDetailParser(BaseParser["ShowBgpAllDetailResult"]):
    """Parser for 'show bgp all detail' on IOS-XE.

    Example output:
        For address family: VPNv4 Unicast
        Route Distinguisher: 65000:100 (default for vrf VRF100)
        BGP routing table entry for 65000:100:192.168.111.0/24, version 2
          Paths: (1 available, best #1, table VRF100)
    """

    @classmethod
    def parse(cls, output: str) -> ShowBgpAllDetailResult:
        """Parse 'show bgp all detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed data with routes grouped by address family.

        Raises:
            ValueError: If no address families with data found.
        """
        lines = output.splitlines()
        address_families: dict[str, AddressFamilySection] = {}
        idx = 0
        total = len(lines)

        while idx < total:
            stripped = lines[idx].strip()
            m = _AF_HEADER_RE.match(stripped)
            if m:
                af_name = m.group(1)
                idx += 1
                af_section, idx = _parse_af_section(lines, idx)
                if _af_has_data(af_section):
                    address_families[af_name] = af_section
            else:
                idx += 1

        if not address_families:
            msg = "No address families with data found in output"
            raise ValueError(msg)

        return {"address_families": address_families}
