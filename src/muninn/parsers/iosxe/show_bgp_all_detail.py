"""Parser for 'show bgp all detail' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PathEntry(TypedDict):
    """Schema for a single BGP path within a route."""

    as_path: str
    origin: str
    next_hop: str
    from_peer: str
    router_id: str
    metric: NotRequired[int]
    localpref: NotRequired[int]
    weight: NotRequired[int]
    valid: bool
    best: bool
    internal: NotRequired[bool]
    sourced: NotRequired[bool]
    multipath: NotRequired[bool]
    refresh_epoch: NotRequired[int]
    rx_pathid: NotRequired[str]
    tx_pathid: NotRequired[str]
    community: NotRequired[str]
    extended_community: NotRequired[str]
    originator: NotRequired[str]
    cluster_list: NotRequired[str]
    mpls_labels_in: NotRequired[str]
    mpls_labels_out: NotRequired[str]
    evpn_esi: NotRequired[str]
    gateway_address: NotRequired[str]
    local_vtep: NotRequired[str]
    evpn_label: NotRequired[int]
    updated: NotRequired[str]


class RouteEntry(TypedDict):
    """Schema for a single BGP route (prefix)."""

    version: int
    paths_available: int
    best_path: int
    table: str
    paths: list[PathEntry]
    rib_failure: NotRequired[str]
    multipath: NotRequired[str]
    bestpath: NotRequired[str]


class RouteDistinguisherEntry(TypedDict):
    """Schema for a Route Distinguisher group."""

    default_vrf: NotRequired[str]
    routes: dict[str, RouteEntry]


class AddressFamilyEntry(TypedDict):
    """Schema for routes within an address family."""

    routes: NotRequired[dict[str, RouteEntry]]
    route_distinguishers: NotRequired[dict[str, RouteDistinguisherEntry]]


class ShowBgpAllDetailResult(TypedDict):
    """Schema for 'show bgp all detail' parsed output."""

    address_families: dict[str, AddressFamilyEntry]


# --- Compiled regex patterns ---

_AF_HEADER_RE = re.compile(r"^\s*For address family:\s+(.+?)\s*$")

_RD_RE = re.compile(
    r"^\s*Route Distinguisher:\s+(\S+)"
    r"(?:\s+\(default for vrf (\S+)\))?\s*$"
)

_ROUTE_ENTRY_RE = re.compile(
    r"^\s*BGP routing table entry for\s+"
    r"(?:\[[\d:]+\])?"  # optional EVPN RD prefix like [5][65535:1][0][24][...]
    r"(?:\d+:\d+:)?"  # optional VPN RD prefix like 100:100:
    r"(\S+),\s+version\s+(\d+)"
)

_ROUTE_FULL_PREFIX_RE = re.compile(
    r"^\s*BGP routing table entry for\s+(\S+),\s+version\s+(\d+)"
)

_PATHS_RE = re.compile(
    r"^\s*Paths:\s+\((\d+)\s+available,\s+best\s+#(\d+),\s+table\s+([^,)\s]+)"
    r"(?:,\s*(.+?)\s*)?\)\s*$"
)

_BESTPATH_RE = re.compile(r"^\s*BGP Bestpath:\s+(.+?)\s*$")

_MULTIPATH_RE = re.compile(r"^\s*Multipath:\s+(.+?)\s*$")

_REFRESH_EPOCH_RE = re.compile(r"^\s*Refresh Epoch\s+(\d+)")

_ORIGIN_LINE_RE = re.compile(
    r"^\s*Origin\s+(?P<origin>\S+)"
    r"(?:,\s*metric\s+(?P<metric>\d+))?"
    r"(?:,\s*localpref\s+(?P<localpref>\d+))?"
    r"(?:,\s*weight\s+(?P<weight>\d+))?"
    r",\s*(?P<flags>.+)$"
)

_NEXT_HOP_RE = re.compile(
    r"^\s+(?P<nexthop>\S+)"
    r"(?:\s+\((?:metric\s+\d+\s*)?\))?"  # optional (metric N) or ()
    r"(?:\s+\((?:inaccessible|via\s+(?:vrf\s+\S+|default))\))?"
    r"\s+from\s+(?P<from>\S+)"
    r"\s+\((?P<rid>[^)]+)\)"
)

_RX_TX_RE = re.compile(r"^\s*rx pathid:\s+(\S+),\s+tx pathid:\s+(\S+)")

_COMMUNITY_RE = re.compile(r"^\s*Community:\s+(.+?)\s*$")
_EXT_COMMUNITY_RE = re.compile(r"^\s*Extended Community:\s+(.+?)\s*$")
_ORIGINATOR_RE = re.compile(r"^\s*Originator:\s+(\S+),\s+Cluster list:\s+(.+?)\s*$")
_MPLS_RE = re.compile(r"^\s*mpls labels in/out\s+(.+)/(\S+)\s*$")
_UPDATED_RE = re.compile(r"^\s*Updated on\s+(.+?)\s*$")

_EVPN_ESI_RE = re.compile(
    r"^\s*EVPN ESI:\s+(\S+),\s+Gateway Address:\s+(\S+)"
    r",\s+local vtep:\s+(\S+),\s+Label\s+(\d+)"
)


def _is_noise_line(stripped: str) -> bool:
    """Return True if a line is a device prompt or noise."""
    if not stripped:
        return True
    if "#" in stripped and ("show " in stripped.lower() or stripped.endswith("#")):
        return True
    return stripped.startswith("Load for ") or stripped.startswith("Time source ")


def _extract_as_path(line: str) -> str:
    """Extract the AS path from the first line after Refresh Epoch."""
    stripped = line.strip()
    if stripped.startswith("Local"):
        return ""
    return stripped.split(",")[0].strip()


def _parse_path_attributes(lines: list[str], idx: int) -> tuple[PathEntry | None, int]:
    """Parse a single BGP path starting from the AS path / source line.

    Returns the parsed PathEntry and the next line index.
    """
    if idx >= len(lines):
        return None, idx

    as_path = _extract_as_path(lines[idx])
    idx += 1

    if idx >= len(lines):
        return None, idx

    # Next line should be the next-hop line
    nh_match = _NEXT_HOP_RE.match(lines[idx])
    if not nh_match:
        return None, idx

    path: PathEntry = {
        "as_path": as_path,
        "origin": "",
        "next_hop": nh_match.group("nexthop"),
        "from_peer": nh_match.group("from"),
        "router_id": nh_match.group("rid"),
        "valid": False,
        "best": False,
    }
    idx += 1

    # Parse attribute lines until a boundary
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue
        if _is_path_boundary(stripped):
            break
        idx = _parse_single_attribute(stripped, path, idx)

    return path, idx


def _is_path_boundary(stripped: str) -> bool:
    """Return True if the stripped line starts a new section or path."""
    if stripped.startswith("BGP routing table entry"):
        return True
    if stripped.startswith("For address family:"):
        return True
    if stripped.startswith("Route Distinguisher:"):
        return True
    if _REFRESH_EPOCH_RE.match(stripped):
        return True
    return False


_ORIGIN_INT_FIELDS: tuple[tuple[str, str], ...] = (
    ("metric", "metric"),
    ("localpref", "localpref"),
    ("weight", "weight"),
)

_ORIGIN_BOOL_FLAGS: tuple[tuple[str, str], ...] = (
    ("internal", "internal"),
    ("sourced", "sourced"),
)


def _apply_origin_match(m: re.Match[str], path: PathEntry) -> None:
    """Apply Origin line match groups to a path entry."""
    path["origin"] = m.group("origin")
    for group_name, field_name in _ORIGIN_INT_FIELDS:
        val = m.group(group_name)
        if val:
            path[field_name] = int(val)  # type: ignore[literal-required]
    flag_set = {f.strip() for f in m.group("flags").split(",")}
    path["valid"] = "valid" in flag_set
    path["best"] = "best" in flag_set
    for flag, field in _ORIGIN_BOOL_FLAGS:
        if flag in flag_set:
            path[field] = True  # type: ignore[literal-required]
    if any("multipath" in f for f in flag_set):
        path["multipath"] = True


def _apply_evpn_match(m: re.Match[str], path: PathEntry) -> None:
    """Apply EVPN ESI match groups to a path entry."""
    path["evpn_esi"] = m.group(1)
    path["gateway_address"] = m.group(2)
    path["local_vtep"] = m.group(3)
    path["evpn_label"] = int(m.group(4))


def _parse_single_attribute(stripped: str, path: PathEntry, idx: int) -> int:
    """Parse one attribute line and update the path entry.

    Returns next index.
    """
    m = _ORIGIN_LINE_RE.match(stripped)
    if m:
        _apply_origin_match(m, path)
        return idx + 1

    m = _RX_TX_RE.match(stripped)
    if m:
        path["rx_pathid"] = m.group(1)
        path["tx_pathid"] = m.group(2)
        return idx + 1

    m = _COMMUNITY_RE.match(stripped)
    if m:
        path["community"] = m.group(1)
        return idx + 1

    m = _EXT_COMMUNITY_RE.match(stripped)
    if m:
        path["extended_community"] = m.group(1)
        return idx + 1

    m = _ORIGINATOR_RE.match(stripped)
    if m:
        path["originator"] = m.group(1)
        path["cluster_list"] = m.group(2)
        return idx + 1

    m = _MPLS_RE.match(stripped)
    if m:
        path["mpls_labels_in"] = m.group(1)
        path["mpls_labels_out"] = m.group(2)
        return idx + 1

    m = _EVPN_ESI_RE.match(stripped)
    if m:
        _apply_evpn_match(m, path)
        return idx + 1

    m = _UPDATED_RE.match(stripped)
    if m:
        path["updated"] = m.group(1)
        return idx + 1

    # Skip unrecognized lines (vxlan vtep info, binding SID, etc.)
    return idx + 1


def _parse_route_header(
    lines: list[str], idx: int
) -> tuple[str, int, str | None, int, int, str, str | None, str | None, int]:
    """Parse the header portion of a route block.

    Returns (raw_prefix, version, bestpath, paths_available, best_path,
             table, rib_failure, multipath, next_idx).
    """
    m = _ROUTE_FULL_PREFIX_RE.match(lines[idx])
    if not m:
        msg = f"Expected route entry at line {idx}"
        raise ValueError(msg)

    raw_prefix = m.group(1)
    version = int(m.group(2))
    idx += 1

    # Optional: BGP Bestpath line
    bestpath = None
    if idx < len(lines) and (bp := _BESTPATH_RE.match(lines[idx])):
        bestpath = bp.group(1)
        idx += 1

    # Paths line
    paths_available, best_path, table, rib_failure, idx = _parse_paths_line(lines, idx)

    # Optional: Multipath line
    multipath = None
    if idx < len(lines) and (mp := _MULTIPATH_RE.match(lines[idx])):
        multipath = mp.group(1)
        idx += 1

    return (
        raw_prefix,
        version,
        bestpath,
        paths_available,
        best_path,
        table,
        rib_failure,
        multipath,
        idx,
    )


def _parse_paths_line(
    lines: list[str], idx: int
) -> tuple[int, int, str, str | None, int]:
    """Parse the 'Paths:' line. Returns (available, best, table, rib_failure, idx)."""
    if idx >= len(lines):
        return 0, 0, "", None, idx
    pm = _PATHS_RE.match(lines[idx])
    if not pm:
        return 0, 0, "", None, idx
    extra = pm.group(4)
    rib_failure = extra.strip() if extra and "RIB-failure" in extra else None
    return int(pm.group(1)), int(pm.group(2)), pm.group(3), rib_failure, idx + 1


def _parse_route_block(lines: list[str], idx: int) -> tuple[str, RouteEntry, int]:
    """Parse a single BGP route block.

    Returns (prefix, route_entry, next_line_index).
    """
    (
        raw_prefix,
        version,
        bestpath,
        paths_available,
        best_path,
        table,
        rib_failure,
        multipath,
        idx,
    ) = _parse_route_header(lines, idx)

    # Skip "Advertised to" / "Not advertised" lines
    idx = _skip_advertised_lines(lines, idx)

    # Parse individual paths
    paths: list[PathEntry] = []
    idx = _parse_all_paths(lines, idx, paths)

    # Strip RD prefix from the route key for cleaner output
    prefix = _strip_rd_prefix(raw_prefix)

    route: RouteEntry = {
        "version": version,
        "paths_available": paths_available,
        "best_path": best_path,
        "table": table,
        "paths": paths,
    }
    if rib_failure:
        route["rib_failure"] = rib_failure
    if multipath:
        route["multipath"] = multipath
    if bestpath:
        route["bestpath"] = bestpath

    return prefix, route, idx


def _is_update_group_line(text: str) -> bool:
    """Return True if text contains only digits and spaces (update group IDs)."""
    return all(c.isdigit() or c.isspace() for c in text)


def _skip_advertised_lines(lines: list[str], idx: int) -> int:
    """Skip 'Advertised to' and 'Not advertised' block lines."""
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue
        if not stripped.startswith(("Advertised to", "Not advertised")):
            break
        idx += 1
        idx = _skip_update_group_ids(lines, idx)
    return idx


def _skip_update_group_ids(lines: list[str], idx: int) -> int:
    """Skip lines that contain only update-group ID numbers."""
    while idx < len(lines):
        next_stripped = lines[idx].strip()
        if not next_stripped:
            return idx + 1
        if _is_update_group_line(next_stripped):
            idx += 1
            continue
        break
    return idx


def _parse_all_paths(lines: list[str], idx: int, paths: list[PathEntry]) -> int:
    """Parse all path entries for a route. Returns next line index."""
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue

        # Check for section boundaries
        if stripped.startswith("BGP routing table entry"):
            break
        if stripped.startswith("For address family:"):
            break
        if stripped.startswith("Route Distinguisher:"):
            break

        epoch_match = _REFRESH_EPOCH_RE.match(stripped)
        if epoch_match:
            refresh_epoch = int(epoch_match.group(1))
            idx += 1
            path_entry, idx = _parse_path_attributes(lines, idx)
            if path_entry:
                path_entry["refresh_epoch"] = refresh_epoch
                paths.append(path_entry)
            continue

        # Skip any other unrecognized lines
        idx += 1

    return idx


def _strip_rd_prefix(prefix: str) -> str:
    """Strip route distinguisher prefix from a route prefix.

    Examples:
        '100:100:10.229.11.11/32' -> '10.229.11.11/32'
        '10.100.1.1:3014:0.0.0.0/0' -> '0.0.0.0/0'
        '[5][65535:1][0][24][10.36.3.0]/17' -> '[5][65535:1][0][24][10.36.3.0]/17'
        '2001:1:1:1::1/128' -> '2001:1:1:1::1/128'
    """
    # EVPN prefixes with brackets are never stripped
    if prefix.startswith("["):
        return prefix
    # VPN RD formats: N:N: or IP:N: before the actual prefix
    # Match RD patterns like 100:100: or 10.100.1.1:3014:
    rd_match = re.match(r"^(\S+:\d+:)(.+)$", prefix)
    if rd_match:
        candidate = rd_match.group(2)
        # If the remainder looks like an IPv4 prefix, strip the RD
        if re.match(r"^\d{1,3}\.", candidate):
            return candidate
    return prefix


def _parse_address_family(
    lines: list[str], idx: int
) -> tuple[AddressFamilyEntry | None, int]:
    """Parse all content within a single address family section.

    Returns (address family entry, next line index).
    """
    direct_routes: dict[str, RouteEntry] = {}
    route_distinguishers: dict[str, RouteDistinguisherEntry] = {}
    current_rd: str | None = None
    current_vrf: str | None = None
    current_routes: dict[str, RouteEntry] = {}

    while idx < len(lines):
        stripped = lines[idx].strip()

        if not stripped:
            idx += 1
            continue

        # New address family = end of this one
        if stripped.startswith("For address family:"):
            break

        # Route Distinguisher
        rd_match = _RD_RE.match(stripped)
        if rd_match:
            current_routes = _flush_current_rd(
                route_distinguishers,
                current_rd,
                current_vrf,
                current_routes,
            )
            current_rd = rd_match.group(1)
            current_vrf = rd_match.group(2)
            idx += 1
            continue

        # Route entry
        if stripped.startswith("BGP routing table entry"):
            prefix, route, idx = _parse_route_block(lines, idx)
            if current_rd is None:
                direct_routes[prefix] = route
            else:
                current_routes[prefix] = route
            continue

        # Skip noise
        idx += 1

    _flush_current_rd(route_distinguishers, current_rd, current_vrf, current_routes)

    entry: AddressFamilyEntry = {}
    if direct_routes:
        entry["routes"] = direct_routes
    if route_distinguishers:
        entry["route_distinguishers"] = route_distinguishers

    return (entry or None), idx


def _build_rd_entry(
    vrf: str | None,
    routes: dict[str, RouteEntry],
) -> RouteDistinguisherEntry:
    """Build a RouteDistinguisherEntry with optional VRF."""
    entry: RouteDistinguisherEntry = {"routes": routes}
    if vrf is not None:
        entry["default_vrf"] = vrf
    return entry


def _flush_current_rd(
    route_distinguishers: dict[str, RouteDistinguisherEntry],
    rd: str | None,
    vrf: str | None,
    routes: dict[str, RouteEntry],
) -> dict[str, RouteEntry]:
    """Store the current RD block if it has routes and reset state."""
    if rd is not None and routes:
        _merge_rd_entry(route_distinguishers, rd, vrf, routes)
        return {}
    return routes


def _merge_rd_entry(
    route_distinguishers: dict[str, RouteDistinguisherEntry],
    rd: str,
    vrf: str | None,
    routes: dict[str, RouteEntry],
) -> None:
    """Merge routes into a Route Distinguisher entry."""
    entry = route_distinguishers.setdefault(rd, {"routes": {}})
    if vrf is not None:
        entry["default_vrf"] = vrf
    entry["routes"].update(routes)


def _merge_address_family_entry(
    current: AddressFamilyEntry,
    new: AddressFamilyEntry,
) -> AddressFamilyEntry:
    """Merge parsed address family data from repeated sections."""
    merged: AddressFamilyEntry = {}

    if "routes" in current or "routes" in new:
        merged["routes"] = {
            **current.get("routes", {}),
            **new.get("routes", {}),
        }

    merged_rds = {
        rd: {
            **rd_entry,
            "routes": dict(rd_entry["routes"]),
        }
        for rd, rd_entry in current.get("route_distinguishers", {}).items()
    }
    for rd, rd_entry in new.get("route_distinguishers", {}).items():
        if rd not in merged_rds:
            merged_rds[rd] = {
                **rd_entry,
                "routes": dict(rd_entry["routes"]),
            }
            continue
        if "default_vrf" in rd_entry:
            merged_rds[rd]["default_vrf"] = rd_entry["default_vrf"]
        merged_rds[rd]["routes"].update(rd_entry["routes"])

    if merged_rds:
        merged["route_distinguishers"] = merged_rds

    return merged


@register(OS.CISCO_IOSXE, "show bgp all detail")
class ShowBgpAllDetailParser(BaseParser["ShowBgpAllDetailResult"]):
    """Parser for 'show bgp all detail' command.

    Example output:
        For address family: IPv4 Unicast
        BGP routing table entry for 10.4.1.1/32, version 4
        Paths: (1 available, best #1, table default)
          0.0.0.0 from 0.0.0.0 (10.1.1.1)
            Origin incomplete, localpref 100, valid, sourced, best
    """

    @classmethod
    def parse(cls, output: str) -> ShowBgpAllDetailResult:
        """Parse 'show bgp all detail' output.

        Args:
            output: Raw CLI output from 'show bgp all detail' command.

        Returns:
            Parsed data organized by address family.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        address_families: dict[str, AddressFamilyEntry] = {}
        idx = 0

        while idx < len(lines):
            stripped = lines[idx].strip()

            if _is_noise_line(stripped):
                idx += 1
                continue

            af_match = _AF_HEADER_RE.match(stripped)
            if af_match:
                af_name = af_match.group(1)
                idx += 1
                af_entry, idx = _parse_address_family(lines, idx)
                if af_entry:
                    existing_entry = address_families.get(af_name)
                    if existing_entry is None:
                        address_families[af_name] = af_entry
                    else:
                        address_families[af_name] = _merge_address_family_entry(
                            existing_entry,
                            af_entry,
                        )
                continue

            idx += 1

        if not address_families:
            msg = "No BGP route detail entries found in output"
            raise ValueError(msg)

        return {"address_families": address_families}
