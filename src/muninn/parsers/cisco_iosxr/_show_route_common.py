"""Shared parsing for IOS-XR 'show route ipv4' / 'show route ipv6' output.

Two output formats exist and are address-family agnostic apart from the prefix
regex:

* the routing table (``show route [vrf <vrf>] ipv4``), one or more lines per
  prefix; and
* the per-prefix detail view (``show route ipv4 <prefix> [detail]``), made of
  ``Routing entry for ...`` blocks.
"""

import re
from collections.abc import Callable
from typing import TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.utils import canonical_interface_name

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RouteNextHop(TypedDict):
    """One path of a routing-table entry."""

    next_hop: NotRequired[str]
    nexthop_vrf: NotRequired[str]
    distance: NotRequired[int]
    metric: NotRequired[int]
    uptime: str
    interface: NotRequired[str]
    directly_connected: bool
    is_backup: bool


class Route(TypedDict):
    """One prefix of the routing table."""

    prefix: str
    mask: int
    protocol: str
    next_hops: list[RouteNextHop]


class GatewayOfLastResort(TypedDict):
    """Gateway of last resort as reported above the routing table."""

    next_hop: str
    network: str


class ShowRouteResult(TypedDict):
    """Routing table of a single VRF, keyed by ``prefix/length``."""

    routes: dict[str, Route]
    gateway_of_last_resort: NotRequired[GatewayOfLastResort]


class ShowRouteVrfAllResult(TypedDict):
    """``show route vrf all`` output: one routing table per ``VRF: <name>``."""

    vrfs: dict[str, ShowRouteResult]


class RedistAdvertiser(TypedDict):
    """A client the route is redistributed to."""

    protocol_id: int
    client_id: int


class RouteDetailPath(TypedDict):
    """One routing descriptor block of a detailed route entry."""

    next_hop: NotRequired[str]
    directly_connected: bool
    from_address: NotRequired[str]
    interface: NotRequired[str]
    attributes: NotRequired[list[str]]
    nexthop_vrf: NotRequired[str]
    nexthop_table: NotRequired[str]
    nexthop_address_family: NotRequired[str]
    table_id: NotRequired[str]
    metric: NotRequired[int]
    label: NotRequired[str]
    tunnel_id: NotRequired[str]
    binding_label: NotRequired[str]
    extended_communities_count: NotRequired[int]
    nhid: NotRequired[str]
    nhid_ref_count: NotRequired[int]
    path_grouping_id: NotRequired[int]
    srv6_headend: NotRequired[str]
    srv6_sid_list: NotRequired[list[str]]
    repair_nodes: NotRequired[list[str]]


class RouteDetail(TypedDict):
    """One ``Routing entry for ...`` block."""

    prefix: str
    mask: int
    known_via: str
    distance: int
    metric: int
    candidate_default: bool
    labeled_sr: bool
    route_type: NotRequired[str]
    tag: NotRequired[int]
    installed: NotRequired[str]
    installed_age: NotRequired[str]
    paths: list[RouteDetailPath]
    route_version: NotRequired[int]
    local_label: NotRequired[str]
    ip_precedence: NotRequired[str]
    qos_group_id: NotRequired[str]
    flow_tag: NotRequired[str]
    fwd_class: NotRequired[str]
    route_priority: NotRequired[str]
    route_priority_value: NotRequired[int]
    svd_type: NotRequired[str]
    download_priority: NotRequired[int]
    download_version: NotRequired[int]
    redist_advertisers: NotRequired[dict[str, RedistAdvertiser]]


class ShowRouteDetailResult(TypedDict):
    """Detailed route entries keyed by ``prefix/length``."""

    routes: dict[str, RouteDetail]


# ---------------------------------------------------------------------------
# Routing table format
# ---------------------------------------------------------------------------

_VIA_RE = re.compile(
    r"^\[(?P<distance>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<next_hop>[^\s,]+)"
    r"(?:\s+\(nexthop in vrf (?P<nexthop_vrf>[^)\s]+)\))?"
    r",\s*(?P<uptime>[^,\s]+)"
    r"(?:,\s*(?P<interface>[^,\s]+))?"
    r"(?P<backup>\s+\(!\))?\s*$"
)
_CONNECTED_RE = re.compile(
    r"^is directly connected,"
    r"(?:\s*(?P<uptime>[^,\s]+)(?:,\s*(?P<interface>[^,\s]+))?)?\s*$"
)
# Second half of a wrapped "is directly connected," line: "<uptime>, <intf>"
_CONNECTED_TAIL_RE = re.compile(r"^(?P<uptime>[^,\s]+),\s*(?P<interface>[^,\s]+)\s*$")
_GATEWAY_RE = re.compile(
    r"^Gateway of last resort is (?P<next_hop>\S+) to network (?P<network>\S+)"
)
_VRF_HEADER_RE = re.compile(r"^VRF: (?P<vrf>\S+)\s*$")

_ROUTE_LINE_TEMPLATE = (
    r"^(?P<code>[A-Za-z][A-Za-z0-9* ]{{0,4}}?)\s+"
    r"(?P<prefix>{address})/(?P<mask>\d{{1,3}})(?P<rest>[\s,].*)?$"
)


def route_line_re(address: str) -> re.Pattern[str]:
    """Compile the route-start line regex for the given address pattern."""
    return re.compile(_ROUTE_LINE_TEMPLATE.format(address=address))


def _interface(name: str | None) -> dict[str, str]:
    if not name:
        return {}
    return {"interface": canonical_interface_name(name, os=OS.CISCO_IOSXR)}


def _via_hop(match: re.Match[str]) -> dict:
    hop: dict = {"next_hop": match["next_hop"]}
    if match["nexthop_vrf"]:
        hop["nexthop_vrf"] = match["nexthop_vrf"]
    hop["distance"] = int(match["distance"])
    hop["metric"] = int(match["metric"])
    hop["uptime"] = match["uptime"]
    hop.update(_interface(match["interface"]))
    hop["directly_connected"] = False
    hop["is_backup"] = match["backup"] is not None
    return hop


def _connected_hop(uptime: str, interface: str | None) -> dict:
    hop: dict = {"uptime": uptime, **_interface(interface)}
    hop["directly_connected"] = True
    hop["is_backup"] = False
    return hop


class _TableState:
    """Mutable state while walking routing-table output."""

    def __init__(self) -> None:
        self.top: dict = {"routes": {}}
        self.vrfs: dict[str, dict] = {}
        self.table: dict = self.top
        self.route: dict | None = None
        # True after "is directly connected," whose uptime/intf wrapped
        self.connected_pending = False

    def add_hop(self, hop: dict) -> None:
        if self.route is not None:
            self.route["next_hops"].append(hop)


def _handle_path_text(text: str, state: _TableState) -> bool:
    """Handle the path portion of a route line or a continuation line."""
    if state.connected_pending:
        state.connected_pending = False
        tail = _CONNECTED_TAIL_RE.match(text)
        if tail:
            state.add_hop(_connected_hop(tail["uptime"], tail["interface"]))
            return True
    if not text:
        return False
    via = _VIA_RE.match(text)
    if via:
        state.add_hop(_via_hop(via))
        return True
    connected = _CONNECTED_RE.match(text)
    if connected:
        if connected["uptime"]:
            state.add_hop(_connected_hop(connected["uptime"], connected["interface"]))
        else:
            state.connected_pending = True
        return True
    return False


def _start_route(match: re.Match[str], state: _TableState) -> None:
    route = {
        "prefix": match["prefix"],
        "mask": int(match["mask"]),
        "protocol": match["code"],
        "next_hops": [],
    }
    state.table["routes"][f"{match['prefix']}/{match['mask']}"] = route
    state.route = route
    state.connected_pending = False
    _handle_path_text((match["rest"] or "").strip(), state)


def _handle_header(line: str, state: _TableState) -> bool:
    vrf = _VRF_HEADER_RE.match(line)
    if vrf:
        state.table = state.vrfs.setdefault(vrf["vrf"], {"routes": {}})
        state.route = None
        return True
    gateway = _GATEWAY_RE.match(line)
    if gateway:
        state.table["gateway_of_last_resort"] = {
            "next_hop": gateway["next_hop"],
            "network": gateway["network"],
        }
        return True
    return False


def parse_route_table(
    output: str, route_re: re.Pattern[str], *, vrf_all: bool = False
) -> dict:
    """Parse routing-table output.

    Returns a ``ShowRouteResult``-shaped dict, or with ``vrf_all`` a
    ``ShowRouteVrfAllResult``-shaped dict built from ``VRF: <name>`` sections.
    Lines that are not routes, paths, VRF headers or the gateway line (legend,
    timestamps, prompts, command echo, ``% No matching routes found``) are
    ignored.

    Raises:
        ValueError: If no routes (or, with ``vrf_all``, no VRF sections) are
            found, or VRF sections appear in single-table output.
    """
    state = _TableState()
    for raw in output.splitlines():
        line = raw.strip()
        if not line or _handle_header(line, state):
            continue
        route = route_re.match(line)
        if route:
            _start_route(route, state)
        elif not _handle_path_text(line, state):
            state.connected_pending = False

    if vrf_all:
        if not state.vrfs:
            msg = "No 'VRF:' sections found in output"
            raise ValueError(msg)
        return {"vrfs": state.vrfs}
    if state.vrfs:
        msg = "Unexpected 'VRF:' sections; use the 'show route vrf all' parser"
        raise ValueError(msg)
    if not state.top["routes"]:
        msg = "No routes found in output"
        raise ValueError(msg)
    return state.top


# ---------------------------------------------------------------------------
# Detail format ("Routing entry for ...")
# ---------------------------------------------------------------------------

_PLACEHOLDERS = frozenset({"None", "Not Set"})

_ENTRY_TEMPLATE = r"^Routing entry for (?P<prefix>{address})/(?P<mask>\d{{1,3}})\s*$"
_KNOWN_VIA_RE = re.compile(
    r'^Known via "(?P<known_via>[^"]+)", distance (?P<distance>\d+), '
    r"metric (?P<metric>\d+)(?P<rest>.*)$"
)
_PATH_START_RE = re.compile(
    r"^(?P<next_hop>[0-9A-Fa-f]*[:.][0-9A-Fa-f:.]*|directly connected)"
    r"(?:,\s*(?P<rest>.*))?$"
)
_REDIST_RE = re.compile(
    r"^(?P<name>\S+) \(protoid=(?P<protocol_id>\d+), clientid=(?P<client_id>\d+)\)$"
)


def entry_re(address: str) -> re.Pattern[str]:
    """Compile the ``Routing entry for`` regex for the given address pattern."""
    return re.compile(_ENTRY_TEMPLATE.format(address=address))


def _fields(pattern: str, **converters: Callable[[str], object]) -> tuple:
    return re.compile(pattern), converters


# (regex, {group: converter}) — every named group lands in the output under
# its own name unless the value is a CLI placeholder ("None", "Not Set").
_ROUTE_FIELDS = (
    _fields(r"^Tag (?P<tag>\d+)(?:, type (?P<route_type>\S+))?$", tag=int),
    _fields(r"^Installed (?P<installed>.+?) for (?P<installed_age>\S+)$"),
    _fields(r"^Route version is \S+ \((?P<route_version>\d+)\)$", route_version=int),
    _fields(r"^Local label: (?P<local_label>\S+)$"),
    _fields(r"^IP Precedence: (?P<ip_precedence>.+)$"),
    _fields(r"^QoS Group ID: (?P<qos_group_id>.+)$"),
    _fields(r"^Flow-tag: (?P<flow_tag>.+)$"),
    _fields(r"^Fwd-class: (?P<fwd_class>.+)$"),
    _fields(
        r"^Route Priority: (?P<route_priority>\S+) \((?P<route_priority_value>\d+)\)"
        r"(?: SVD Type (?P<svd_type>\S+))?$",
        route_priority_value=int,
    ),
    _fields(
        r"^Download Priority (?P<download_priority>\d+), "
        r"Download Version (?P<download_version>\d+)$",
        download_priority=int,
        download_version=int,
    ),
)

_PATH_FIELDS = (
    _fields(
        r'^Nexthop in Vrf: "(?P<nexthop_vrf>[^"]+)", Table: "(?P<nexthop_table>[^"]+)"'
        r", (?P<nexthop_address_family>[^,]+), Table Id: (?P<table_id>\S+)$"
    ),
    _fields(r"^Route metric is (?P<metric>\d+)$", metric=int),
    _fields(r"^Label: (?P<label>\S+)$"),
    _fields(r"^Tunnel ID: (?P<tunnel_id>\S+)$"),
    _fields(r"^Binding Label: (?P<binding_label>\S+)$"),
    _fields(
        r"^Extended communities count: (?P<extended_communities_count>\d+)$",
        extended_communities_count=int,
    ),
    _fields(
        r"^NHID:(?P<nhid>[^(\s]+)\(Ref:(?P<nhid_ref_count>\d+)\)$",
        nhid_ref_count=int,
    ),
    _fields(r"^Path Grouping ID: (?P<path_grouping_id>\d+)$", path_grouping_id=int),
    _fields(
        r"^SRv6 Headend: (?P<srv6_headend>.+?), SID-list \{(?P<srv6_sid_list>[^}]*)\}$",
        srv6_sid_list=str.split,
    ),
    _fields(
        r"^Repair Node\(s\): (?P<repair_nodes>.+)$", repair_nodes=lambda v: v.split()
    ),
)


def _apply_fields(line: str, specs: tuple, target: dict) -> bool:
    for regex, converters in specs:
        match = regex.match(line)
        if not match:
            continue
        for key, value in match.groupdict().items():
            if value is None or value in _PLACEHOLDERS:
                continue
            target[key] = converters.get(key, str)(value)
        return True
    return False


def _apply_known_via(match: re.Match[str], route: dict) -> None:
    route["known_via"] = match["known_via"]
    route["distance"] = int(match["distance"])
    route["metric"] = int(match["metric"])
    route["candidate_default"] = False
    route["labeled_sr"] = False
    for item in match["rest"].split(","):
        item = item.strip()
        if item == "candidate default path":
            route["candidate_default"] = True
        elif item == "labeled SR":
            route["labeled_sr"] = True
        elif item.startswith("type "):
            route["route_type"] = item.removeprefix("type ")


def _new_path(match: re.Match[str]) -> dict:
    path: dict = {"directly_connected": match["next_hop"] == "directly connected"}
    if not path["directly_connected"]:
        path["next_hop"] = match["next_hop"]
    attributes = []
    for item in (match["rest"] or "").split(","):
        item = item.strip()
        if item.startswith("from "):
            path["from_address"] = item.removeprefix("from ")
        elif item.startswith("via "):
            path.update(_interface(item.removeprefix("via ")))
        elif item:
            attributes.append(item)
    if attributes:
        path["attributes"] = attributes
    return path


class _DetailState:
    """Mutable state while walking detail output."""

    def __init__(self) -> None:
        self.routes: dict[str, dict] = {}
        self.route: dict | None = None
        self.path: dict | None = None
        self.section: str | None = None  # "paths" | "redist" | None


def _start_entry(match: re.Match[str], state: _DetailState) -> None:
    route: dict = {
        "prefix": match["prefix"],
        "mask": int(match["mask"]),
        "paths": [],
    }
    state.routes[f"{match['prefix']}/{match['mask']}"] = route
    state.route, state.path, state.section = route, None, None


def _handle_section_line(line: str, route: dict, state: _DetailState) -> bool:
    if line == "Routing Descriptor Blocks":
        state.section = "paths"
        return True
    if line == "Redist Advertisers:":
        state.section, state.path = "redist", None
        return True
    if state.section == "redist":
        redist = _REDIST_RE.match(line)
        if redist:
            route.setdefault("redist_advertisers", {})[redist["name"]] = {
                "protocol_id": int(redist["protocol_id"]),
                "client_id": int(redist["client_id"]),
            }
            return True
    if state.section == "paths":
        path_start = _PATH_START_RE.match(line)
        if path_start:
            state.path = _new_path(path_start)
            route["paths"].append(state.path)
            return True
        if state.path is not None and _apply_fields(line, _PATH_FIELDS, state.path):
            return True
    return False


def _handle_route_line(line: str, route: dict, state: _DetailState) -> None:
    known_via = _KNOWN_VIA_RE.match(line)
    if known_via:
        _apply_known_via(known_via, route)
        return
    if _handle_section_line(line, route, state):
        return
    if _apply_fields(line, _ROUTE_FIELDS, route):
        state.section, state.path = None, None


def parse_route_detail(output: str, entry_pattern: re.Pattern[str]) -> dict:
    """Parse ``Routing entry for`` blocks into a ``ShowRouteDetailResult`` dict.

    Raises:
        ValueError: If no route entry or no ``Known via`` line is found.
    """
    state = _DetailState()
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        entry = entry_pattern.match(line)
        if entry:
            _start_entry(entry, state)
        elif state.route is not None:
            _handle_route_line(line, state.route, state)

    if not state.routes:
        msg = "No route entries found in output"
        raise ValueError(msg)
    for key, route in state.routes.items():
        if "known_via" not in route:
            msg = f"Missing 'Known via' line for route {key}"
            raise ValueError(msg)
    return {"routes": state.routes}
