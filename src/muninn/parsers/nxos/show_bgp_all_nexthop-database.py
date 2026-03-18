"""Parser for 'show bgp all nexthop-database' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class AttachedNexthopEntry(TypedDict):
    """Schema for an attached nexthop entry."""

    interface: str


class NexthopEntry(TypedDict):
    """Schema for a single nexthop entry in the database."""

    flags: str
    refcount: int
    igp_cost: int
    igp_route_type: int
    igp_preference: int
    attached: bool
    local: bool
    reachable: bool
    labeled: bool
    resolve_time: str
    rib_route: str
    metric_next_advertise: str
    rnh_epoch: int
    attached_nexthops: NotRequired[dict[str, AttachedNexthopEntry]]


class AddressFamilyEntry(TypedDict):
    """Schema for an address family nexthop database."""

    trigger_delay_critical_ms: int
    trigger_delay_non_critical_ms: int
    nexthops: NotRequired[dict[str, NexthopEntry]]


class VrfEntry(TypedDict):
    """Schema for a VRF in the nexthop database."""

    address_families: dict[str, AddressFamilyEntry]


class ShowBgpAllNexthopDatabaseResult(TypedDict):
    """Schema for 'show bgp all nexthop-database' parsed output on NX-OS."""

    vrfs: dict[str, VrfEntry]


# --- Compiled regex patterns ---

_VRF_AF_HEADER_RE = re.compile(
    r"^Next Hop table for VRF (?P<vrf>\S+),\s+"
    r"address family (?P<af>.+):\s*$"
)

_TRIGGER_DELAY_RE = re.compile(
    r"^Critical:\s+(?P<critical>\d+)\s+"
    r"Non-critical:\s+(?P<non_critical>\d+)"
)

_NEXTHOP_RE = re.compile(
    r"^Nexthop:\s+(?P<nexthop>\S+),\s+"
    r"Flags:\s+(?P<flags>\S+),\s+"
    r"Refcount:\s+(?P<refcount>\d+),\s+"
    r"IGP cost:\s+(?P<igp_cost>-?\d+)"
)

_IGP_ROUTE_RE = re.compile(
    r"^IGP Route type:\s+(?P<route_type>\d+),\s+"
    r"IGP preference:\s+(?P<preference>\d+)"
)

_ATTACHED_NEXTHOP_RE = re.compile(
    r"^Attached nexthop:\s+(?P<addr>\S+),\s+"
    r"Interface:\s+(?P<intf>\S+)"
)

_NEXTHOP_FLAGS_RE = re.compile(r"^Nexthop is\s+(?P<flags>.+)$")

_RESOLVE_TIME_RE = re.compile(
    r"^Nexthop last resolved:\s+(?P<time>\S+),\s+"
    r"using\s+(?P<route>\S+)"
)

_METRIC_ADVERTISE_RE = re.compile(r"^Metric next advertise:\s+(?P<value>.+)$")

_RNH_EPOCH_RE = re.compile(r"^RNH epoch:\s+(?P<epoch>\d+)")


def _parse_nexthop_flags(flags_str: str) -> dict[str, bool]:
    """Parse the nexthop status flags string into boolean fields."""
    tokens = flags_str.strip().split()
    attached = False
    local = False
    reachable = False
    labeled = False

    for token in tokens:
        token_lower = token.lower()
        if token_lower == "attached":  # nosec B105
            attached = True
        elif token_lower == "not-attached":  # nosec B105
            attached = False
        elif token_lower == "local":  # nosec B105
            local = True
        elif token_lower == "not-local":  # nosec B105
            local = False
        elif token_lower == "reachable":  # nosec B105
            reachable = True
        elif token_lower == "unreachable":  # nosec B105
            reachable = False
        elif token_lower == "labeled":  # nosec B105
            labeled = True
        elif token_lower == "not-labeled":  # nosec B105
            labeled = False

    return {
        "attached": attached,
        "local": local,
        "reachable": reachable,
        "labeled": labeled,
    }


def _try_match_nexthop_detail(line: str, entry: NexthopEntry) -> bool:
    """Try to match nexthop detail lines. Return True if matched."""
    m = _IGP_ROUTE_RE.match(line)
    if m:
        entry["igp_route_type"] = int(m.group("route_type"))
        entry["igp_preference"] = int(m.group("preference"))
        return True

    m = _ATTACHED_NEXTHOP_RE.match(line)
    if m:
        attached_addr = m.group("addr")
        intf = canonical_interface_name(m.group("intf"), os=OS.CISCO_NXOS)
        attached_nexthops = entry.get("attached_nexthops", {}).copy()
        attached_nexthops[attached_addr] = AttachedNexthopEntry(interface=intf)
        entry["attached_nexthops"] = attached_nexthops
        return True

    m = _NEXTHOP_FLAGS_RE.match(line)
    if m:
        flags = _parse_nexthop_flags(m.group("flags"))
        entry["attached"] = flags["attached"]
        entry["local"] = flags["local"]
        entry["reachable"] = flags["reachable"]
        entry["labeled"] = flags["labeled"]
        return True

    m = _RESOLVE_TIME_RE.match(line)
    if m:
        entry["resolve_time"] = m.group("time")
        entry["rib_route"] = m.group("route")
        return True

    m = _METRIC_ADVERTISE_RE.match(line)
    if m:
        entry["metric_next_advertise"] = m.group("value").strip().lower()
        return True

    m = _RNH_EPOCH_RE.match(line)
    if m:
        entry["rnh_epoch"] = int(m.group("epoch"))
        return True

    return False


def _build_nexthop_entry(m: re.Match[str]) -> NexthopEntry:
    """Build an initial NexthopEntry from a parsed nexthop header match."""
    return {
        "flags": m.group("flags"),
        "refcount": int(m.group("refcount")),
        "igp_cost": int(m.group("igp_cost")),
        "igp_route_type": 0,
        "igp_preference": 0,
        "attached": False,
        "local": False,
        "reachable": False,
        "labeled": False,
        "resolve_time": "",
        "rib_route": "",
        "metric_next_advertise": "",
        "rnh_epoch": 0,
    }


def _parse_output(output: str) -> ShowBgpAllNexthopDatabaseResult:
    """Parse the full command output into structured data."""
    vrfs: dict[str, VrfEntry] = {}

    current_vrf: str | None = None
    current_af: str | None = None
    current_af_entry: AddressFamilyEntry | None = None
    current_nexthop: NexthopEntry | None = None
    current_nexthop_addr: str | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Match VRF/AF header
        m = _VRF_AF_HEADER_RE.match(line)
        if m:
            _flush_nexthop(current_af_entry, current_nexthop_addr, current_nexthop)
            _flush_af(vrfs, current_vrf, current_af, current_af_entry)
            current_vrf = m.group("vrf")
            current_af = m.group("af").lower()
            current_af_entry = {
                "trigger_delay_critical_ms": 0,
                "trigger_delay_non_critical_ms": 0,
            }
            current_nexthop = None
            current_nexthop_addr = None
            continue

        if current_af_entry is None:
            continue

        # Match trigger delay
        m = _TRIGGER_DELAY_RE.match(line)
        if m:
            current_af_entry["trigger_delay_critical_ms"] = int(m.group("critical"))
            current_af_entry["trigger_delay_non_critical_ms"] = int(
                m.group("non_critical")
            )
            continue

        # Match nexthop header
        m = _NEXTHOP_RE.match(line)
        if m:
            _flush_nexthop(current_af_entry, current_nexthop_addr, current_nexthop)
            current_nexthop_addr = m.group("nexthop")
            current_nexthop = _build_nexthop_entry(m)
            continue

        if current_nexthop is not None:
            _try_match_nexthop_detail(line, current_nexthop)

    # Flush final state
    _flush_nexthop(current_af_entry, current_nexthop_addr, current_nexthop)
    _flush_af(vrfs, current_vrf, current_af, current_af_entry)

    return {"vrfs": vrfs}


def _flush_nexthop(
    af_entry: AddressFamilyEntry | None,
    nexthop_addr: str | None,
    nexthop: NexthopEntry | None,
) -> None:
    """Flush a completed nexthop entry into its address family."""
    if af_entry is None or nexthop_addr is None or nexthop is None:
        return
    nexthops = af_entry.get("nexthops", {})
    nexthops[nexthop_addr] = nexthop
    af_entry["nexthops"] = nexthops


def _flush_af(
    vrfs: dict[str, VrfEntry],
    vrf: str | None,
    af: str | None,
    af_entry: AddressFamilyEntry | None,
) -> None:
    """Flush a completed address family entry into its VRF."""
    if vrf is None or af is None or af_entry is None:
        return
    if vrf not in vrfs:
        vrfs[vrf] = {"address_families": {}}
    vrfs[vrf]["address_families"][af] = af_entry


@register(OS.CISCO_NXOS, "show bgp all nexthop-database")
class ShowBgpAllNexthopDatabaseParser(
    BaseParser["ShowBgpAllNexthopDatabaseResult"],
):
    """Parser for 'show bgp all nexthop-database' on NX-OS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpAllNexthopDatabaseResult:
        """Parse 'show bgp all nexthop-database' output."""
        return _parse_output(output)
