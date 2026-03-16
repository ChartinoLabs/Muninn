"""Parser for 'show bgp vrf all all nexthop-database' command on NX-OS."""

from __future__ import annotations

import re
from typing import Any, ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# ---------------------------------------------------------------------------
# TypedDict schemas
# ---------------------------------------------------------------------------


class AttachedNexthopEntry(TypedDict):
    """Schema for an attached next-hop entry."""

    interface: str


class NextHopEntry(TypedDict):
    """Schema for a single next-hop entry."""

    refcount: int
    igp_cost: int
    igp_route_type: int
    igp_preference: int
    attached: bool
    local: bool
    reachable: bool
    labeled: bool
    filtered: bool
    pending_update: bool
    resolve_time: str
    rib_route: str
    metric_next_advertise: str
    rnh_epoch: int
    attached_nexthops: NotRequired[dict[str, AttachedNexthopEntry]]


class AddressFamilyEntry(TypedDict):
    """Schema for an address family within a VRF."""

    trigger_delay_critical: int
    trigger_delay_non_critical: int
    next_hops: NotRequired[dict[str, NextHopEntry]]


class ShowBgpVrfAllAllNexthopDatabaseResult(TypedDict):
    """Schema for 'show bgp vrf all all nexthop-database' parsed output."""

    vrfs: dict[str, dict[str, AddressFamilyEntry]]


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_VRF_AF_HEADER_RE = re.compile(
    r"^Next Hop table for VRF (\S+), address family (.+?):\s*$"
)
_TRIGGER_DELAY_RE = re.compile(r"^\s*Critical:\s*(\d+)\s+Non-critical:\s*(\d+)\s*$")
_NEXTHOP_RE = re.compile(
    r"^Nexthop:\s+(\S+),\s+Refcount:\s+(\d+),\s+IGP cost:\s+(\d+)\s*$"
)
_IGP_ROUTE_RE = re.compile(r"^IGP Route type:\s+(\d+),\s+IGP preference:\s+(\d+)\s*$")
_NEXTHOP_FLAGS_RE = re.compile(r"^Nexthop is\s+(.+?)\s*$")
_RESOLVE_TIME_RE = re.compile(r"^Nexthop last resolved:\s+(\S+),\s+using\s+(\S+)\s*$")
_METRIC_NEXT_RE = re.compile(r"^Metric next advertise:\s+(.+?)\s*$")
_RNH_EPOCH_RE = re.compile(r"^RNH epoch:\s+(\d+)\s*$")
_ATTACHED_NEXTHOP_RE = re.compile(
    r"^Attached nexthop:\s+(\S+),\s+Interface:\s+(\S+)\s*$"
)

# Flag token mapping
_FLAG_POSITIVE: dict[str, str] = {
    "attached": "attached",
    "local": "local",
    "reachable": "reachable",
    "labeled": "labeled",
    "filtered": "filtered",
    "pending-update": "pending_update",
}

_FLAG_NEGATIVE: dict[str, str] = {
    "not-attached": "attached",
    "not-local": "local",
    "unreachable": "reachable",
    "not-labeled": "labeled",
    "not-filtered": "filtered",
    "not-pending-update": "pending_update",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _parse_flags(flags_str: str) -> dict[str, bool]:
    """Parse the nexthop flags string into boolean fields."""
    flags: dict[str, bool] = {
        "attached": False,
        "local": False,
        "reachable": False,
        "labeled": False,
        "filtered": False,
        "pending_update": False,
    }
    tokens = flags_str.split()
    for token in tokens:
        if token in _FLAG_POSITIVE:
            flags[_FLAG_POSITIVE[token]] = True
        elif token in _FLAG_NEGATIVE:
            flags[_FLAG_NEGATIVE[token]] = False
    return flags


def _finalize_nexthop(nh_entry: dict[str, Any]) -> NextHopEntry:
    """Build a NextHopEntry from collected fields, applying defaults."""
    result: NextHopEntry = {
        "refcount": int(nh_entry.get("refcount", 0)),
        "igp_cost": int(nh_entry.get("igp_cost", 0)),
        "igp_route_type": int(nh_entry.get("igp_route_type", 0)),
        "igp_preference": int(nh_entry.get("igp_preference", 0)),
        "attached": bool(nh_entry.get("attached", False)),
        "local": bool(nh_entry.get("local", False)),
        "reachable": bool(nh_entry.get("reachable", False)),
        "labeled": bool(nh_entry.get("labeled", False)),
        "filtered": bool(nh_entry.get("filtered", False)),
        "pending_update": bool(nh_entry.get("pending_update", False)),
        "resolve_time": str(nh_entry.get("resolve_time", "")),
        "rib_route": str(nh_entry.get("rib_route", "")),
        "metric_next_advertise": str(nh_entry.get("metric_next_advertise", "")),
        "rnh_epoch": int(nh_entry.get("rnh_epoch", 0)),
    }
    if "attached_nexthops" in nh_entry:
        result["attached_nexthops"] = nh_entry["attached_nexthops"]
    return result


def _flush_nexthop(
    current_nh_addr: str | None,
    current_nh: dict[str, Any],
    next_hops: dict[str, NextHopEntry],
) -> None:
    """Flush the current next-hop entry into the next_hops dict."""
    if current_nh_addr is not None:
        next_hops[current_nh_addr] = _finalize_nexthop(current_nh)


def _flush_af(
    current_vrf: str | None,
    current_af_name: str | None,
    current_af: AddressFamilyEntry | None,
    next_hops: dict[str, NextHopEntry],
    vrfs: dict[str, dict[str, AddressFamilyEntry]],
) -> None:
    """Flush the current address family entry into the vrfs dict."""
    if (
        current_vrf is not None
        and current_af_name is not None
        and current_af is not None
    ):
        if next_hops:
            current_af["next_hops"] = dict(next_hops)
        vrfs.setdefault(current_vrf, {})[current_af_name] = current_af


def _parse_nexthop_line(
    stripped: str,
    current_nh: dict[str, Any],
) -> bool:
    """Try to parse a next-hop detail line. Returns True if consumed."""
    if m := _IGP_ROUTE_RE.match(stripped):
        current_nh["igp_route_type"] = int(m.group(1))
        current_nh["igp_preference"] = int(m.group(2))
        return True

    if m := _NEXTHOP_FLAGS_RE.match(stripped):
        flags = _parse_flags(m.group(1))
        current_nh.update(flags)
        return True

    if m := _RESOLVE_TIME_RE.match(stripped):
        current_nh["resolve_time"] = m.group(1)
        current_nh["rib_route"] = m.group(2)
        return True

    if m := _METRIC_NEXT_RE.match(stripped):
        current_nh["metric_next_advertise"] = m.group(1).capitalize()
        return True

    if m := _RNH_EPOCH_RE.match(stripped):
        current_nh["rnh_epoch"] = int(m.group(1))
        return True

    if m := _ATTACHED_NEXTHOP_RE.match(stripped):
        attached_nhs: dict[str, AttachedNexthopEntry] = current_nh.setdefault(
            "attached_nexthops",
            {},
        )
        attached_nhs[m.group(1)] = {"interface": m.group(2)}
        return True

    return False


class _ParserState:
    """Mutable state container for the line-by-line parser."""

    __slots__ = ("vrf", "af_name", "af_entry", "next_hops", "nh_addr", "nh_fields")

    def __init__(self) -> None:
        self.vrf: str | None = None
        self.af_name: str | None = None
        self.af_entry: AddressFamilyEntry | None = None
        self.next_hops: dict[str, NextHopEntry] = {}
        self.nh_addr: str | None = None
        self.nh_fields: dict[str, Any] = {}


def _handle_vrf_af_header(
    m: re.Match[str],
    state: _ParserState,
    vrfs: dict[str, dict[str, AddressFamilyEntry]],
) -> None:
    """Handle a VRF/AF header line, flushing previous state."""
    _flush_nexthop(state.nh_addr, state.nh_fields, state.next_hops)
    state.nh_addr = None
    state.nh_fields = {}

    _flush_af(state.vrf, state.af_name, state.af_entry, state.next_hops, vrfs)

    state.vrf = m.group(1)
    state.af_name = m.group(2).lower()
    state.af_entry = {
        "trigger_delay_critical": 0,
        "trigger_delay_non_critical": 0,
    }
    state.next_hops = {}


def _process_line(
    stripped: str,
    state: _ParserState,
    vrfs: dict[str, dict[str, AddressFamilyEntry]],
) -> None:
    """Process a single non-empty line of output."""
    if m := _VRF_AF_HEADER_RE.match(stripped):
        _handle_vrf_af_header(m, state, vrfs)
        return

    if state.af_entry is not None:
        if m := _TRIGGER_DELAY_RE.match(stripped):
            state.af_entry["trigger_delay_critical"] = int(m.group(1))
            state.af_entry["trigger_delay_non_critical"] = int(m.group(2))
            return

    if m := _NEXTHOP_RE.match(stripped):
        _flush_nexthop(state.nh_addr, state.nh_fields, state.next_hops)
        state.nh_addr = m.group(1)
        state.nh_fields = {
            "refcount": int(m.group(2)),
            "igp_cost": int(m.group(3)),
        }
        return

    if state.nh_addr is not None:
        _parse_nexthop_line(stripped, state.nh_fields)


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


@register(OS.CISCO_NXOS, "show bgp vrf all all nexthop-database")
class ShowBgpVrfAllAllNexthopDatabaseParser(
    BaseParser["ShowBgpVrfAllAllNexthopDatabaseResult"],
):
    """Parser for 'show bgp vrf all all nexthop-database' on NX-OS.

    Parses the BGP next-hop database showing per-VRF, per-address-family
    next-hop entries with their resolution status, metrics, and flags.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"bgp", "routing"})

    @classmethod
    def parse(cls, output: str) -> ShowBgpVrfAllAllNexthopDatabaseResult:
        """Parse 'show bgp vrf all all nexthop-database' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed next-hop database keyed by VRF, address family, and
            next-hop address.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        vrfs: dict[str, dict[str, AddressFamilyEntry]] = {}
        state = _ParserState()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            _process_line(stripped, state, vrfs)

        # Flush final entries
        _flush_nexthop(state.nh_addr, state.nh_fields, state.next_hops)
        _flush_af(state.vrf, state.af_name, state.af_entry, state.next_hops, vrfs)

        if not vrfs:
            msg = "No VRF/address-family sections found in output"
            raise ValueError(msg)

        return {"vrfs": vrfs}
