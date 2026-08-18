"""Parser for 'show ip mroute vrf all detail' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# VRF header: "VRF:default" or "VRF:FOO"
_VRF_RE = re.compile(r"^VRF:(?P<vrf>\S+)$")

# Group line: bare IP at start of line (not indented)
_GROUP_RE = re.compile(r"^(?P<group>\d+\.\d+\.\d+\.\d+)\s*$")

# Source entry: indented source line with uptime, optional RP, and flags
_SOURCE_RE = re.compile(
    r"^\s+(?P<source>\d+\.\d+\.\d+\.\d+|\*),\s+"
    r"(?P<uptime>\S+)"
    r"(?:,\s+RP\s+(?P<rp>[\d.]+))?"
    r",\s+flags:\s+(?P<flags>\S+)\s*$"
)

# Incoming interface: "Incoming interface: Ethernet32"
_INCOMING_RE = re.compile(r"^\s+Incoming interface:\s+(?P<interface>\S+)\s*$")

# RPF route line: "RPF route: [U] 192.168.98.0/27 [20/0] via 10.100.10.6"
_RPF_ROUTE_RE = re.compile(
    r"^\s+RPF route:\s+\[(?P<route_type>[UM])\]\s+"
    r"(?P<prefix>\S+)\s+\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+"
    r"via\s+(?P<next_hop>[\d.]+)\s*$"
)

# Outgoing interface list header
_OIF_HEADER_RE = re.compile(r"^\s+Outgoing interface list:\s*$")

# Interfaces not in OIL header
_NOT_IN_OIL_HEADER_RE = re.compile(r"^\s+Interfaces not in OIL:\s*$")

# Interface line in OIL or not-in-OIL (indented, name only or name: reason)
_OIF_ENTRY_RE = re.compile(r"^\s+(?P<interface>\S+)\s*$")
_NOT_IN_OIL_ENTRY_RE = re.compile(r"^\s+(?P<interface>\S+):\s+(?P<reason>.+?)\s*$")

# Upstream state lines
_UPSTREAM_JOINED_RE = re.compile(r"^\s+Upstream joined state:\s+(?P<state>\S+)\s*$")
_UPSTREAM_RPT_JOINED_RE = re.compile(
    r"^\s+Upstream RPT joined state:\s+(?P<state>\S+)\s*$"
)


class RpfRouteInfo(TypedDict):
    """Schema for RPF route information."""

    route_type: str
    prefix: str
    ad: int
    metric: int
    next_hop: str


class NotInOilEntry(TypedDict):
    """Schema for an interface not in the outgoing interface list."""

    reason: str


class SourceEntry(TypedDict):
    """Schema for a source entry within a multicast group."""

    uptime: str
    flags: str
    incoming_interface: str
    upstream_joined_state: str
    upstream_rpt_joined_state: str
    rp: NotRequired[str]
    rpf_route: NotRequired[RpfRouteInfo]
    outgoing_interfaces: NotRequired[list[str]]
    interfaces_not_in_oil: NotRequired[dict[str, NotInOilEntry]]


class GroupEntry(TypedDict):
    """Schema for a multicast group."""

    sources: dict[str, SourceEntry]


class VrfEntry(TypedDict):
    """Schema for a VRF's multicast routing table."""

    groups: dict[str, GroupEntry]


class ShowIpMrouteVrfAllDetailResult(TypedDict):
    """Schema for 'show ip mroute vrf all detail' parsed output."""

    vrfs: dict[str, VrfEntry]


def _try_parse_scalar_field(line: str, result: dict[str, object]) -> bool:
    """Try to match a single-value field line (incoming, RPF, upstream state).

    Returns True if the line was consumed.
    """
    m = _INCOMING_RE.match(line)
    if m:
        result["incoming_interface"] = m.group("interface")
        return True

    m = _RPF_ROUTE_RE.match(line)
    if m:
        result["rpf_route"] = RpfRouteInfo(
            route_type=m.group("route_type"),
            prefix=m.group("prefix"),
            ad=int(m.group("ad")),
            metric=int(m.group("metric")),
            next_hop=m.group("next_hop"),
        )
        return True

    m = _UPSTREAM_JOINED_RE.match(line)
    if m:
        result["upstream_joined_state"] = m.group("state")
        return True

    m = _UPSTREAM_RPT_JOINED_RE.match(line)
    if m:
        result["upstream_rpt_joined_state"] = m.group("state")
        return True

    return False


_LIST_NONE = 0
_LIST_OIF = 1
_LIST_NOT_OIL = 2


def _try_accumulate_list_entry(
    line: str,
    list_mode: int,
    oif_list: list[str],
    not_in_oil: dict[str, NotInOilEntry],
) -> tuple[bool, int]:
    """Try to accumulate a list entry based on the current list mode.

    Returns (consumed, new_list_mode).
    """
    if list_mode == _LIST_NOT_OIL:
        m = _NOT_IN_OIL_ENTRY_RE.match(line)
        if m:
            not_in_oil[m.group("interface")] = NotInOilEntry(reason=m.group("reason"))
            return True, list_mode
        return False, _LIST_NONE

    if list_mode == _LIST_OIF:
        m = _OIF_ENTRY_RE.match(line)
        if m:
            oif_list.append(m.group("interface"))
            return True, list_mode
        return False, _LIST_NONE

    return False, list_mode


def _parse_source_body(lines: list[str]) -> dict[str, object]:
    """Parse the body lines following a source header.

    Args:
        lines: Body lines for a single source entry.

    Returns:
        Dict of parsed fields to merge into the source entry.
    """
    result: dict[str, object] = {}
    list_mode = _LIST_NONE
    oif_list: list[str] = []
    not_in_oil: dict[str, NotInOilEntry] = {}

    for line in lines:
        # Try scalar fields first; they also end any list context
        if _try_parse_scalar_field(line, result):
            list_mode = _LIST_NONE
            continue

        # Section headers toggle list-accumulation mode
        if _OIF_HEADER_RE.match(line):
            list_mode = _LIST_OIF
            continue
        if _NOT_IN_OIL_HEADER_RE.match(line):
            list_mode = _LIST_NOT_OIL
            continue

        # Accumulate list entries
        consumed, list_mode = _try_accumulate_list_entry(
            line, list_mode, oif_list, not_in_oil
        )
        if consumed:
            continue

    if oif_list:
        result["outgoing_interfaces"] = oif_list
    if not_in_oil:
        result["interfaces_not_in_oil"] = not_in_oil

    return result


def _build_source_entry(header: re.Match[str], body_lines: list[str]) -> SourceEntry:
    """Build a SourceEntry from the header match and body lines."""
    entry: dict[str, object] = {
        "uptime": header.group("uptime"),
        "flags": header.group("flags"),
    }

    rp = header.group("rp")
    if rp:
        entry["rp"] = rp

    body = _parse_source_body(body_lines)
    entry.update(body)

    return cast(SourceEntry, entry)


def _process_line(
    line: str,
    state: dict[str, object],
) -> None:
    """Process a single line, updating parser state.

    State keys: vrf, group, source_match, body, groups, vrfs.
    """
    # VRF header
    m = _VRF_RE.match(line)
    if m:
        _flush_vrf(state)
        state["vrf"] = m.group("vrf")
        state["group"] = None
        return

    # Group line
    m = _GROUP_RE.match(line)
    if m:
        _flush_source(state)
        state["group"] = m.group("group")
        return

    # Source header
    m = _SOURCE_RE.match(line)
    if m:
        _flush_source(state)
        state["source_match"] = m
        state["body"] = []
        return

    # Accumulate body lines for current source
    if state["source_match"] is not None:
        cast(list[str], state["body"]).append(line)


def _flush_source(state: dict[str, object]) -> None:
    """Flush the current source entry into the groups dict."""
    source_match = state["source_match"]
    group_raw = state["group"]
    if source_match is not None and group_raw is not None:
        group = cast(str, group_raw)
        groups = cast(dict[str, GroupEntry], state["groups"])
        source_key = cast(re.Match[str], source_match).group("source")
        entry = _build_source_entry(
            cast(re.Match[str], source_match),
            cast(list[str], state["body"]),
        )
        if group not in groups:
            groups[group] = GroupEntry(sources={})
        groups[group]["sources"][source_key] = entry
    state["source_match"] = None
    state["body"] = []


def _flush_vrf(state: dict[str, object]) -> None:
    """Flush the current VRF's groups into the vrfs dict."""
    _flush_source(state)
    vrf = state["vrf"]
    groups = cast(dict[str, GroupEntry], state["groups"])
    if vrf is not None and groups:
        cast(dict[str, VrfEntry], state["vrfs"])[cast(str, vrf)] = VrfEntry(
            groups=groups
        )
    state["groups"] = {}


@register(OS.ARISTA_EOS, "show ip mroute vrf all detail")
class ShowIpMrouteVrfAllDetailParser(
    BaseParser[ShowIpMrouteVrfAllDetailResult],
):
    """Parser for 'show ip mroute vrf all detail' on Arista EOS.

    Parses PIM multicast routing table entries across all VRFs with
    detailed source/group information including RPF routes, outgoing
    interface lists, and upstream state.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MULTICAST,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpMrouteVrfAllDetailResult:
        """Parse 'show ip mroute vrf all detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed multicast route entries nested by VRF, group, source.

        Raises:
            ValueError: If no VRF sections found in output.
        """
        state: dict[str, object] = {
            "vrfs": {},
            "groups": {},
            "vrf": None,
            "group": None,
            "source_match": None,
            "body": [],
        }

        for line in output.splitlines():
            _process_line(line, state)

        _flush_vrf(state)

        vrfs = cast(dict[str, VrfEntry], state["vrfs"])
        if not vrfs:
            msg = "No VRF sections found in output"
            raise ValueError(msg)

        return ShowIpMrouteVrfAllDetailResult(vrfs=vrfs)
