"""Parser for 'show isis neighbors detail' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import Any, ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class AdjacencySid(TypedDict):
    """Schema for an IS-IS Adjacency SID entry."""

    level: int
    f_flag: int
    b_flag: int
    v_flag: int
    l_flag: int
    s_flag: int
    p_flag: int
    weight: int


class Srv6EndxSid(TypedDict):
    """Schema for an SRv6 End.X SID entry."""

    b_flag: int
    s_flag: int
    p_flag: int
    weight: int


class IsisAdjacencyDetail(TypedDict):
    """Schema for an IS-IS adjacency on a specific interface and type."""

    ip_address: str
    state: str
    holdtime: int
    circuit_id: str
    area_addresses: list[str]
    snpa: str
    ipv6_addresses: NotRequired[list[str]]
    ipv6_global_address: NotRequired[str]
    state_changed: str
    format: str
    remote_tid: list[int]
    local_tid: list[int]
    interface_name: str
    neighbor_circuit_id: int
    adjacency_sids: NotRequired[dict[str, AdjacencySid]]
    srv6_endx_sids: NotRequired[dict[str, Srv6EndxSid]]
    adj_sync: NotRequired[str]


class IsisInterfaceDetail(TypedDict):
    """Schema for IS-IS adjacencies on a specific interface, keyed by type."""

    adjacencies: dict[str, IsisAdjacencyDetail]


class IsisNeighborDetail(TypedDict):
    """Schema for an IS-IS neighbor, keyed by interface."""

    interfaces: dict[str, IsisInterfaceDetail]


class ShowIsisNeighborsDetailResult(TypedDict):
    """Schema for 'show isis neighbors detail' parsed output."""

    tags: dict[str, dict[str, IsisNeighborDetail]]


_TAG_PATTERN = re.compile(r"^Tag\s+(?P<tag>\S+):$")

_HEADER_PATTERN = re.compile(r"^System\s+Id\s+Type\s+Interface", re.IGNORECASE)

_NEIGHBOR_ROW_PATTERN = re.compile(
    r"^(?P<system_id>\S+)\s+"
    r"(?P<type>L[12])\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<ip_address>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<holdtime>\d+)\s+"
    r"(?P<circuit_id>\S+)\s*$"
)

_AREA_ADDR_PATTERN = re.compile(r"^\s*Area Address\(es\):\s*(?P<value>.+)$")
_SNPA_PATTERN = re.compile(r"^\s*SNPA:\s*(?P<value>\S+)")
_IPV6_ADDR_PATTERN = re.compile(r"^\s*IPv6 Address\(es\):\s*(?P<value>.+)$")
_IPV6_GLOBAL_PATTERN = re.compile(r"^\s*IPv6 Global Address:\s*(?P<value>\S+)")
_STATE_CHANGED_PATTERN = re.compile(r"^\s*State Changed:\s*(?P<value>\S+)")
_FORMAT_PATTERN = re.compile(r"^\s*Format:\s*(?P<value>.+)$")
_REMOTE_TID_PATTERN = re.compile(r"^\s*Remote TID:\s*(?P<value>.+)$")
_LOCAL_TID_PATTERN = re.compile(r"^\s*Local TID:\s*(?P<value>.+)$")
_INTERFACE_NAME_PATTERN = re.compile(r"^\s*Interface name:\s*(?P<value>\S+)")
_NEIGHBOR_CID_PATTERN = re.compile(r"^\s*Neighbor Circuit Id:\s*(?P<value>\d+)")
_ADJ_SID_PATTERN = re.compile(
    r"^\s*L\((?P<level>\d)\)\s+Adjacency SID Value:"
    r"(?P<value>\d+)\s+"
    r"f:(?P<f>\d+)\s+"
    r"b:(?P<b>\d+)\s+"
    r"v:(?P<v>\d+)\s+"
    r"l:(?P<l>\d+)\s+"
    r"s:(?P<s>\d+)\s+"
    r"p:(?P<p>\d+)\s+"
    r"weight:(?P<weight>\d+)"
)
_SRV6_ENDX_PATTERN = re.compile(
    r"^\s*SRv6 End\.X SID\s+(?P<sid>\S+)\s+"
    r"b:(?P<b>\d+)\s+"
    r"s:(?P<s>\d+)\s+"
    r"p:(?P<p>\d+)\s+"
    r"weight:(?P<weight>\d+)"
)
_ADJ_SYNC_PATTERN = re.compile(r"^\s*Adj sync:\s*(?P<value>\S+)")


def _parse_tid_list(raw: str) -> list[int]:
    """Parse a comma-separated TID list into a list of integers."""
    return [int(v.strip()) for v in raw.split(",") if v.strip()]


def _build_adj_sid(match: re.Match[str]) -> tuple[str, AdjacencySid]:
    """Build an Adjacency SID entry from a regex match, keyed by value."""
    return (
        match.group("value"),
        AdjacencySid(
            level=int(match.group("level")),
            f_flag=int(match.group("f")),
            b_flag=int(match.group("b")),
            v_flag=int(match.group("v")),
            l_flag=int(match.group("l")),
            s_flag=int(match.group("s")),
            p_flag=int(match.group("p")),
            weight=int(match.group("weight")),
        ),
    )


def _build_srv6_endx(match: re.Match[str]) -> tuple[str, Srv6EndxSid]:
    """Build an SRv6 End.X SID entry from a regex match, keyed by SID."""
    return (
        match.group("sid"),
        Srv6EndxSid(
            b_flag=int(match.group("b")),
            s_flag=int(match.group("s")),
            p_flag=int(match.group("p")),
            weight=int(match.group("weight")),
        ),
    )


def _handle_area_addr(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["area_addresses"] = [
        a.strip() for a in m.group("value").split(",") if a.strip()
    ]


def _handle_snpa(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["snpa"] = m.group("value")


def _handle_ipv6_addr(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    addrs: list[str] = details.get("ipv6_addresses", [])
    addrs.append(m.group("value").strip())
    details["ipv6_addresses"] = addrs


def _handle_ipv6_global(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["ipv6_global_address"] = m.group("value")


def _handle_state_changed(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["state_changed"] = m.group("value")


def _handle_format(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["format"] = m.group("value").strip()


def _handle_remote_tid(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["remote_tid"] = _parse_tid_list(m.group("value"))


def _handle_local_tid(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["local_tid"] = _parse_tid_list(m.group("value"))


def _handle_interface_name(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["interface_name"] = canonical_interface_name(
        m.group("value"), os=OS.CISCO_IOSXE
    )


def _handle_neighbor_cid(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["neighbor_circuit_id"] = int(m.group("value"))


def _handle_adj_sid(
    m: re.Match[str],
    _d: dict[str, Any],
    adj_sids: dict[str, Any],
    _s: dict[str, Any],
) -> None:
    key, sid = _build_adj_sid(m)
    adj_sids[key] = sid


def _handle_srv6_endx(
    m: re.Match[str],
    _d: dict[str, Any],
    _a: dict[str, Any],
    srv6_sids: dict[str, Any],
) -> None:
    key, sid = _build_srv6_endx(m)
    srv6_sids[key] = sid


def _handle_adj_sync(
    m: re.Match[str], details: dict[str, Any], _a: dict[str, Any], _s: dict[str, Any]
) -> None:
    details["adj_sync"] = m.group("value")


_DetailHandler = Callable[
    [re.Match[str], dict[str, Any], dict[str, Any], dict[str, Any]], None
]

_DETAIL_DISPATCH: list[tuple[re.Pattern[str], _DetailHandler]] = [
    (_AREA_ADDR_PATTERN, _handle_area_addr),
    (_SNPA_PATTERN, _handle_snpa),
    (_IPV6_ADDR_PATTERN, _handle_ipv6_addr),
    (_IPV6_GLOBAL_PATTERN, _handle_ipv6_global),
    (_STATE_CHANGED_PATTERN, _handle_state_changed),
    (_FORMAT_PATTERN, _handle_format),
    (_REMOTE_TID_PATTERN, _handle_remote_tid),
    (_LOCAL_TID_PATTERN, _handle_local_tid),
    (_INTERFACE_NAME_PATTERN, _handle_interface_name),
    (_NEIGHBOR_CID_PATTERN, _handle_neighbor_cid),
    (_ADJ_SID_PATTERN, _handle_adj_sid),
    (_SRV6_ENDX_PATTERN, _handle_srv6_endx),
    (_ADJ_SYNC_PATTERN, _handle_adj_sync),
]


def _parse_detail_lines(
    lines: list[str],
    start_idx: int,
) -> tuple[dict[str, Any], int]:
    """Parse indented detail lines following a neighbor summary row.

    Returns:
        Tuple of (detail_fields dict, index of next non-detail line).
    """
    details: dict[str, Any] = {}
    adj_sids: dict[str, AdjacencySid] = {}
    srv6_sids: dict[str, Srv6EndxSid] = {}
    idx = start_idx

    while idx < len(lines):
        line = lines[idx]
        if line and not line[0].isspace():
            break

        if not line.strip():
            idx += 1
            continue

        _try_dispatch(line, details, adj_sids, srv6_sids)
        idx += 1

    if adj_sids:
        details["adjacency_sids"] = adj_sids
    if srv6_sids:
        details["srv6_endx_sids"] = srv6_sids

    return details, idx


def _try_dispatch(
    line: str,
    details: dict[str, Any],
    adj_sids: dict[str, AdjacencySid],
    srv6_sids: dict[str, Srv6EndxSid],
) -> None:
    """Try each detail pattern and dispatch to its handler."""
    for pattern, handler in _DETAIL_DISPATCH:
        m = pattern.match(line)
        if m:
            handler(m, details, adj_sids, srv6_sids)
            return


def _build_adjacency_detail(
    neighbor_match: re.Match[str],
    details: dict[str, Any],
) -> IsisAdjacencyDetail:
    """Assemble an IsisAdjacencyDetail from summary match and parsed details."""
    entry = IsisAdjacencyDetail(
        ip_address=neighbor_match.group("ip_address"),
        state=neighbor_match.group("state"),
        holdtime=int(neighbor_match.group("holdtime")),
        circuit_id=neighbor_match.group("circuit_id"),
        area_addresses=details.get("area_addresses", []),
        snpa=details.get("snpa", ""),
        state_changed=details.get("state_changed", ""),
        format=details.get("format", ""),
        remote_tid=details.get("remote_tid", []),
        local_tid=details.get("local_tid", []),
        interface_name=details.get("interface_name", ""),
        neighbor_circuit_id=details.get("neighbor_circuit_id", 0),
    )

    if "ipv6_addresses" in details:
        entry["ipv6_addresses"] = details["ipv6_addresses"]
    if "ipv6_global_address" in details:
        entry["ipv6_global_address"] = details["ipv6_global_address"]
    if "adjacency_sids" in details:
        entry["adjacency_sids"] = details["adjacency_sids"]
    if "srv6_endx_sids" in details:
        entry["srv6_endx_sids"] = details["srv6_endx_sids"]
    if "adj_sync" in details:
        entry["adj_sync"] = details["adj_sync"]

    return entry


def _insert_adjacency(
    tags: dict[str, dict[str, IsisNeighborDetail]],
    current_tag: str,
    system_id: str,
    interface: str,
    adj_type: str,
    adjacency: IsisAdjacencyDetail,
) -> None:
    """Insert an adjacency detail into the nested tag/neighbor/interface/type tree."""
    neighbors = tags[current_tag]
    if system_id not in neighbors:
        neighbors[system_id] = IsisNeighborDetail(interfaces={})

    interfaces = neighbors[system_id]["interfaces"]
    if interface not in interfaces:
        interfaces[interface] = IsisInterfaceDetail(adjacencies={})

    interfaces[interface]["adjacencies"][adj_type] = adjacency


def _process_lines(lines: list[str]) -> dict[str, dict[str, IsisNeighborDetail]]:
    """Walk all lines, returning tag-keyed nested neighbor structures."""
    tags: dict[str, dict[str, IsisNeighborDetail]] = {}
    current_tag: str | None = None
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if not stripped or _HEADER_PATTERN.match(stripped):
            idx += 1
            continue

        tag_match = _TAG_PATTERN.match(stripped)
        if tag_match:
            current_tag = tag_match.group("tag")
            if current_tag not in tags:
                tags[current_tag] = {}
            idx += 1
            continue

        neighbor_match = _NEIGHBOR_ROW_PATTERN.match(stripped)
        if neighbor_match and current_tag is not None:
            interface = canonical_interface_name(
                neighbor_match.group("interface"), os=OS.CISCO_IOSXE
            )
            details, idx = _parse_detail_lines(lines, idx + 1)
            adjacency = _build_adjacency_detail(neighbor_match, details)
            _insert_adjacency(
                tags,
                current_tag,
                neighbor_match.group("system_id"),
                interface,
                neighbor_match.group("type"),
                adjacency,
            )
            continue

        idx += 1

    return tags


@register(OS.CISCO_IOSXE, "show isis neighbors detail")
class ShowIsisNeighborsDetailParser(
    BaseParser["ShowIsisNeighborsDetailResult"],
):
    """Parser for 'show isis neighbors detail' on IOS-XE.

    Example output::

        Tag 64512:
        System Id       Type Interface     IP Address      State Holdtime Circuit Id
        ROUTER-A        L2   Te0/0/0.10   198.51.100.1    UP    29       00
          Area Address(es): 49.0001
          SNPA: aabb.cc00.0100
          IPv6 Address(es): FE80::1:1
          State Changed: 5w0d
          ...
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.ISIS, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIsisNeighborsDetailResult:
        """Parse 'show isis neighbors detail' output.

        Args:
            output: Raw CLI output from 'show isis neighbors detail'.

        Returns:
            Parsed IS-IS neighbor detail data grouped by tag instance,
            then system ID, interface, and adjacency type.

        Raises:
            ValueError: If no IS-IS neighbor entries are found.
        """
        lines = output.splitlines()
        tags = _process_lines(lines)

        result_tags = {k: v for k, v in tags.items() if v}
        if not result_tags:
            msg = "No IS-IS neighbor detail entries found in output"
            raise ValueError(msg)

        return ShowIsisNeighborsDetailResult(tags=result_tags)
