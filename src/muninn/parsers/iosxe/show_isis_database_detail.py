"""Parser for 'show isis database detail' command on Cisco IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisIsNeighborEntry(TypedDict):
    """Schema for an IS-IS IS-Extended or IS (MT-IPv6) neighbor."""

    neighbor_id: str
    metric: int
    mt: NotRequired[str]


class IsisIpReachabilityEntry(TypedDict):
    """Schema for an IP reachability (prefix) entry."""

    prefix: str
    metric: int


class IsisIpv6ReachabilityEntry(TypedDict):
    """Schema for an IPv6 reachability (prefix) entry."""

    prefix: str
    metric: int
    mt: NotRequired[str]


class IsisLspEntry(TypedDict):
    """Schema for a single IS-IS LSP entry."""

    sequence_number: str
    checksum: str
    holdtime: int
    holdtime_received: NotRequired[int]
    att: int
    p_bit: int
    ol: int
    is_local: NotRequired[bool]
    area_address: NotRequired[str]
    nlpid: NotRequired[list[str]]
    topologies: NotRequired[list[str]]
    router_id: NotRequired[str]
    ip_address: NotRequired[str]
    ipv6_address: NotRequired[str]
    ipv6_router_id: NotRequired[str]
    hostname: NotRequired[str]
    is_neighbors: NotRequired[list[IsisIsNeighborEntry]]
    ip_reachability: NotRequired[list[IsisIpReachabilityEntry]]
    ipv6_reachability: NotRequired[list[IsisIpv6ReachabilityEntry]]


class ShowIsisDatabaseDetailResult(TypedDict):
    """Schema for 'show isis database detail' parsed output.

    Top-level keys: tag (IS-IS instance tag) and levels containing LSP entries.
    """

    tag: str
    levels: dict[str, dict[str, IsisLspEntry]]


# "Tag 64512:" at start of output
_TAG_PATTERN = re.compile(r"^Tag\s+(?P<tag>\S+):\s*$")

# "IS-IS Level-1 Link State Database:" or "IS-IS Level-2 Link State Database:"
_LEVEL_HEADER_PATTERN = re.compile(
    r"^IS-IS\s+(?P<level>Level-[12])\s+Link\s+State\s+Database:\s*$"
)

# Column header line (skip it)
_COLUMN_HEADER_PATTERN = re.compile(r"^LSPID\s+LSP\s+Seq\s+Num")

# LSP entry on single line:
# ROUTER-B.00-00    0x00009F02   0xE364     643/1200      0/0/0
_LSP_SINGLE_PATTERN = re.compile(
    r"^(?P<lsp_id>\S+\.\d+-\d+)\s+"
    r"(?P<local>\*)?\s*"
    r"(?P<seq>0x[0-9a-fA-F]+)\s+"
    r"(?P<checksum>0x[0-9a-fA-F]+)\s+"
    r"(?P<holdtime>\d+)/(?P<rcvd>\d+|\*)\s+"
    r"(?P<att>\d)/(?P<p>\d)/(?P<ol>\d)\s*$"
)

# LSP entry with line continuation (backslash):
# ROUTER-A.00-00 \
_LSP_CONT_START_PATTERN = re.compile(r"^(?P<lsp_id>\S+\.\d+-\d+)\s+\\$")

# Continuation line with remaining fields:
#                     * 0x00009EE4   0xA64A      1100/*         0/0/1
_LSP_CONT_DATA_PATTERN = re.compile(
    r"^\s+(?P<local>\*)?\s*"
    r"(?P<seq>0x[0-9a-fA-F]+)\s+"
    r"(?P<checksum>0x[0-9a-fA-F]+)\s+"
    r"(?P<holdtime>\d+)/(?P<rcvd>\d+|\*)\s+"
    r"(?P<att>\d)/(?P<p>\d)/(?P<ol>\d)\s*$"
)

# TLV patterns
_AREA_ADDRESS = re.compile(r"^\s+Area Address:\s+(?P<area>\S+)\s*$")
_NLPID = re.compile(r"^\s+NLPID:\s+(?P<nlpid>.+?)\s*$")
_TOPOLOGY = re.compile(r"^\s+Topology:\s+(?P<topo>.+?)\s*$")
_TOPOLOGY_CONT = re.compile(r"^\s+(?P<topo>IPv[46]\s+\(0x[0-9a-fA-F]+\))\s*$")
_ROUTER_ID = re.compile(r"^\s+Router ID:\s+(?P<id>\S+)\s*$")
_IP_ADDRESS = re.compile(r"^\s+IP Address:\s+(?P<ip>\S+)\s*$")
_IPV6_ADDRESS = re.compile(r"^\s+IPv6 Address:\s+(?P<ip>\S+)\s*$")
_IPV6_ROUTER_ID = re.compile(r"^\s+IPv6 Router ID:\s+(?P<id>\S+)\s*$")
_HOSTNAME = re.compile(r"^\s+Hostname:\s+(?P<hostname>\S+)\s*$")

# Metric lines for IS neighbors:
# "  Metric: 100        IS-Extended ROUTER-C.00"
# "  Metric: 10         IS (MT-IPv6) ROUTER-C.00"
_METRIC_IS = re.compile(
    r"^\s+Metric:\s+(?P<metric>\d+)\s+"
    r"(?:IS-Extended|IS\s+\((?P<mt>[^)]+)\))\s+"
    r"(?P<neighbor>\S+)\s*$"
)

# Metric lines for IP reachability:
# "  Metric: 100        IP 10.1.5.16/30"
_METRIC_IP = re.compile(r"^\s+Metric:\s+(?P<metric>\d+)\s+IP\s+(?P<prefix>\S+)\s*$")

# Metric lines for IPv6 reachability:
# "  Metric: 10         IPv6 (MT-IPv6) 2001:DB8::53/128"
_METRIC_IPV6 = re.compile(
    r"^\s+Metric:\s+(?P<metric>\d+)\s+"
    r"IPv6\s+(?:\((?P<mt>[^)]+)\)\s+)?(?P<prefix>\S+)\s*$"
)


def _build_lsp_entry(
    seq: str,
    checksum: str,
    holdtime: str,
    rcvd: str,
    att: str,
    p: str,
    ol: str,
    local: str | None,
) -> IsisLspEntry:
    """Construct an LSP entry from parsed fields."""
    lsp: IsisLspEntry = {
        "sequence_number": seq,
        "checksum": checksum,
        "holdtime": int(holdtime),
        "att": int(att),
        "p_bit": int(p),
        "ol": int(ol),
    }
    if rcvd and rcvd != "*":
        lsp["holdtime_received"] = int(rcvd)
    if local:
        lsp["is_local"] = True
    return lsp


def _parse_identity_tlv(line: str, lsp: IsisLspEntry) -> bool:
    """Try to parse identity-related TLV fields. Returns True if matched."""
    area_match = _AREA_ADDRESS.match(line)
    if area_match:
        lsp["area_address"] = area_match.group("area")
        return True

    rid_match = _ROUTER_ID.match(line)
    if rid_match:
        lsp["router_id"] = rid_match.group("id")
        return True

    ip_match = _IP_ADDRESS.match(line)
    if ip_match:
        lsp["ip_address"] = ip_match.group("ip")
        return True

    ipv6_match = _IPV6_ADDRESS.match(line)
    if ipv6_match:
        lsp["ipv6_address"] = ipv6_match.group("ip")
        return True

    ipv6_rid_match = _IPV6_ROUTER_ID.match(line)
    if ipv6_rid_match:
        lsp["ipv6_router_id"] = ipv6_rid_match.group("id")
        return True

    hostname_match = _HOSTNAME.match(line)
    if hostname_match:
        lsp["hostname"] = hostname_match.group("hostname")
        return True

    return False


def _parse_capability_tlv(line: str, lsp: IsisLspEntry) -> bool:
    """Try to parse capability TLV fields (NLPID). Returns True if matched."""
    nlpid_match = _NLPID.match(line)
    if nlpid_match:
        raw = nlpid_match.group("nlpid")
        lsp["nlpid"] = [tok.strip() for tok in raw.split() if tok.strip()]
        return True

    return False


def _parse_metric_tlv(line: str, lsp: IsisLspEntry) -> bool:
    """Try to parse metric-based TLV fields. Returns True if matched."""
    is_match = _METRIC_IS.match(line)
    if is_match:
        if "is_neighbors" not in lsp:
            lsp["is_neighbors"] = []
        entry: IsisIsNeighborEntry = {
            "neighbor_id": is_match.group("neighbor"),
            "metric": int(is_match.group("metric")),
        }
        mt_value = is_match.group("mt")
        if mt_value:
            entry["mt"] = mt_value
        lsp["is_neighbors"].append(entry)
        return True

    ip_metric_match = _METRIC_IP.match(line)
    if ip_metric_match:
        if "ip_reachability" not in lsp:
            lsp["ip_reachability"] = []
        ip_entry: IsisIpReachabilityEntry = {
            "prefix": ip_metric_match.group("prefix"),
            "metric": int(ip_metric_match.group("metric")),
        }
        lsp["ip_reachability"].append(ip_entry)
        return True

    ipv6_metric_match = _METRIC_IPV6.match(line)
    if ipv6_metric_match:
        if "ipv6_reachability" not in lsp:
            lsp["ipv6_reachability"] = []
        v6_entry: IsisIpv6ReachabilityEntry = {
            "prefix": ipv6_metric_match.group("prefix"),
            "metric": int(ipv6_metric_match.group("metric")),
        }
        mt_val = ipv6_metric_match.group("mt")
        if mt_val:
            v6_entry["mt"] = mt_val
        lsp["ipv6_reachability"].append(v6_entry)
        return True

    return False


class _ParseState:
    """Mutable parsing state container."""

    __slots__ = (
        "tag",
        "levels",
        "current_level",
        "current_lsp",
        "pending_lsp_id",
        "in_topology_block",
    )

    def __init__(self) -> None:
        self.tag: str = "null"
        self.levels: dict[str, dict[str, IsisLspEntry]] = {}
        self.current_level: str | None = None
        self.current_lsp: IsisLspEntry | None = None
        self.pending_lsp_id: str | None = None
        self.in_topology_block: bool = False

    def ensure_level(self) -> str:
        """Ensure a level context exists, defaulting to Level-2."""
        if self.current_level is None:
            self.current_level = "Level-2"
            self.levels.setdefault(self.current_level, {})
        return self.current_level

    def reset_lsp_context(self) -> None:
        """Reset LSP-level context on structural change."""
        self.current_lsp = None
        self.pending_lsp_id = None
        self.in_topology_block = False


def _handle_structural_line(line: str, state: _ParseState) -> bool:
    """Handle tag, level header, and column header lines. Returns True if matched."""
    tag_match = _TAG_PATTERN.match(line)
    if tag_match:
        state.tag = tag_match.group("tag")
        state.reset_lsp_context()
        return True

    level_match = _LEVEL_HEADER_PATTERN.match(line)
    if level_match:
        state.current_level = level_match.group("level")
        state.levels.setdefault(state.current_level, {})
        state.reset_lsp_context()
        return True

    if _COLUMN_HEADER_PATTERN.match(line):
        state.reset_lsp_context()
        return True

    return False


def _handle_lsp_header(line: str, state: _ParseState) -> bool:
    """Handle LSP header lines (single-line and continuation).

    Returns True if matched.
    """
    lsp_single = _LSP_SINGLE_PATTERN.match(line)
    if lsp_single:
        level = state.ensure_level()
        lsp_id = lsp_single.group("lsp_id")
        state.current_lsp = _build_lsp_entry(
            seq=lsp_single.group("seq"),
            checksum=lsp_single.group("checksum"),
            holdtime=lsp_single.group("holdtime"),
            rcvd=lsp_single.group("rcvd"),
            att=lsp_single.group("att"),
            p=lsp_single.group("p"),
            ol=lsp_single.group("ol"),
            local=lsp_single.group("local"),
        )
        state.levels[level][lsp_id] = state.current_lsp
        state.pending_lsp_id = None
        state.in_topology_block = False
        return True

    cont_start = _LSP_CONT_START_PATTERN.match(line)
    if cont_start:
        state.pending_lsp_id = cont_start.group("lsp_id")
        state.in_topology_block = False
        return True

    return False


def _handle_continuation_data(line: str, state: _ParseState) -> bool:
    """Handle LSP continuation data line. Returns True if matched."""
    if state.pending_lsp_id is None:
        return False

    cont_data = _LSP_CONT_DATA_PATTERN.match(line)
    if cont_data:
        level = state.ensure_level()
        state.current_lsp = _build_lsp_entry(
            seq=cont_data.group("seq"),
            checksum=cont_data.group("checksum"),
            holdtime=cont_data.group("holdtime"),
            rcvd=cont_data.group("rcvd"),
            att=cont_data.group("att"),
            p=cont_data.group("p"),
            ol=cont_data.group("ol"),
            local=cont_data.group("local"),
        )
        state.levels[level][state.pending_lsp_id] = state.current_lsp
        state.pending_lsp_id = None
        return True

    return False


def _handle_topology(line: str, state: _ParseState) -> bool:
    """Handle topology TLV lines. Returns True if matched."""
    if state.current_lsp is None:
        return False

    if state.in_topology_block:
        topo_cont = _TOPOLOGY_CONT.match(line)
        if topo_cont:
            if "topologies" not in state.current_lsp:
                state.current_lsp["topologies"] = []
            state.current_lsp["topologies"].append(topo_cont.group("topo").strip())
            return True
        state.in_topology_block = False

    topo_match = _TOPOLOGY.match(line)
    if topo_match:
        if "topologies" not in state.current_lsp:
            state.current_lsp["topologies"] = []
        state.current_lsp["topologies"].append(topo_match.group("topo").strip())
        state.in_topology_block = True
        return True

    return False


@register(OS.CISCO_IOSXE, "show isis database detail")
class ShowIsisDatabaseDetailParser(BaseParser["ShowIsisDatabaseDetailResult"]):
    """Parser for 'show isis database detail' command on IOS-XE.

    Parses the IS-IS link state database detail output including LSP headers
    and TLV contents (area address, NLPID, topology, router ID, hostname,
    IS neighbors, IP reachability, and IPv6 reachability).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisDatabaseDetailResult":
        """Parse 'show isis database detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LSP data grouped by tag and level.

        Raises:
            ValueError: If no LSP entries found in output.
        """
        state = _ParseState()

        for line in output.splitlines():
            if not line.strip():
                continue

            if _handle_structural_line(line, state):
                continue

            if _handle_lsp_header(line, state):
                continue

            if _handle_continuation_data(line, state):
                continue

            if _handle_topology(line, state):
                continue

            if state.current_lsp is not None:
                (
                    _parse_identity_tlv(line, state.current_lsp)
                    or _parse_capability_tlv(line, state.current_lsp)
                    or _parse_metric_tlv(line, state.current_lsp)
                )

        if not state.levels:
            msg = "No IS-IS LSP entries found in output"
            raise ValueError(msg)

        return {"tag": state.tag, "levels": state.levels}
