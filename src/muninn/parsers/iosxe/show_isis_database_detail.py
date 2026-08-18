"""Parser for 'show isis database detail' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

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


class RouterCapEntry(TypedDict):
    """Schema for Router Capability TLV."""

    address: str
    d_flag: int
    s_flag: int


class SrGlobalBlock(TypedDict):
    """Schema for Segment Routing Global Block (SRGB)."""

    base: int
    range: int


class SrLocalBlock(TypedDict):
    """Schema for Segment Routing Local Block (SRLB)."""

    base: int
    range: int


class SidStructureEntry(TypedDict):
    """Schema for SRv6 SID Structure."""

    block_length: int
    node_id_length: int
    func_length: int
    args_length: int


class Srv6EndSidEntry(TypedDict):
    """Schema for an SRv6 End SID entry."""

    sid: str
    behavior: str
    flavors: NotRequired[str]
    sid_structure: NotRequired[SidStructureEntry]


class Srv6LocatorEntry(TypedDict):
    """Schema for an SRv6 Locator entry."""

    prefix: str
    metric: int
    algorithm: int
    mt: NotRequired[str]
    end_sids: NotRequired[list[Srv6EndSidEntry]]


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
    router_cap: NotRequired[RouterCapEntry]
    sr_srgb: NotRequired[SrGlobalBlock]
    sr_srlb: NotRequired[SrLocalBlock]
    node_msd: NotRequired[int]
    srv6_locators: NotRequired[list[Srv6LocatorEntry]]
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

# SR/SRv6 TLV patterns
# "  Router CAP:   10.255.255.1, D:0, S:0"
_ROUTER_CAP = re.compile(
    r"^\s+Router CAP:\s+(?P<address>\S+),\s+D:(?P<d>\d),\s+S:(?P<s>\d)\s*$"
)

# "    Segment Routing: I:1 V:0, SRGB Base: 16000 Range: 8000"
_SR_SRGB = re.compile(
    r"^\s+Segment Routing:\s+I:\d+\s+V:\d+,\s+SRGB Base:\s+(?P<base>\d+)\s+"
    r"Range:\s+(?P<range>\d+)\s*$"
)

# "    Segment Routing Local Block: SRLB Base: 15000 Range: 1000"
_SR_SRLB = re.compile(
    r"^\s+Segment Routing Local Block:\s+SRLB Base:\s+(?P<base>\d+)\s+"
    r"Range:\s+(?P<range>\d+)\s*$"
)

# "    Node-MSD"
_NODE_MSD_HEADER = re.compile(r"^\s+Node-MSD\s*$")

# "      MSD: 16"
_MSD_VALUE = re.compile(r"^\s+MSD:\s+(?P<msd>\d+)\s*$")

# "  SRv6 Locator: (MT-IPv6) fd00:1:1::/48 Metric:0 Algorithm:0"
_SRV6_LOCATOR = re.compile(
    r"^\s+SRv6 Locator:\s+(?:\((?P<mt>[^)]+)\)\s+)?(?P<prefix>\S+)\s+"
    r"Metric:(?P<metric>\d+)\s+Algorithm:(?P<algo>\d+)\s*$"
)

# "    End SID: fd00:1:1:: uN (PSP/USD)"
_END_SID = re.compile(
    r"^\s+End SID:\s+(?P<sid>\S+)\s+(?P<behavior>\S+)"
    r"(?:\s+\((?P<flavors>[^)]+)\))?\s*$"
)

# "      SID Structure:"
_SID_STRUCTURE_HEADER = re.compile(r"^\s+SID Structure:\s*$")

# "        Block Length: 32, Node-ID Length: 16, Func-Length: 0, Args-Length: 80"
_SID_STRUCTURE_DATA = re.compile(
    r"^\s+Block Length:\s+(?P<block>\d+),\s+"
    r"Node-ID Length:\s+(?P<node_id>\d+),\s+"
    r"Func-Length:\s+(?P<func>\d+),\s+"
    r"Args-Length:\s+(?P<args>\d+)\s*$"
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
        "in_node_msd",
        "in_sid_structure",
        "current_locator",
        "current_end_sid",
    )

    def __init__(self) -> None:
        self.tag: str = "null"
        self.levels: dict[str, dict[str, IsisLspEntry]] = {}
        self.current_level: str | None = None
        self.current_lsp: IsisLspEntry | None = None
        self.pending_lsp_id: str | None = None
        self.in_topology_block: bool = False
        self.in_node_msd: bool = False
        self.in_sid_structure: bool = False
        self.current_locator: Srv6LocatorEntry | None = None
        self.current_end_sid: Srv6EndSidEntry | None = None

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
        self.in_node_msd = False
        self.in_sid_structure = False
        self.current_locator = None
        self.current_end_sid = None


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
        state.in_node_msd = False
        state.in_sid_structure = False
        state.current_locator = None
        state.current_end_sid = None
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


def _parse_sr_pending_state(line: str, state: _ParseState) -> bool:
    """Handle state-dependent SR TLV lines (SID structure data, MSD value).

    Returns True if matched and consumed.
    """
    lsp = state.current_lsp
    if lsp is None:
        return False

    if state.in_sid_structure:
        sid_data = _SID_STRUCTURE_DATA.match(line)
        if sid_data:
            structure: SidStructureEntry = {
                "block_length": int(sid_data.group("block")),
                "node_id_length": int(sid_data.group("node_id")),
                "func_length": int(sid_data.group("func")),
                "args_length": int(sid_data.group("args")),
            }
            if state.current_end_sid is not None:
                state.current_end_sid["sid_structure"] = structure
            state.in_sid_structure = False
            return True
        state.in_sid_structure = False

    if state.in_node_msd:
        msd_match = _MSD_VALUE.match(line)
        if msd_match:
            lsp["node_msd"] = int(msd_match.group("msd"))
            state.in_node_msd = False
            return True
        state.in_node_msd = False

    return False


def _parse_sr_router_cap(line: str, lsp: IsisLspEntry) -> bool:
    """Try to parse Router CAP and SR block TLV fields. Returns True if matched."""
    cap_match = _ROUTER_CAP.match(line)
    if cap_match:
        lsp["router_cap"] = {
            "address": cap_match.group("address"),
            "d_flag": int(cap_match.group("d")),
            "s_flag": int(cap_match.group("s")),
        }
        return True

    srgb_match = _SR_SRGB.match(line)
    if srgb_match:
        lsp["sr_srgb"] = {
            "base": int(srgb_match.group("base")),
            "range": int(srgb_match.group("range")),
        }
        return True

    srlb_match = _SR_SRLB.match(line)
    if srlb_match:
        lsp["sr_srlb"] = {
            "base": int(srlb_match.group("base")),
            "range": int(srlb_match.group("range")),
        }
        return True

    return False


def _parse_srv6_end_sid(line: str, state: _ParseState) -> bool:
    """Try to parse an SRv6 End SID line. Returns True if matched."""
    end_sid_match = _END_SID.match(line)
    if not end_sid_match:
        return False

    end_sid: Srv6EndSidEntry = {
        "sid": end_sid_match.group("sid"),
        "behavior": end_sid_match.group("behavior"),
    }
    flavors = end_sid_match.group("flavors")
    if flavors:
        end_sid["flavors"] = flavors
    if state.current_locator is not None:
        if "end_sids" not in state.current_locator:
            state.current_locator["end_sids"] = []
        state.current_locator["end_sids"].append(end_sid)
    state.current_end_sid = end_sid
    return True


def _parse_srv6_tlv(line: str, state: _ParseState) -> bool:
    """Try to parse SRv6 locator and related fields. Returns True if matched."""
    lsp = state.current_lsp
    if lsp is None:
        return False

    if _NODE_MSD_HEADER.match(line):
        state.in_node_msd = True
        return True

    loc_match = _SRV6_LOCATOR.match(line)
    if loc_match:
        locator: Srv6LocatorEntry = {
            "prefix": loc_match.group("prefix"),
            "metric": int(loc_match.group("metric")),
            "algorithm": int(loc_match.group("algo")),
        }
        mt_val = loc_match.group("mt")
        if mt_val:
            locator["mt"] = mt_val
        if "srv6_locators" not in lsp:
            lsp["srv6_locators"] = []
        lsp["srv6_locators"].append(locator)
        state.current_locator = locator
        state.current_end_sid = None
        return True

    if _parse_srv6_end_sid(line, state):
        return True

    if _SID_STRUCTURE_HEADER.match(line):
        state.in_sid_structure = True
        return True

    return False


@register(OS.CISCO_IOSXE, "show isis database detail")
class ShowIsisDatabaseDetailParser(BaseParser["ShowIsisDatabaseDetailResult"]):
    """Parser for 'show isis database detail' command on IOS-XE.

    Parses the IS-IS link state database detail output including LSP headers
    and TLV contents (area address, NLPID, topology, router ID, hostname,
    IS neighbors, IP reachability, IPv6 reachability, Router CAP,
    Segment Routing SRGB/SRLB, Node-MSD, and SRv6 locators).
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
            cls._process_line(line, state)

        if not state.levels:
            msg = "No IS-IS LSP entries found in output"
            raise ValueError(msg)

        return {"tag": state.tag, "levels": state.levels}

    @classmethod
    def _process_line(cls, line: str, state: _ParseState) -> None:
        """Dispatch a single non-empty line to the appropriate handler."""
        if _handle_structural_line(line, state):
            return

        if _handle_lsp_header(line, state):
            return

        if _handle_continuation_data(line, state):
            return

        if _handle_topology(line, state):
            return

        if state.current_lsp is not None:
            cls._try_lsp_content_handlers(line, state)

    @classmethod
    def _try_lsp_content_handlers(cls, line: str, state: _ParseState) -> None:
        """Try LSP content handlers (SR, SRv6, identity, capability, metric)."""
        assert state.current_lsp is not None  # noqa: S101  # nosec B101
        (
            _parse_sr_pending_state(line, state)
            or _parse_sr_router_cap(line, state.current_lsp)
            or _parse_srv6_tlv(line, state)
            or _parse_identity_tlv(line, state.current_lsp)
            or _parse_capability_tlv(line, state.current_lsp)
            or _parse_metric_tlv(line, state.current_lsp)
        )
