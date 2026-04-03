"""Parser for 'show ted database extensive' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Sentinel for unknown node type (displayed as "---" by Junos)
_UNKNOWN_TYPE = "---"


class ISCDEntry(TypedDict):
    """Interface Switching Capability Descriptor."""

    switching_type: str
    encoding_type: str
    maximum_lsp_bw_bps: list[str]


class AdjacencySID(TypedDict):
    """P2P Adjacency-SID entry."""

    address_family: str
    flags: str
    weight: int


class PrefixSID(TypedDict):
    """Prefix-SID entry."""

    sid: int
    flags: str
    algorithm: int


class PrefixEntry(TypedDict):
    """A prefix with optional flags and Prefix-SID."""

    flags: NotRequired[str]
    prefix_sid: NotRequired[PrefixSID]


class SRGBBlock(TypedDict):
    """SPRING SRGB block."""

    range: int
    flags: str


class LinkEntry(TypedDict):
    """A single TE link to a neighbor."""

    local_address: str
    remote_address: str
    local_interface_index: int
    remote_interface_index: int
    color: NotRequired[int]
    color_name: NotRequired[str]
    metric: int
    static_bw: NotRequired[str]
    reservable_bw: NotRequired[str]
    available_bw_bps: NotRequired[list[str]]
    iscd: NotRequired[dict[str, ISCDEntry]]
    adjacency_sids: NotRequired[dict[str, AdjacencySID]]


class NodeEntry(TypedDict):
    """A single TED node."""

    node_type: NotRequired[str]
    age_secs: int
    link_in: int
    link_out: int
    protocol: NotRequired[str]
    links: NotRequired[dict[str, LinkEntry]]
    prefixes: NotRequired[dict[str, PrefixEntry]]
    srgb_blocks: NotRequired[dict[str, SRGBBlock]]
    spring_algorithms: NotRequired[list[int]]


ShowTedDatabaseExtensiveResult = dict[str, NodeEntry]


# -- Compiled patterns --

_NODE_ID = re.compile(r"^\s*NodeID:\s+(?P<node_id>\S+)\s*$")
_NODE_TYPE = re.compile(
    r"^\s*Type:\s+(?P<type>\S+),\s+Age:\s+(?P<age>\d+)\s+secs,"
    r"\s+LinkIn:\s+(?P<link_in>\d+),\s+LinkOut:\s+(?P<link_out>\d+)\s*$"
)
_PROTOCOL = re.compile(r"^\s*Protocol:\s+(?P<protocol>.+?)\s*$")
_TO = re.compile(
    r"^\s*To:\s+(?P<to>\S+),\s+Local:\s+(?P<local>\S+),"
    r"\s+Remote:\s+(?P<remote>\S+)\s*$"
)
_INTF_INDEX = re.compile(
    r"^\s*Local interface index:\s+(?P<local>\d+),"
    r"\s+Remote interface index:\s+(?P<remote>\d+)\s*$"
)
_COLOR = re.compile(r"^\s*Color:\s+(?P<color>\d+)\s*(?P<name>\S+)?\s*$")
_METRIC = re.compile(r"^\s*Metric:\s+(?P<metric>\d+)\s*$")
_STATIC_BW = re.compile(r"^\s*Static BW:\s+(?P<bw>\S+)\s*$")
_RESERVABLE_BW = re.compile(r"^\s*Reservable BW:\s+(?P<bw>\S+)\s*$")
_SWITCHING_TYPE = re.compile(r"^\s*Switching type:\s+(?P<val>.+?)\s*$")
_ENCODING_TYPE = re.compile(r"^\s*Encoding type:\s+(?P<val>.+?)\s*$")
_ISCD_HEADER = re.compile(
    r"^\s*Interface Switching Capability Descriptor\((?P<index>\d+)\):\s*$"
)
_ADJ_SID = re.compile(
    r"^\s*(?P<af>IPV[46]),\s+SID:\s+(?P<sid>\d+),"
    r"\s+Flags:\s+(?P<flags>0x[0-9a-fA-F]+),\s+Weight:\s+(?P<weight>\d+)\s*$"
)
_PREFIX_LINE = re.compile(r"^\s+(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)\s*$")
_PREFIX_FLAGS = re.compile(r"^\s*Flags:\s+(?P<flags>0x[0-9a-fA-F]+)\s*$")
_PREFIX_SID_LINE = re.compile(
    r"^\s*SID:\s+(?P<sid>\d+),\s+Flags:\s+(?P<flags>0x[0-9a-fA-F]+),"
    r"\s+Algo:\s+(?P<algo>\d+)\s*$"
)
_SRGB_BLOCK = re.compile(
    r"^\s*SRGB block \[Start:\s+(?P<start>\d+),"
    r"\s+Range:\s+(?P<range>\d+),"
    r"\s+Flags:\s+(?P<flags>0x[0-9a-fA-F]+)\]\s*$"
)
_SPRING_ALGO = re.compile(r"^\s*Algo:\s+(?P<algo>\d+)\s*$")
_BW_VALUES = re.compile(r"\[(\d+)\]\s+(\S+)")


def _parse_bw_line(line: str) -> list[str]:
    """Extract bandwidth values from a priority-indexed line."""
    return [m.group(2) for m in _BW_VALUES.finditer(line)]


def _is_link_block_boundary(line: str, stripped: str) -> bool:
    """Return True if this line marks the end of a link block."""
    if _TO.match(line) or _NODE_ID.match(line):
        return True
    if stripped.startswith("Prefixes:") or stripped.startswith("SPRING-"):
        return True
    return False


def _process_link_value_line(
    stripped: str,
    link: dict[str, object],
    adj_sids: dict[str, AdjacencySID],
    current_iscd: dict[str, object] | None,
    bw_target: str,
    idx: int,
) -> tuple[int, dict[str, object] | None, str]:
    """Process value lines (bandwidth arrays, ISCD fields, adj-SIDs)."""
    if m := _ADJ_SID.match(stripped):
        sid_key = str(m.group("sid"))
        adj_sids[sid_key] = AdjacencySID(
            address_family=m.group("af"),
            flags=m.group("flags"),
            weight=int(m.group("weight")),
        )
        return idx + 1, current_iscd, bw_target

    if current_iscd is not None:
        if m := _SWITCHING_TYPE.match(stripped):
            current_iscd["switching_type"] = m.group("val")
            return idx + 1, current_iscd, bw_target
        if m := _ENCODING_TYPE.match(stripped):
            current_iscd["encoding_type"] = m.group("val")
            return idx + 1, current_iscd, bw_target

    # Bandwidth priority lines like "[0] 10bps  [1] 10bps ..."
    bw_vals = _parse_bw_line(stripped)
    if bw_vals:
        _collect_bw_values(bw_vals, bw_target, link, current_iscd)

    return idx + 1, current_iscd, bw_target


def _collect_bw_values(
    bw_vals: list[str],
    bw_target: str,
    link: dict[str, object],
    current_iscd: dict[str, object] | None,
) -> None:
    """Append bandwidth values to the correct target list."""
    if bw_target == "available":
        available = link.get("available_bw_bps")
        if isinstance(available, list):
            cast(list[str], available).extend(bw_vals)
    elif bw_target == "max_lsp" and current_iscd is not None:
        max_lsp = current_iscd.get("maximum_lsp_bw_bps")
        if isinstance(max_lsp, list):
            cast(list[str], max_lsp).extend(bw_vals)


def _parse_link_attributes(
    stripped: str,
    link: dict[str, object],
) -> bool:
    """Try to parse a link attribute line (metric, color, BW, etc.).

    Returns True if the line was consumed.
    """
    if m := _INTF_INDEX.match(stripped):
        link["local_interface_index"] = int(m.group("local"))
        link["remote_interface_index"] = int(m.group("remote"))
        return True

    if m := _COLOR.match(stripped):
        link["color"] = int(m.group("color"))
        name = m.group("name")
        if name and name != "<none>":
            link["color_name"] = name
        return True

    if m := _METRIC.match(stripped):
        link["metric"] = int(m.group("metric"))
        return True

    if m := _STATIC_BW.match(stripped):
        link["static_bw"] = m.group("bw")
        return True

    if m := _RESERVABLE_BW.match(stripped):
        link["reservable_bw"] = m.group("bw")
        return True

    return False


def _parse_link_section_header(
    stripped: str,
    link: dict[str, object],
    iscd_dict: dict[str, ISCDEntry],
    current_iscd: dict[str, object] | None,
) -> tuple[dict[str, object] | None, str] | None:
    """Try to parse a section header line inside a link block.

    Returns (new_current_iscd, new_bw_target) if consumed, else None.
    """
    if stripped.startswith("Available BW"):
        link["available_bw_bps"] = []
        return current_iscd, "available"

    if m := _ISCD_HEADER.match(stripped):
        new_iscd: dict[str, object] = {}
        iscd_dict[m.group("index")] = cast(ISCDEntry, new_iscd)
        return new_iscd, ""

    if stripped.startswith("Maximum LSP BW"):
        if current_iscd is not None:
            current_iscd["maximum_lsp_bw_bps"] = []
        return current_iscd, "max_lsp"

    if stripped.startswith("P2P Adjacency-SID"):
        return current_iscd, ""

    return None


def _process_single_link_line(
    stripped: str,
    link: dict[str, object],
    iscd_dict: dict[str, ISCDEntry],
    adj_sids: dict[str, AdjacencySID],
    current_iscd: dict[str, object] | None,
    bw_target: str,
    idx: int,
) -> tuple[int, dict[str, object] | None, str]:
    """Process one line inside a link block.

    Returns (next_idx, current_iscd, bw_target).
    """
    if _parse_link_attributes(stripped, link):
        return idx + 1, current_iscd, bw_target

    result = _parse_link_section_header(
        stripped,
        link,
        iscd_dict,
        current_iscd,
    )
    if result is not None:
        return idx + 1, result[0], result[1]

    return _process_link_value_line(
        stripped,
        link,
        adj_sids,
        current_iscd,
        bw_target,
        idx,
    )


def _finalize_link(
    link: dict[str, object],
    iscd_dict: dict[str, ISCDEntry],
    adj_sids: dict[str, AdjacencySID],
) -> None:
    """Attach optional sub-structures to the link dict if non-empty."""
    if iscd_dict:
        link["iscd"] = iscd_dict
    if adj_sids:
        link["adjacency_sids"] = adj_sids


def _parse_link_block(
    lines: list[str],
    start: int,
) -> tuple[str, LinkEntry, int]:
    """Parse a link block starting at the 'To:' line.

    Returns:
        Tuple of (to_address, link_entry, next_line_index).
    """
    to_match = _TO.match(lines[start])
    if not to_match:
        msg = f"Expected 'To:' line at index {start}"
        raise ValueError(msg)

    to_addr = to_match.group("to")
    link: dict[str, object] = {
        "local_address": to_match.group("local"),
        "remote_address": to_match.group("remote"),
    }
    idx = start + 1
    iscd_dict: dict[str, ISCDEntry] = {}
    adj_sids: dict[str, AdjacencySID] = {}
    current_iscd: dict[str, object] | None = None
    bw_target: str = ""

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if _is_link_block_boundary(line, stripped):
            break

        idx, current_iscd, bw_target = _process_single_link_line(
            stripped,
            link,
            iscd_dict,
            adj_sids,
            current_iscd,
            bw_target,
            idx,
        )

    _finalize_link(link, iscd_dict, adj_sids)
    return to_addr, cast(LinkEntry, link), idx


def _is_prefix_section_boundary(line: str, stripped: str) -> bool:
    """Return True if the line ends the prefix section."""
    if _NODE_ID.match(line):
        return True
    return stripped.startswith("SPRING-")


def _parse_prefix_detail(
    stripped: str,
    current: dict[str, object],
    in_prefix_sid: bool,
) -> bool:
    """Parse a detail line for the current prefix (flags or SID).

    Returns True if the line was consumed.
    """
    if stripped.startswith("Prefix-SID:"):
        return True  # caller sets in_prefix_sid

    if in_prefix_sid:
        if m := _PREFIX_SID_LINE.match(stripped):
            current["prefix_sid"] = PrefixSID(
                sid=int(m.group("sid")),
                flags=m.group("flags"),
                algorithm=int(m.group("algo")),
            )
            return True

    if m := _PREFIX_FLAGS.match(stripped):
        current["flags"] = m.group("flags")
        return True

    return False


def _parse_prefixes(
    lines: list[str],
    start: int,
) -> tuple[dict[str, PrefixEntry], int]:
    """Parse the Prefixes: section. Return (prefix_dict, next_index)."""
    idx = start
    prefixes: dict[str, PrefixEntry] = {}
    current: dict[str, object] | None = None
    in_prefix_sid = False

    while idx < len(lines):
        stripped = lines[idx].strip()

        if _is_prefix_section_boundary(lines[idx], stripped):
            break

        if m := _PREFIX_LINE.match(lines[idx]):
            current = {}
            prefixes[m.group("prefix")] = cast(PrefixEntry, current)
            in_prefix_sid = False
            idx += 1
            continue

        if current is not None:
            if stripped.startswith("Prefix-SID:"):
                in_prefix_sid = True
                idx += 1
                continue
            if _parse_prefix_detail(stripped, current, in_prefix_sid):
                if in_prefix_sid and _PREFIX_SID_LINE.match(stripped):
                    in_prefix_sid = False
                idx += 1
                continue

        idx += 1

    return prefixes, idx


def _parse_spring_capabilities(
    lines: list[str],
    start: int,
) -> tuple[dict[str, SRGBBlock], int]:
    """Parse SPRING-Capabilities section. Return (srgb_blocks_dict, next_index)."""
    idx = start
    blocks: dict[str, SRGBBlock] = {}

    while idx < len(lines):
        stripped = lines[idx].strip()

        if _NODE_ID.match(lines[idx]):
            break
        if stripped.startswith("SPRING-Algorithms"):
            break

        if m := _SRGB_BLOCK.match(stripped):
            start_key = m.group("start")
            blocks[start_key] = SRGBBlock(
                range=int(m.group("range")),
                flags=m.group("flags"),
            )

        idx += 1

    return blocks, idx


def _parse_spring_algorithms(lines: list[str], start: int) -> tuple[list[int], int]:
    """Parse SPRING-Algorithms section. Return (algo_list, next_index)."""
    idx = start
    algos: list[int] = []

    while idx < len(lines):
        stripped = lines[idx].strip()

        if _NODE_ID.match(lines[idx]):
            break
        if stripped.startswith("SPRING-Capabilities"):
            break

        if m := _SPRING_ALGO.match(stripped):
            algos.append(int(m.group("algo")))

        idx += 1

    return algos, idx


def _dispatch_node_section(
    lines: list[str],
    idx: int,
    stripped: str,
    node: dict[str, object],
) -> int | None:
    """Try to parse a named section (Prefixes, SPRING-*).

    Returns new idx if a section was consumed, else None.
    """
    if stripped.startswith("Prefixes:"):
        prefixes, new_idx = _parse_prefixes(lines, idx + 1)
        if prefixes:
            node["prefixes"] = prefixes
        return new_idx

    if stripped.startswith("SPRING-Capabilities:"):
        blocks, new_idx = _parse_spring_capabilities(lines, idx + 1)
        if blocks:
            node["srgb_blocks"] = blocks
        return new_idx

    if stripped.startswith("SPRING-Algorithms:"):
        algos, new_idx = _parse_spring_algorithms(lines, idx + 1)
        if algos:
            node["spring_algorithms"] = algos
        return new_idx

    return None


def _parse_node_body(
    lines: list[str],
    start: int,
    node: dict[str, object],
) -> int:
    """Parse the body of a node (links, prefixes, SPRING). Return next index."""
    idx = start
    links: dict[str, LinkEntry] = {}

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if _NODE_ID.match(line):
            break

        if m := _PROTOCOL.match(stripped):
            node["protocol"] = m.group("protocol")
            idx += 1
            continue

        if _TO.match(line):
            to_addr, link, idx = _parse_link_block(lines, idx)
            links[to_addr] = link
            continue

        new_idx = _dispatch_node_section(lines, idx, stripped, node)
        if new_idx is not None:
            idx = new_idx
            continue

        idx += 1

    if links:
        node["links"] = links

    return idx


@register(OS.JUNIPER_JUNOS, "show ted database extensive")
class ShowTedDatabaseExtensiveParser(
    BaseParser[ShowTedDatabaseExtensiveResult],
):
    """Parser for 'show ted database extensive' command on Juniper Junos.

    Parses TED (Traffic Engineering Database) nodes including links,
    prefixes, and SPRING/Segment Routing capabilities.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> ShowTedDatabaseExtensiveResult:
        """Parse 'show ted database extensive' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by node ID with node details.

        Raises:
            ValueError: If no nodes found in output.
        """
        lines = output.splitlines()
        result: ShowTedDatabaseExtensiveResult = {}
        idx = 0

        while idx < len(lines):
            m = _NODE_ID.match(lines[idx])
            if not m:
                idx += 1
                continue

            node_id = m.group("node_id")
            idx += 1

            if idx >= len(lines):
                break

            type_match = _NODE_TYPE.match(lines[idx].strip())
            if not type_match:
                continue

            node: dict[str, object] = {
                "age_secs": int(type_match.group("age")),
                "link_in": int(type_match.group("link_in")),
                "link_out": int(type_match.group("link_out")),
            }

            node_type = type_match.group("type")
            if node_type != _UNKNOWN_TYPE:
                node["node_type"] = node_type

            idx += 1

            idx = _parse_node_body(lines, idx, node)
            result[node_id] = cast(NodeEntry, node)

        if not result:
            msg = "No TED nodes found in output"
            raise ValueError(msg)

        return result
