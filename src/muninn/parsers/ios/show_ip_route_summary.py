"""Parser for 'show ip route summary' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RoutingTableInfo(TypedDict):
    """Schema for routing table metadata."""

    name: NotRequired[str]
    maximum_paths: NotRequired[int]


class OspfSubdetail(TypedDict):
    """Schema for OSPF route sub-details."""

    intra_area: int
    inter_area: int
    external_1: int
    external_2: int
    nssa_external_1: int
    nssa_external_2: int


class BgpSubdetail(TypedDict):
    """Schema for BGP route sub-details."""

    external: int
    internal: int
    local: int


class IsisSubdetail(TypedDict):
    """Schema for ISIS route sub-details."""

    level_1: int
    level_2: int
    inter_area: int


class RouteSourceEntry(TypedDict):
    """Schema for a single route source entry."""

    networks: int
    subnets: NotRequired[int]
    replicates: NotRequired[int]
    overhead: NotRequired[int]
    memory_bytes: int
    ospf: NotRequired[OspfSubdetail]
    bgp: NotRequired[BgpSubdetail]
    isis: NotRequired[IsisSubdetail]


class TotalEntry(TypedDict):
    """Schema for the total summary row."""

    networks: int
    subnets: NotRequired[int]
    replicates: NotRequired[int]
    overhead: NotRequired[int]
    memory_bytes: int


class ShowIpRouteSummaryResult(TypedDict):
    """Schema for 'show ip route summary' parsed output."""

    routing_table: NotRequired[RoutingTableInfo]
    route_sources: dict[str, RouteSourceEntry]
    total: TotalEntry


# Routing table header patterns
_TABLE_NAME_RE = re.compile(
    r"^IP routing table name is (?P<name>.+?)\s*(?:\([\w\d]+\))?\s*$"
)
_TABLE_MAX_PATHS_RE = re.compile(
    r"^IP routing table maximum-paths is (?P<max_paths>\d+)\s*$"
)

# Route source row: source name (alpha word, optionally space + identifier),
# followed by 2+ spaces then numeric columns.
# Examples:
#   connected       0           41          0           3936        11808
#   eigrp 65329     3           3013        0           481920      868608
#   internal        24                                              240672
_DATA_ROW_RE = re.compile(
    r"^(?P<source>[a-zA-Z]+(?:\s[a-zA-Z0-9]+)?)\s{2,}(?P<nums>\d[\d\s]*\d)\s*$"
)

# Header line detection
_HEADER_RE = re.compile(r"^Route Source\s+Networks\s+Subnets")

# OSPF sub-detail line
_OSPF_SUBDETAIL_RE = re.compile(
    r"^\s*Intra-area:\s*(?P<intra>\d+)\s+"
    r"Inter-area:\s*(?P<inter>\d+)\s+"
    r"External-1:\s*(?P<ext1>\d+)\s+"
    r"External-2:\s*(?P<ext2>\d+)\s*$"
)

_OSPF_NSSA_RE = re.compile(
    r"^\s*NSSA External-1:\s*(?P<nssa1>\d+)\s+"
    r"NSSA External-2:\s*(?P<nssa2>\d+)\s*$"
)

# BGP sub-detail line
_BGP_SUBDETAIL_RE = re.compile(
    r"^\s*External:\s*(?P<external>\d+)\s+"
    r"Internal:\s*(?P<internal>\d+)\s+"
    r"Local:\s*(?P<local>\d+)\s*$"
)

# ISIS sub-detail line
_ISIS_SUBDETAIL_RE = re.compile(
    r"^\s*Level 1:\s*(?P<level1>\d+)\s+"
    r"Level 2:\s*(?P<level2>\d+)\s+"
    r"Inter-area:\s*(?P<inter>\d+)\s*$"
)

# Known non-data source names to skip
_SKIP_SOURCES = frozenset({"Route"})


def _detect_column_count(output: str) -> int:
    """Detect the number of data columns from the header line.

    Returns:
        Number of numeric columns (4 without Replicates, 5 with).
    """
    for line in output.splitlines():
        if _HEADER_RE.match(line.strip()):
            if "Replicates" in line:
                return 5
            return 4
    return 5


def _build_entry_from_nums(nums: list[int], col_count: int, is_internal: bool) -> dict:
    """Build a dict from the numeric columns of a data row.

    Args:
        nums: List of parsed integers from the row.
        col_count: Expected number of columns (4 or 5).
        is_internal: True for the 'internal' row which lacks subnets column.

    Returns:
        Dict with the appropriate fields populated.
    """
    entry: dict = {}

    if is_internal:
        # 'internal' rows only have: networks  memory_bytes
        entry["networks"] = nums[0]
        entry["memory_bytes"] = nums[-1]
        return entry

    if col_count == 5:
        # networks, subnets, replicates, overhead, memory_bytes
        entry["networks"] = nums[0]
        entry["subnets"] = nums[1]
        entry["replicates"] = nums[2]
        entry["overhead"] = nums[3]
        entry["memory_bytes"] = nums[4]
    else:
        # networks, subnets, overhead, memory_bytes
        entry["networks"] = nums[0]
        entry["subnets"] = nums[1]
        entry["overhead"] = nums[2]
        entry["memory_bytes"] = nums[3]

    return entry


def _process_data_row(
    stripped: str,
    col_count: int,
    route_sources: dict[str, RouteSourceEntry],
) -> tuple[str | None, TotalEntry | None]:
    """Process a data row, returning (last_source, total_if_found)."""
    result_row = _try_parse_data_row(stripped, col_count)
    if result_row is None:
        return None, None

    source, entry = result_row
    if source == "Total":
        return source, cast(TotalEntry, entry)

    route_sources[source] = entry  # type: ignore[assignment]
    return source, None


def _parse_all_lines(
    lines: list[str],
    col_count: int,
    routing_table: RoutingTableInfo,
    route_sources: dict[str, RouteSourceEntry],
) -> TotalEntry | None:
    """Parse all lines and populate routing_table and route_sources.

    Returns:
        The Total entry if found, else None.
    """
    total: TotalEntry | None = None
    last_source: str | None = None
    ospf_subdetail: OspfSubdetail | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped or _HEADER_RE.match(stripped):
            continue

        if _try_parse_metadata(stripped, routing_table):
            continue

        if _try_parse_subdetails(line, route_sources, last_source, ospf_subdetail):
            ospf_subdetail = None
            continue

        ospf_subdetail = _try_parse_ospf_first_line(line)
        if ospf_subdetail is not None:
            continue

        source, found_total = _process_data_row(stripped, col_count, route_sources)
        if source is not None:
            last_source = source
        if found_total is not None:
            total = found_total

    return total


def _attach_ospf_subdetail(
    route_sources: dict[str, RouteSourceEntry],
    last_source: str | None,
    ospf_subdetail: OspfSubdetail,
) -> None:
    """Attach OSPF sub-detail to the last route source."""
    if last_source is not None and last_source in route_sources:
        route_sources[last_source]["ospf"] = ospf_subdetail


@register(OS.CISCO_IOS, "show ip route summary")
class ShowIpRouteSummaryParser(BaseParser["ShowIpRouteSummaryResult"]):
    """Parser for 'show ip route summary' command.

    Example output:
        IP routing table name is default (0x0)
        IP routing table maximum-paths is 32
        Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
        connected       0           41          0           3936        11808
        eigrp 65329     3           3013        0           481920      868608
        Total           28          3057        0           486528      1122244
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpRouteSummaryResult:
        """Parse 'show ip route summary' output.

        Args:
            output: Raw CLI output from 'show ip route summary' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        col_count = _detect_column_count(output)
        routing_table: RoutingTableInfo = {}
        route_sources: dict[str, RouteSourceEntry] = {}
        total: TotalEntry | None = None

        total = _parse_all_lines(
            output.splitlines(), col_count, routing_table, route_sources
        )

        if total is None:
            msg = "No Total row found in output"
            raise ValueError(msg)

        result: ShowIpRouteSummaryResult = {
            "route_sources": route_sources,
            "total": total,
        }

        if routing_table:
            result["routing_table"] = routing_table

        return result


def _try_parse_metadata(stripped: str, routing_table: RoutingTableInfo) -> bool:
    """Try to parse routing table metadata lines. Returns True if matched."""
    m = _TABLE_NAME_RE.match(stripped)
    if m:
        routing_table["name"] = m.group("name")
        return True

    m = _TABLE_MAX_PATHS_RE.match(stripped)
    if m:
        routing_table["maximum_paths"] = int(m.group("max_paths"))
        return True

    return False


def _try_parse_ospf_first_line(line: str) -> OspfSubdetail | None:
    """Try to parse the first OSPF sub-detail line. Returns partial detail."""
    m = _OSPF_SUBDETAIL_RE.match(line)
    if m:
        return {
            "intra_area": int(m.group("intra")),
            "inter_area": int(m.group("inter")),
            "external_1": int(m.group("ext1")),
            "external_2": int(m.group("ext2")),
            "nssa_external_1": 0,
            "nssa_external_2": 0,
        }
    return None


def _try_parse_subdetails(
    line: str,
    route_sources: dict[str, RouteSourceEntry],
    last_source: str | None,
    ospf_subdetail: OspfSubdetail | None,
) -> bool:
    """Try to parse OSPF NSSA, BGP, or ISIS sub-detail lines."""
    m = _OSPF_NSSA_RE.match(line)
    if m and ospf_subdetail is not None:
        ospf_subdetail["nssa_external_1"] = int(m.group("nssa1"))
        ospf_subdetail["nssa_external_2"] = int(m.group("nssa2"))
        _attach_ospf_subdetail(route_sources, last_source, ospf_subdetail)
        return True

    m = _BGP_SUBDETAIL_RE.match(line)
    if m and last_source is not None and last_source in route_sources:
        route_sources[last_source]["bgp"] = {
            "external": int(m.group("external")),
            "internal": int(m.group("internal")),
            "local": int(m.group("local")),
        }
        return True

    m = _ISIS_SUBDETAIL_RE.match(line)
    if m and last_source is not None and last_source in route_sources:
        route_sources[last_source]["isis"] = {
            "level_1": int(m.group("level1")),
            "level_2": int(m.group("level2")),
            "inter_area": int(m.group("inter")),
        }
        return True

    return False


def _try_parse_data_row(stripped: str, col_count: int) -> tuple[str, dict] | None:
    """Try to parse a data row (route source, internal, or Total)."""
    m = _DATA_ROW_RE.match(stripped)
    if not m:
        return None

    source = m.group("source").strip()
    if source in _SKIP_SOURCES:
        return None

    nums = [int(x) for x in m.group("nums").split()]
    is_internal = source == "internal"
    entry = _build_entry_from_nums(nums, col_count, is_internal)
    return source, entry
