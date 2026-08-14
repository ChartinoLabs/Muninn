"""Parser for 'show route summary' command on Cisco FTD."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RouteSourceEntry(TypedDict):
    """Schema for a single route source entry."""

    networks: int
    subnets: int
    replicates: int
    overhead: int
    memory_bytes: int
    external: NotRequired[int]
    internal: NotRequired[int]
    local: NotRequired[int]


class ShowRouteSummaryResult(TypedDict):
    """Schema for 'show route summary' parsed output on Cisco FTD."""

    maximum_paths: int
    route_sources: dict[str, RouteSourceEntry]


# --- Compiled regex patterns ---

_MAX_PATHS_RE = re.compile(r"IP routing table maximum-paths is (?P<max_paths>\d+)")

_ROUTE_SOURCE_RE = re.compile(
    r"^(?P<source>.+?)\s{2,}(?P<networks>\d+)\s+"
    r"(?P<subnets>\d+)\s+"
    r"(?P<replicates>\d+)\s+"
    r"(?P<overhead>\d+)\s+"
    r"(?P<memory>\d+)\s*$"
)

_INTERNAL_SOURCE_RE = re.compile(
    r"^(?P<source>internal)\s+(?P<networks>\d+)\s+(?P<memory>\d+)\s*$"
)

_BGP_DETAIL_RE = re.compile(
    r"^\s+External:\s*(?P<external>\d+)\s+"
    r"Internal:\s*(?P<internal>\d+)\s+"
    r"Local:\s*(?P<local>\d+)"
)


@register(OS.CISCO_FTD, "show route summary")
class ShowRouteSummaryParser(BaseParser["ShowRouteSummaryResult"]):
    """Parser for 'show route summary' command on Cisco FTD.

    Example output:
        IP routing table maximum-paths is 8
        Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
        connected       3           32          0           3080        10360
        static          1           0           0           88          296
        bgp 65001       5           2           0           2288        2072
          External: 7 Internal: 0 Local: 0
        internal        5                                               4560
        Total           14          34          0           5456        17288
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def _parse_bgp_detail(
        cls,
        line: str,
        last_source: str | None,
        route_sources: dict[str, RouteSourceEntry],
    ) -> bool:
        """Parse a BGP detail line and update the last source entry.

        Returns True if the line was consumed.
        """
        m = _BGP_DETAIL_RE.match(line)
        if m and last_source is not None and last_source in route_sources:
            route_sources[last_source]["external"] = int(m.group("external"))
            route_sources[last_source]["internal"] = int(m.group("internal"))
            route_sources[last_source]["local"] = int(m.group("local"))
            return True
        return False

    @classmethod
    def _parse_internal_source(cls, line: str) -> RouteSourceEntry | None:
        """Parse an internal source line (missing subnets/replicates/overhead).

        Returns the entry if matched, None otherwise.
        """
        m = _INTERNAL_SOURCE_RE.match(line.strip())
        if not m:
            return None
        return {
            "networks": int(m.group("networks")),
            "subnets": 0,
            "replicates": 0,
            "overhead": 0,
            "memory_bytes": int(m.group("memory")),
        }

    @classmethod
    def _parse_standard_source(cls, line: str) -> tuple[str, RouteSourceEntry] | None:
        """Parse a standard route source line.

        Returns a (source_name, entry) tuple if matched, None otherwise.
        """
        m = _ROUTE_SOURCE_RE.match(line.strip())
        if not m:
            return None
        source = m.group("source").strip()
        entry: RouteSourceEntry = {
            "networks": int(m.group("networks")),
            "subnets": int(m.group("subnets")),
            "replicates": int(m.group("replicates")),
            "overhead": int(m.group("overhead")),
            "memory_bytes": int(m.group("memory")),
        }
        return source, entry

    @classmethod
    def parse(cls, output: str) -> ShowRouteSummaryResult:
        """Parse 'show route summary' output.

        Args:
            output: Raw CLI output from 'show route summary' command.

        Returns:
            Parsed data with maximum paths and route source information.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        maximum_paths: int | None = None
        route_sources: dict[str, RouteSourceEntry] = {}
        last_source: str | None = None

        for line in lines:
            if not line.strip() or line.strip().startswith("Route Source"):
                continue

            m = _MAX_PATHS_RE.match(line.strip())
            if m:
                maximum_paths = int(m.group("max_paths"))
                continue

            if cls._parse_bgp_detail(line, last_source, route_sources):
                continue

            internal_entry = cls._parse_internal_source(line)
            if internal_entry is not None:
                m = _INTERNAL_SOURCE_RE.match(line.strip())
                assert m is not None
                source = m.group("source").strip()
                route_sources[source] = internal_entry
                last_source = source
                continue

            standard_result = cls._parse_standard_source(line)
            if standard_result is not None:
                source, entry = standard_result
                route_sources[source] = entry
                last_source = source
                continue

        if maximum_paths is None:
            msg = "Could not find 'IP routing table maximum-paths' in output"
            raise ValueError(msg)

        if not route_sources:
            msg = "No route sources found in output"
            raise ValueError(msg)

        return {
            "maximum_paths": maximum_paths,
            "route_sources": route_sources,
        }
