"""Parser for 'show isis topology' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisTopologyPath(TypedDict):
    """Schema for a single IS-IS topology path (next-hop) entry."""

    metric: int
    next_hop: str
    snpa: str


class IsisTopologySystem(TypedDict):
    """Schema for a single system in the IS-IS topology table.

    When is_local is True, paths will be empty (the local router has
    no next-hop to itself).
    """

    is_local: bool
    paths: dict[str, IsisTopologyPath]


class ShowIsisTopologyResult(TypedDict):
    """Schema for 'show isis topology' parsed output.

    Top-level keys are IS-IS instance IDs. Each instance maps topology
    table identifiers (e.g. "IPv4 Unicast (Level-2)") to a dict of
    system IDs, each containing reachability path information keyed
    by outgoing interface.
    """

    instances: dict[str, dict[str, dict[str, IsisTopologySystem]]]
    total_path_count: NotRequired[int]


# Table header: "IS-IS <instance> paths to <address_family> (<level>) routers"
_TABLE_HEADER_PATTERN = re.compile(
    r"^IS-IS\s+(?P<instance>\S+)\s+paths\s+to\s+"
    r"(?P<address_family>.+?)\s+"
    r"\((?P<level>[^)]+)\)\s+routers\s*$"
)

# Column header line (skip it)
_COLUMN_HEADER_PATTERN = re.compile(
    r"^System\s+Id\s+Metric\s+Next-Hop\s+Interface\s+SNPA\s*$"
)

# Local system entry: "system_id       --"
_LOCAL_SYSTEM_PATTERN = re.compile(r"^(?P<system_id>\S+)\s+--\s*$")

# Path entry: "system_id  metric  next_hop  interface  snpa"
_PATH_PATTERN = re.compile(
    r"^(?P<system_id>\S+)\s+"
    r"(?P<metric>\d+)\s+"
    r"(?P<next_hop>\S+)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<snpa>\S+)\s*$"
)


@register(OS.CISCO_IOSXR, "show isis topology")
class ShowIsisTopologyParser(BaseParser["ShowIsisTopologyResult"]):
    """Parser for 'show isis topology' command on IOS-XR.

    Parses IS-IS topology (SPF) path information showing reachability
    to all routers in the IS-IS domain. Entries are grouped by IS-IS
    instance, then by address family and level, then keyed by system
    ID and outgoing interface.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisTopologyResult":
        """Parse 'show isis topology' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed topology data grouped by IS-IS instance, address
            family/level, and system ID.

        Raises:
            ValueError: If no topology tables found in output.
        """
        instances: dict[str, dict[str, dict[str, IsisTopologySystem]]] = {}
        current_instance: str | None = None
        current_table_key: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _COLUMN_HEADER_PATTERN.match(stripped):
                continue

            header_match = _TABLE_HEADER_PATTERN.match(stripped)
            if header_match:
                current_instance = header_match.group("instance")
                current_table_key = cls._table_key(header_match)
                instances.setdefault(current_instance, {})[current_table_key] = {}
                continue

            if current_instance is None or current_table_key is None:
                continue

            systems = instances[current_instance][current_table_key]
            cls._process_entry(systems, stripped)

        if not instances:
            msg = "No IS-IS topology tables found in output"
            raise ValueError(msg)

        result: ShowIsisTopologyResult = {"instances": instances}
        total = cls._count_paths(instances)
        if total > 0:
            result["total_path_count"] = total

        return result

    @staticmethod
    def _table_key(match: re.Match[str]) -> str:
        """Build a table key from address family and level."""
        af = match.group("address_family")
        level = match.group("level")
        return f"{af} ({level})"

    @classmethod
    def _process_entry(cls, systems: dict[str, IsisTopologySystem], line: str) -> None:
        """Process a single topology entry line."""
        local_match = _LOCAL_SYSTEM_PATTERN.match(line)
        if local_match:
            system_id = local_match.group("system_id")
            if system_id not in systems:
                systems[system_id] = {"is_local": True, "paths": {}}
            else:
                systems[system_id]["is_local"] = True
            return

        path_match = _PATH_PATTERN.match(line)
        if path_match:
            cls._add_path(systems, path_match)

    @staticmethod
    def _add_path(
        systems: dict[str, IsisTopologySystem],
        match: re.Match[str],
    ) -> None:
        """Add a parsed path entry to the systems dict."""
        system_id = match.group("system_id")
        interface_raw = match.group("interface").strip()
        interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)

        if system_id not in systems:
            systems[system_id] = {"is_local": False, "paths": {}}

        path: IsisTopologyPath = {
            "metric": int(match.group("metric")),
            "next_hop": match.group("next_hop"),
            "snpa": match.group("snpa"),
        }
        systems[system_id]["paths"][interface] = path

    @staticmethod
    def _count_paths(
        instances: dict[str, dict[str, dict[str, IsisTopologySystem]]],
    ) -> int:
        """Count total paths across all instances and tables."""
        total = 0
        for tables in instances.values():
            for systems in tables.values():
                for system in systems.values():
                    total += len(system["paths"])
        return total
