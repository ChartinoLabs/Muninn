"""Parser for 'show isis topology' command on Cisco IOS-XE."""

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
    """Schema for 'show isis topology' parsed output on IOS-XE.

    Top-level keys are IS-IS tags. Each tag maps table identifiers
    (e.g. "TID 0 (level-2)") to a dict of system IDs, each
    containing reachability path information keyed by outgoing
    interface.
    """

    tags: dict[str, dict[str, dict[str, IsisTopologySystem]]]
    total_path_count: NotRequired[int]


# Tag line: "Tag 64512:" or "Tag null:"
_TAG_PATTERN = re.compile(r"^Tag\s+(?P<tag>\S+):$")

# Table header: "IS-IS TID 0 paths to level-1 routers"
_TABLE_HEADER_PATTERN = re.compile(
    r"^IS-IS\s+TID\s+(?P<tid>\d+)\s+paths\s+to\s+"
    r"level-(?P<level>\d+)\s+routers\s*$"
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

# Continuation line: "                   next_hop  interface  snpa"
# (no system_id or metric, leading whitespace)
_CONTINUATION_PATTERN = re.compile(
    r"^\s+"
    r"(?P<next_hop>\S+)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<snpa>\S+)\s*$"
)


def _process_local_entry(
    systems: dict[str, IsisTopologySystem], system_id: str
) -> None:
    """Register a local system entry (metric --)."""
    if system_id not in systems:
        systems[system_id] = {"is_local": True, "paths": {}}
    else:
        systems[system_id]["is_local"] = True


def _process_path_entry(
    systems: dict[str, IsisTopologySystem], match: re.Match[str]
) -> tuple[str, int]:
    """Process a full path entry and return (system_id, metric)."""
    system_id = match.group("system_id")
    metric = int(match.group("metric"))
    interface_raw = match.group("interface")
    interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXE)

    if system_id not in systems:
        systems[system_id] = {"is_local": False, "paths": {}}

    path: IsisTopologyPath = {
        "metric": metric,
        "next_hop": match.group("next_hop"),
        "snpa": match.group("snpa"),
    }
    systems[system_id]["paths"][interface] = path
    return system_id, metric


def _process_continuation(
    systems: dict[str, IsisTopologySystem],
    match: re.Match[str],
    system_id: str,
    metric: int,
) -> None:
    """Process a continuation line (additional next-hop for same system)."""
    interface_raw = match.group("interface")
    interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXE)

    path: IsisTopologyPath = {
        "metric": metric,
        "next_hop": match.group("next_hop"),
        "snpa": match.group("snpa"),
    }
    systems[system_id]["paths"][interface] = path


def _process_entry(
    systems: dict[str, IsisTopologySystem],
    stripped: str,
    raw_line: str,
    last_system_id: str | None,
    last_metric: int,
) -> tuple[str | None, int]:
    """Process a topology entry line, returning updated (system_id, metric).

    Handles local entries, full path entries, and continuation lines.
    """
    local_match = _LOCAL_SYSTEM_PATTERN.match(stripped)
    if local_match:
        system_id = local_match.group("system_id")
        _process_local_entry(systems, system_id)
        return system_id, 0

    path_match = _PATH_PATTERN.match(stripped)
    if path_match:
        return _process_path_entry(systems, path_match)

    cont_match = _CONTINUATION_PATTERN.match(raw_line)
    if cont_match and last_system_id is not None:
        _process_continuation(systems, cont_match, last_system_id, last_metric)

    return last_system_id, last_metric


@register(OS.CISCO_IOSXE, "show isis topology")
class ShowIsisTopologyParser(BaseParser["ShowIsisTopologyResult"]):
    """Parser for 'show isis topology' command on IOS-XE.

    Parses IS-IS topology (SPF) path information showing reachability
    to all routers in the IS-IS domain. Entries are grouped by IS-IS
    tag, then by topology ID and level, then keyed by system ID and
    outgoing interface.

    Example output::

        Tag 64512:
        IS-IS TID 0 paths to level-2 routers
        System Id            Metric     Next-Hop             Interface   SNPA
        ROUTER-A             20         ROUTER-B             Te0/0/0.20 aabb.cc00.0100
                                        ROUTER-C             Te0/0/4.20 aabb.cc00.0200
        ROUTER-LOCAL         --
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
            Parsed topology data grouped by IS-IS tag, topology ID/level,
            and system ID.

        Raises:
            ValueError: If no topology tables found in output.
        """
        all_tags: dict[str, dict[str, dict[str, IsisTopologySystem]]] = {}
        current_tag: str | None = None
        current_table_key: str | None = None
        last_system_id: str | None = None
        last_metric: int = 0

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or _COLUMN_HEADER_PATTERN.match(stripped):
                continue

            tag_match = _TAG_PATTERN.match(stripped)
            if tag_match:
                current_tag = tag_match.group("tag")
                current_table_key = None
                last_system_id = None
                continue

            header_match = _TABLE_HEADER_PATTERN.match(stripped)
            if header_match and current_tag is not None:
                current_table_key = cls._table_key(header_match)
                all_tags.setdefault(current_tag, {})[current_table_key] = {}
                last_system_id = None
                continue

            if current_tag is None or current_table_key is None:
                continue

            systems = all_tags[current_tag][current_table_key]
            last_system_id, last_metric = _process_entry(
                systems, stripped, line, last_system_id, last_metric
            )

        populated = {
            k: v for k, v in all_tags.items() if any(systems for systems in v.values())
        }

        if not populated:
            msg = "No IS-IS topology tables found in output"
            raise ValueError(msg)

        result: ShowIsisTopologyResult = {"tags": populated}
        total = cls._count_paths(populated)
        if total > 0:
            result["total_path_count"] = total

        return result

    @staticmethod
    def _table_key(match: re.Match[str]) -> str:
        """Build a table key from TID and level."""
        tid = match.group("tid")
        level = match.group("level")
        return f"TID {tid} (level-{level})"

    @staticmethod
    def _count_paths(
        tags: dict[str, dict[str, dict[str, IsisTopologySystem]]],
    ) -> int:
        """Count total paths across all tags and tables."""
        total = 0
        for tables in tags.values():
            for systems in tables.values():
                for system in systems.values():
                    total += len(system["paths"])
        return total
