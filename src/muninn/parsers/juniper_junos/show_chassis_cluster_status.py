"""Parser for 'show chassis cluster status' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Sentinel values that mean "no data" in chassis cluster output.
_NO_VALUE_SENTINELS = frozenset({"n/a", "N/A", "none", "None", "NONE"})


class RedundancyGroupNode(TypedDict):
    """Schema for a node within a redundancy group."""

    priority: int
    status: str
    preempt: NotRequired[bool]
    manual_failover: NotRequired[bool]
    monitor_failures: NotRequired[list[str]]


class RedundancyGroup(TypedDict):
    """Schema for a single redundancy group."""

    failover_count: int
    nodes: dict[str, RedundancyGroupNode]


class ShowChassisClusterStatusResult(TypedDict):
    """Schema for 'show chassis cluster status' parsed output.

    Captures cluster ID and redundancy group details including per-node
    priority, status, preempt, manual failover, and monitor failure codes.
    """

    cluster_id: int
    redundancy_groups: dict[str, RedundancyGroup]


@register(OS.JUNIPER_JUNOS, "show chassis cluster status")
class ShowChassisClusterStatusParser(
    BaseParser[ShowChassisClusterStatusResult],
):
    """Parser for 'show chassis cluster status' command on Juniper Junos.

    Parses cluster membership, redundancy groups, and per-node status
    from SRX chassis cluster output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    _CLUSTER_ID = re.compile(r"^Cluster\s+ID:\s+(?P<id>\d+)")
    _RG_HEADER = re.compile(
        r"^Redundancy\s+group:\s+(?P<group>\d+)\s*,\s*"
        r"Failover\s+count:\s+(?P<failover>\d+)",
    )
    _NODE_LINE = re.compile(
        r"^(?P<node>node\d+)\s+"
        r"(?P<priority>\d+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<preempt>\S+)\s+"
        r"(?P<manual>\S+)\s+"
        r"(?P<monitor>.+)$",
    )

    @classmethod
    def _parse_bool_field(cls, value: str) -> bool | None:
        """Parse a yes/no field, returning None for sentinel values."""
        if value in _NO_VALUE_SENTINELS:
            return None
        return value.lower() == "yes"

    @classmethod
    def _parse_monitor_failures(cls, value: str) -> list[str] | None:
        """Parse monitor failure codes, returning None for sentinel values."""
        stripped = value.strip()
        if stripped in _NO_VALUE_SENTINELS:
            return None
        return stripped.split()

    @classmethod
    def _build_node(cls, match: re.Match[str]) -> RedundancyGroupNode:
        """Build a RedundancyGroupNode from a regex match."""
        node = RedundancyGroupNode(
            priority=int(match.group("priority")),
            status=match.group("status"),
        )

        preempt = cls._parse_bool_field(match.group("preempt"))
        if preempt is not None:
            node["preempt"] = preempt

        manual = cls._parse_bool_field(match.group("manual"))
        if manual is not None:
            node["manual_failover"] = manual

        failures = cls._parse_monitor_failures(match.group("monitor"))
        if failures is not None:
            node["monitor_failures"] = failures

        return node

    @classmethod
    def parse(cls, output: str) -> ShowChassisClusterStatusResult:
        """Parse 'show chassis cluster status' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed cluster status information.

        Raises:
            ValueError: If cluster ID or redundancy group data is missing.
        """
        cluster_id: int | None = None
        redundancy_groups: dict[str, RedundancyGroup] = {}
        current_group: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := cls._CLUSTER_ID.match(stripped):
                cluster_id = int(match.group("id"))
                continue

            if match := cls._RG_HEADER.match(stripped):
                current_group = match.group("group")
                redundancy_groups[current_group] = RedundancyGroup(
                    failover_count=int(match.group("failover")),
                    nodes={},
                )
                continue

            if current_group is not None and (match := cls._NODE_LINE.match(stripped)):
                node = cls._build_node(match)
                redundancy_groups[current_group]["nodes"][match.group("node")] = node

        if cluster_id is None:
            msg = "No cluster ID found in output"
            raise ValueError(msg)

        if not redundancy_groups:
            msg = "No redundancy groups found in output"
            raise ValueError(msg)

        return cast(
            ShowChassisClusterStatusResult,
            {
                "cluster_id": cluster_id,
                "redundancy_groups": redundancy_groups,
            },
        )
