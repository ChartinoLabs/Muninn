"""Parser for 'show install active' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NodeInfo(TypedDict):
    """Schema for a single node's install information."""

    node_type: str
    boot_partition: NotRequired[str]
    active_packages: list[str]


class ShowInstallActiveResult(TypedDict):
    """Schema for 'show install active' parsed output on IOS-XR.

    Top-level keys:
        label: The software label (e.g. "7.3.2").
        nodes: Dict keyed by node location (e.g. "0/RP0/CPU0") mapping to
            node details including type, boot partition, and active packages.
    """

    label: NotRequired[str]
    nodes: dict[str, NodeInfo]


@register(OS.CISCO_IOSXR, "show install active")
class ShowInstallActiveParser(BaseParser[ShowInstallActiveResult]):
    """Parser for 'show install active' command on Cisco IOS-XR.

    Parses the active installed packages per node/location, including
    the software label, boot partition, and package list for each node.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _LABEL = re.compile(r"^Label\s*:\s*(?P<label>\S+)")
    _NODE = re.compile(r"^Node\s+(?P<location>\S+)\s+\[(?P<node_type>[^\]]+)\]")
    _BOOT_PARTITION = re.compile(r"^\s+Boot Partition:\s+(?P<partition>\S+)")
    _ACTIVE_PACKAGES_COUNT = re.compile(r"^\s+Active Packages:\s+\d+")
    _PACKAGE = re.compile(r"^\s{8}(?P<package>.+\S)")

    @classmethod
    def _parse_node_line(
        cls,
        line: str,
        current_node: str | None,
        nodes: dict[str, NodeInfo],
        in_packages: bool,
    ) -> tuple[str | None, bool]:
        """Parse a line within a node block, updating node state.

        Returns:
            Tuple of (current_node, in_packages) after processing the line.
        """
        if match := cls._BOOT_PARTITION.match(line):
            if current_node is not None:
                nodes[current_node]["boot_partition"] = match.group("partition")
            return current_node, in_packages

        if cls._ACTIVE_PACKAGES_COUNT.match(line):
            return current_node, True

        if in_packages and current_node is not None:
            if match := cls._PACKAGE.match(line):
                nodes[current_node]["active_packages"].append(match.group("package"))

        return current_node, in_packages

    @classmethod
    def parse(cls, output: str) -> ShowInstallActiveResult:
        """Parse 'show install active' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed install information with nodes and their active packages.

        Raises:
            ValueError: If no node information can be parsed.
        """
        label: str | None = None
        nodes: dict[str, NodeInfo] = {}
        current_node: str | None = None
        in_packages = False

        for line in output.splitlines():
            if not line.strip():
                in_packages = False
                continue

            if match := cls._LABEL.match(line):
                label = match.group("label")
                continue

            if match := cls._NODE.match(line):
                current_node = match.group("location")
                nodes[current_node] = NodeInfo(
                    node_type=match.group("node_type"),
                    active_packages=[],
                )
                in_packages = False
                continue

            current_node, in_packages = cls._parse_node_line(
                line, current_node, nodes, in_packages
            )

        if not nodes:
            msg = "No node information found in output"
            raise ValueError(msg)

        result = ShowInstallActiveResult(nodes=nodes)
        if label is not None:
            result["label"] = label
        return result
