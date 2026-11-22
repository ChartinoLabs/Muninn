"""Parser for 'show spanning-tree root' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class RootId(TypedDict):
    """Schema for the root bridge identifier."""

    priority: int
    address: str


class SpanningTreeRootEntry(TypedDict):
    """Schema for a single VLAN spanning-tree root entry."""

    vlan_id: int
    root_id: RootId
    root_cost: int
    hello_time: int
    max_age: int
    forward_delay: int
    root_port: NotRequired[str]
    is_root: NotRequired[bool]


class ShowSpanningTreeRootResult(TypedDict):
    """Schema for 'show spanning-tree root' parsed output."""

    vlans: dict[str, SpanningTreeRootEntry]


# VLAN0001             1 1211.a111.1111       0    2   20  10  This bridge is root
# VLAN0002            10 1211.a111.1112       3    2   20  10    port-channel10
_VLAN_LINE_PATTERN = re.compile(
    r"^VLAN(?P<vlan_id>\d+)"
    r"\s+(?P<priority>\d+)"
    rf"\s+(?P<address>{MAC_ADDRESS})"
    r"\s+(?P<cost>\d+)"
    r"\s+(?P<hello>\d+)"
    r"\s+(?P<max_age>\d+)"
    r"\s+(?P<fwd_delay>\d+)"
    r"\s+(?P<root_port>.+)$"
)

_THIS_BRIDGE_IS_ROOT = "This bridge is root"


@register(OS.CISCO_NXOS, "show spanning-tree root")
class ShowSpanningTreeRootParser(BaseParser[ShowSpanningTreeRootResult]):
    """Parser for 'show spanning-tree root' command on NX-OS.

    Parses spanning-tree root bridge information per VLAN, including
    root priority, address, cost, timers, and root port.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.STP,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowSpanningTreeRootResult:
        """Parse 'show spanning-tree root' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed spanning-tree root entries keyed by VLAN ID string.

        Raises:
            ValueError: If no spanning-tree root entries found in output.
        """
        vlans: dict[str, SpanningTreeRootEntry] = {}

        for line in output.splitlines():
            match = _VLAN_LINE_PATTERN.match(line.strip())
            if not match:
                continue

            vlan_id_str = match.group("vlan_id")
            root_port_raw = match.group("root_port").strip()

            entry: SpanningTreeRootEntry = {
                "vlan_id": int(vlan_id_str),
                "root_id": RootId(
                    priority=int(match.group("priority")),
                    address=match.group("address"),
                ),
                "root_cost": int(match.group("cost")),
                "hello_time": int(match.group("hello")),
                "max_age": int(match.group("max_age")),
                "forward_delay": int(match.group("fwd_delay")),
            }

            if root_port_raw == _THIS_BRIDGE_IS_ROOT:
                entry["is_root"] = True
            else:
                entry["root_port"] = canonical_interface_name(
                    root_port_raw, os=OS.CISCO_NXOS
                )

            vlans[vlan_id_str] = entry

        if not vlans:
            msg = "No spanning-tree root entries found in output"
            raise ValueError(msg)

        return ShowSpanningTreeRootResult(vlans=vlans)
