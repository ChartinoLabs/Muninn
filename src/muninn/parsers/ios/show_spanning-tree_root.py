"""Parser for 'show spanning-tree root' command on IOS."""

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
    """Schema for 'show spanning-tree root' parsed output on IOS."""

    vlans: dict[str, SpanningTreeRootEntry]


# Data line: VLAN name, priority, MAC, cost, hello, max age, fwd dly, optional root port
_DATA_RE = re.compile(
    r"^(?P<vlan>VLAN\d+)\s+"
    r"(?P<priority>\d+)\s+"
    rf"(?P<address>{MAC_ADDRESS})\s+"
    r"(?P<cost>\d+)\s+"
    r"(?P<hello>\d+)\s+"
    r"(?P<max_age>\d+)\s+"
    r"(?P<fwd_delay>\d+)"
    r"(?:\s+(?P<root_port>\S+))?\s*$",
    re.IGNORECASE,
)


@register(OS.CISCO_IOS, "show spanning-tree root")
class ShowSpanningTreeRootParser(BaseParser[ShowSpanningTreeRootResult]):
    """Parser for 'show spanning-tree root' on IOS.

    Example output::

                                            Root    Hello Max Fwd
        Vlan                   Root ID          Cost    Time  Age Dly  Root Port
        ---------------- -------------------- --------- ----- --- ---  ------------
        VLAN0001         11175 5c6e.f0a7.a0b0         0    2   20  15
        VLAN0002         11185 5c6e.f0a7.a0b0         0    2   20  15
        VLAN0003         11195 5c6e.f0a7.a0b0         0    2   20  15  Po34
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.STP,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowSpanningTreeRootResult:
        """Parse 'show spanning-tree root' output.

        Args:
            output: Raw CLI output from 'show spanning-tree root' command.

        Returns:
            Parsed spanning-tree root entries keyed by VLAN ID string (digits
            from the ``VLAN####`` name, preserving leading zeros).

        Raises:
            ValueError: If no spanning-tree root entries found in output.
        """
        vlans: dict[str, SpanningTreeRootEntry] = {}

        for line in output.splitlines():
            match = _DATA_RE.match(line.strip())
            if not match:
                continue

            vlan_name = match.group("vlan")
            vlan_digits = re.match(r"VLAN(?P<vid>\d+)", vlan_name, re.IGNORECASE)
            if not vlan_digits:
                msg = f"Cannot extract VLAN ID from: {vlan_name}"
                raise ValueError(msg)

            vlan_id_str = vlan_digits.group("vid")

            entry: SpanningTreeRootEntry = {
                "vlan_id": int(vlan_id_str),
                "root_id": RootId(
                    priority=int(match.group("priority")),
                    address=match.group("address").lower(),
                ),
                "root_cost": int(match.group("cost")),
                "hello_time": int(match.group("hello")),
                "max_age": int(match.group("max_age")),
                "forward_delay": int(match.group("fwd_delay")),
            }

            root_port_raw = match.group("root_port")
            if root_port_raw:
                entry["root_port"] = canonical_interface_name(
                    root_port_raw, os=OS.CISCO_IOS
                )
            else:
                entry["is_root"] = True

            vlans[vlan_id_str] = entry

        if not vlans:
            msg = "No spanning-tree root entries found in output"
            raise ValueError(msg)

        return ShowSpanningTreeRootResult(vlans=vlans)
