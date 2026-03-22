"""Parser for 'show spanning-tree root' command on IOS."""

import re
from typing import Annotated, ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.schema_doc import SchemaDoc
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

MacAddressString = Annotated[
    str,
    SchemaDoc(
        "Root bridge MAC in dotted hex (three groups of four hex digits) "
        "as in CLI output."
    ),
]

VlanIdKey = Annotated[
    str,
    SchemaDoc(
        "VLAN id as a decimal string without leading zeros, derived from the "
        "CLI VLAN label (e.g. VLAN0001 → '1')."
    ),
]

# --- Column header pattern ---
_HEADER_RE = re.compile(r"^Vlan\s+Root\s+ID\s+Cost\s+Time\s+Age\s+Dly\s+Root\s+Port")

# Data line: VLAN, priority, address, cost, hello, max age, fwd dly, port
_DATA_RE = re.compile(
    r"^(?P<vlan>\S+)\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<address>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
    r"(?P<cost>\d+)\s+"
    r"(?P<hello>\d+)\s+"
    r"(?P<max_age>\d+)\s+"
    r"(?P<fwd_delay>\d+)"
    r"(?:\s+(?P<root_port>\S+))?\s*$"
)


class RootBridgeEntry(TypedDict):
    """Schema for the root bridge identification."""

    priority: int
    address: MacAddressString


class VlanRootEntry(TypedDict):
    """Schema for a single VLAN's spanning-tree root information."""

    root_id: RootBridgeEntry
    root_cost: int
    hello_time: int
    max_age: int
    forward_delay: int
    root_port: NotRequired[
        Annotated[
            str,
            SchemaDoc(
                "Local port toward the root bridge when present; "
                "canonical IOS interface name (e.g. 'Port-channel34')."
            ),
        ]
    ]


ShowSpanningTreeRootResult = dict[VlanIdKey, VlanRootEntry]


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
            Dict keyed by VLAN ID with root bridge information.

        Raises:
            ValueError: If a data line cannot be parsed.
        """
        result: ShowSpanningTreeRootResult = {}

        for line in output.splitlines():
            match = _DATA_RE.match(line)
            if not match:
                continue

            vlan_name = match.group("vlan")
            # Extract numeric VLAN ID from names like "VLAN0001"
            vlan_match = re.match(r"VLAN(\d+)", vlan_name, re.IGNORECASE)
            if not vlan_match:
                msg = f"Cannot extract VLAN ID from: {vlan_name}"
                raise ValueError(msg)

            vlan_id = str(int(vlan_match.group(1)))

            entry: VlanRootEntry = {
                "root_id": {
                    "priority": int(match.group("priority")),
                    "address": match.group("address"),
                },
                "root_cost": int(match.group("cost")),
                "hello_time": int(match.group("hello")),
                "max_age": int(match.group("max_age")),
                "forward_delay": int(match.group("fwd_delay")),
            }

            root_port = match.group("root_port")
            if root_port:
                entry["root_port"] = canonical_interface_name(
                    root_port, os=OS.CISCO_IOS
                )

            result[vlan_id] = entry

        return result
