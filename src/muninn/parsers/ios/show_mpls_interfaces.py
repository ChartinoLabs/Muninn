"""Parser for 'show mpls interfaces' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MplsInterfaceEntry(TypedDict):
    """Schema for a single MPLS interface entry."""

    ip_enabled: bool
    ip_protocol: NotRequired[str]
    tunnel: bool
    bgp: bool
    static: bool
    operational: bool


class ShowMplsInterfacesResult(TypedDict):
    """Schema for 'show mpls interfaces' parsed output."""

    interfaces: dict[str, MplsInterfaceEntry]


# Data row: interface, Yes/No (optional protocol), four Yes/No fields
_ROW_RE = re.compile(
    r"^(\S+)\s+"
    r"(Yes|No)\s*(?:\((\S+)\))?\s+"
    r"(Yes|No)\s+"
    r"(Yes|No)\s+"
    r"(Yes|No)\s+"
    r"(Yes|No)\s*$",
    re.IGNORECASE,
)


def _to_bool(value: str) -> bool:
    """Convert Yes/No string to boolean."""
    return value.strip().lower() == "yes"


@register(OS.CISCO_IOS, "show mpls interfaces")
class ShowMplsInterfacesParser(BaseParser[ShowMplsInterfacesResult]):
    """Parser for 'show mpls interfaces' on IOS.

    Parses the tabular output into a dict keyed by canonical interface name.

    Example output::

        Interface              IP            Tunnel   BGP Static Operational
        TenGigabitEthernet1/1  Yes (ldp)     No       No  No     Yes
        Vlan101                Yes (ldp)     No       No  No     Yes
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> ShowMplsInterfacesResult:
        """Parse 'show mpls interfaces' output."""
        interfaces: dict[str, MplsInterfaceEntry] = {}

        for line in output.splitlines():
            m = _ROW_RE.match(line)
            if not m:
                continue

            raw_name = m.group(1)
            name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)

            entry: MplsInterfaceEntry = {
                "ip_enabled": _to_bool(m.group(2)),
                "tunnel": _to_bool(m.group(4)),
                "bgp": _to_bool(m.group(5)),
                "static": _to_bool(m.group(6)),
                "operational": _to_bool(m.group(7)),
            }

            # Only include protocol when IP is enabled and a protocol is specified
            protocol = m.group(3)
            if protocol:
                entry["ip_protocol"] = protocol

            interfaces[name] = entry

        return {"interfaces": interfaces}
