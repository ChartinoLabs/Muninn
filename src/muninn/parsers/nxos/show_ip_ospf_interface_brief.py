"""Parser for 'show ip ospf interface brief' command on NX-OS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class OspfInterfaceBriefEntry(TypedDict):
    """Schema for a single NX-OS OSPF interface brief entry."""

    process_id: str
    vrf: str
    interface_id: int
    area: str
    cost: int
    state: str
    neighbors: int
    status: str


class ShowIpOspfInterfaceBriefResult(TypedDict):
    """Schema for 'show ip ospf interface brief' parsed output."""

    interfaces: dict[str, OspfInterfaceBriefEntry]


# --- Process ID / VRF header line ---
_PROCESS_RE = re.compile(r"^\s*OSPF Process ID (\S+) VRF (\S+)\s*$")

# --- Interface data line ---
_INTF_RE = re.compile(r"^\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s*$")

# --- Header line (skip) ---
_HEADER_RE = re.compile(
    r"^\s+Interface\s+ID\s+Area\s+Cost\s+State\s+Neighbors\s+Status"
)

# --- Total number line (skip) ---
_TOTAL_RE = re.compile(r"^\s+Total number of interface:\s*\d+")


@register(OS.CISCO_NXOS, "show ip ospf interface brief")
class ShowIpOspfInterfaceBriefParser(BaseParser[ShowIpOspfInterfaceBriefResult]):
    """Parser for 'show ip ospf interface brief' on NX-OS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfInterfaceBriefResult:
        """Parse 'show ip ospf interface brief' output."""
        interfaces: dict[str, OspfInterfaceBriefEntry] = {}
        current_process: str | None = None
        current_vrf: str | None = None

        for line in output.splitlines():
            m = _PROCESS_RE.match(line)
            if m:
                current_process = m.group(1)
                current_vrf = m.group(2)
                continue

            if _HEADER_RE.match(line) or _TOTAL_RE.match(line):
                continue

            m = _INTF_RE.match(line)
            if m and current_process is not None and current_vrf is not None:
                raw_name = m.group(1)
                name = canonical_interface_name(raw_name, os=OS.CISCO_NXOS)
                interfaces[name] = {
                    "process_id": current_process,
                    "vrf": current_vrf,
                    "interface_id": int(m.group(2)),
                    "area": m.group(3),
                    "cost": int(m.group(4)),
                    "state": m.group(5),
                    "neighbors": int(m.group(6)),
                    "status": m.group(7),
                }

        return {"interfaces": interfaces}
