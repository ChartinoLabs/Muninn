"""Parser for 'show spanning-tree' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# --- Role and status normalization maps ---
_ROLE_MAP: dict[str, str] = {
    "root": "root",
    "desg": "designated",
    "altn": "alternate",
    "mstr": "master",
    "back": "backup",
}

_STATUS_MAP: dict[str, str] = {
    "fwd": "forwarding",
    "blk": "blocking",
    "lrn": "learning",
    "lis": "listening",
}


class InterfaceEntry(TypedDict):
    """Schema for a single STP interface entry."""

    name: str
    role: str
    status: str
    cost: int
    priority: int
    port_number: int
    type: str


class RootIdEntry(TypedDict):
    """Schema for the Root ID section."""

    priority: int
    address: str
    hello_time: int
    max_age: int
    forward_delay: int
    cost: NotRequired[int]
    port_number: NotRequired[int]
    port_name: NotRequired[str]


class BridgeIdEntry(TypedDict):
    """Schema for the Bridge ID section."""

    priority: int
    priority_base: int
    sys_id_ext: int
    address: str
    hello_time: int
    max_age: int
    forward_delay: int
    is_root: bool
    aging_time: NotRequired[int]


class InstanceEntry(TypedDict):
    """Schema for a single STP instance (VLAN or MST)."""

    name: str
    protocol: str
    root_id: RootIdEntry
    bridge_id: BridgeIdEntry
    interfaces: dict[str, InterfaceEntry]


class ShowSpanningTreeResult(TypedDict):
    """Schema for 'show spanning-tree' parsed output."""

    instances: dict[str, InstanceEntry]


# --- Regex patterns ---
_INSTANCE_RE = re.compile(r"^(VLAN\d+|MST\d+)\s*$")
_PROTOCOL_RE = re.compile(r"^\s*Spanning tree enabled protocol (\S+)\s*$")
_PRIORITY_RE = re.compile(r"^\s*Priority\s+(\d+)\s*$")
_PRIORITY_EXT_RE = re.compile(
    r"^\s*Priority\s+(\d+)\s+\(priority\s+(\d+)\s+sys-id-ext\s+(\d+)\)\s*$"
)
_ADDRESS_RE = re.compile(r"^\s*Address\s+([0-9a-f.]+)\s*$")
_COST_RE = re.compile(r"^\s*Cost\s+(\d+)\s*$")
_PORT_RE = re.compile(r"^\s*Port\s+(\d+)\s+\((\S+)\)\s*$")
_TIMERS_RE = re.compile(
    r"^\s*Hello Time\s+(\d+)\s+sec\s+Max Age\s+(\d+)\s+sec"
    r"\s+Forward Delay\s+(\d+)\s+sec\s*$"
)
_AGING_RE = re.compile(r"^\s*Aging Time\s+(\d+)\s+sec\s*$")
_IS_ROOT_RE = re.compile(r"^\s*This bridge is the root\s*$")
_INTF_RE = re.compile(
    r"^(\S+)\s+(Root|Desg|Altn|Mstr|Back)\s+"
    r"(FWD|BLK|LRN|LIS|BKN\*?)\s+"
    r"(\d+)\s+(\d+)\.(\d+)\s+(.+?)\s*$"
)
_SEPARATOR_RE = re.compile(r"^-{4,}")
_HEADER_RE = re.compile(r"^Interface\s+Role\s+Sts\s+Cost")


def _split_instances(output: str) -> list[tuple[str, list[str]]]:
    """Split output into per-instance blocks keyed by instance name."""
    blocks: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _INSTANCE_RE.match(line)
        if m:
            if current_name is not None:
                blocks.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = []
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        blocks.append((current_name, current_lines))

    return blocks


def _parse_root_id(lines: list[str]) -> tuple[RootIdEntry, bool]:
    """Parse Root ID section lines. Returns (root_id, is_root)."""
    root: dict = {}
    is_root = False

    for line in lines:
        m = _PRIORITY_RE.match(line)
        if m:
            root["priority"] = int(m.group(1))
            continue

        m = _ADDRESS_RE.match(line)
        if m:
            root["address"] = m.group(1)
            continue

        m = _COST_RE.match(line)
        if m:
            root["cost"] = int(m.group(1))
            continue

        m = _PORT_RE.match(line)
        if m:
            root["port_number"] = int(m.group(1))
            root["port_name"] = canonical_interface_name(m.group(2), os=OS.CISCO_IOS)
            continue

        m = _TIMERS_RE.match(line)
        if m:
            root["hello_time"] = int(m.group(1))
            root["max_age"] = int(m.group(2))
            root["forward_delay"] = int(m.group(3))
            continue

        if _IS_ROOT_RE.match(line):
            is_root = True

    return root, is_root  # type: ignore[return-value]


def _parse_bridge_id(lines: list[str], is_root: bool) -> BridgeIdEntry:
    """Parse Bridge ID section lines."""
    bridge: dict = {"is_root": is_root}

    for line in lines:
        m = _PRIORITY_EXT_RE.match(line)
        if m:
            bridge["priority"] = int(m.group(1))
            bridge["priority_base"] = int(m.group(2))
            bridge["sys_id_ext"] = int(m.group(3))
            continue

        m = _ADDRESS_RE.match(line)
        if m:
            bridge["address"] = m.group(1)
            continue

        m = _TIMERS_RE.match(line)
        if m:
            bridge["hello_time"] = int(m.group(1))
            bridge["max_age"] = int(m.group(2))
            bridge["forward_delay"] = int(m.group(3))
            continue

        m = _AGING_RE.match(line)
        if m:
            bridge["aging_time"] = int(m.group(1))

    return bridge  # type: ignore[return-value]


def _parse_interfaces(lines: list[str]) -> dict[str, InterfaceEntry]:
    """Parse the interface table section."""
    interfaces: dict[str, InterfaceEntry] = {}

    for line in lines:
        m = _INTF_RE.match(line)
        if not m:
            continue

        raw_name = m.group(1)
        name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)
        role_abbr = m.group(2).lower()
        status_abbr = m.group(3).rstrip("*").lower()

        role = _ROLE_MAP.get(role_abbr, role_abbr)
        # Handle BKN* (broken) status specially
        if m.group(3).startswith("BKN"):
            status = "broken"
        else:
            status = _STATUS_MAP.get(status_abbr, status_abbr)

        interfaces[name] = {
            "name": name,
            "role": role,
            "status": status,
            "cost": int(m.group(4)),
            "priority": int(m.group(5)),
            "port_number": int(m.group(6)),
            "type": m.group(7),
        }

    return interfaces


def _extract_section_lines(lines: list[str], start_marker: str) -> list[str]:
    """Extract lines belonging to a named section (Root ID or Bridge ID)."""
    section_lines: list[str] = []
    in_section = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(start_marker):
            in_section = True
            # The first line may have content after the marker
            remainder = stripped[len(start_marker) :].strip()
            if remainder:
                section_lines.append("  " + remainder)
            continue

        if in_section:
            # Section ends at empty line or new section header
            is_end = (
                not stripped
                or stripped.startswith("Bridge ID")
                or _HEADER_RE.match(line)
            )
            if is_end:
                break
            section_lines.append(line)

    return section_lines


def _parse_instance(name: str, lines: list[str]) -> InstanceEntry:
    """Parse a single STP instance block."""
    protocol = ""
    for line in lines:
        m = _PROTOCOL_RE.match(line)
        if m:
            protocol = m.group(1)
            break

    root_lines = _extract_section_lines(lines, "Root ID")
    bridge_lines = _extract_section_lines(lines, "Bridge ID")

    root_id, is_root = _parse_root_id(root_lines)
    bridge_id = _parse_bridge_id(bridge_lines, is_root)

    # Extract interface lines (after header/separator)
    intf_lines: list[str] = []
    past_header = False
    for line in lines:
        if past_header:
            intf_lines.append(line)
        elif _SEPARATOR_RE.match(line.strip()):
            past_header = True

    interfaces = _parse_interfaces(intf_lines)

    return {
        "name": name,
        "protocol": protocol,
        "root_id": root_id,
        "bridge_id": bridge_id,
        "interfaces": interfaces,
    }


@register(OS.CISCO_IOS, "show spanning-tree")
@register(OS.CISCO_IOSXE, "show spanning-tree")
class ShowSpanningTreeParser(BaseParser[ShowSpanningTreeResult]):
    """Parser for 'show spanning-tree' on IOS/IOS-XE."""

    @classmethod
    def parse(cls, output: str) -> ShowSpanningTreeResult:
        """Parse 'show spanning-tree' output."""
        blocks = _split_instances(output)
        instances: dict[str, InstanceEntry] = {}

        for name, block_lines in blocks:
            instances[name] = _parse_instance(name, block_lines)

        return {"instances": instances}
