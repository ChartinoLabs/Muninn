"""Parser for 'show ip ospf interface' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class OspfInterfaceEntry(TypedDict):
    """Schema for a single NX-OS OSPF interface entry."""

    status: str
    line_protocol: str
    ip_address: str
    process_id: str
    vrf: str
    area: str
    state: str
    network_type: str
    cost: int
    index: int
    unnumbered_interface: NotRequired[str]
    enabled_by_interface_config: NotRequired[bool]
    passive: NotRequired[bool]
    bfd_enabled: NotRequired[bool]
    transmit_delay: NotRequired[int]
    router_priority: NotRequired[int]
    dr_router_id: NotRequired[str]
    dr_address: NotRequired[str]
    bdr_router_id: NotRequired[str]
    bdr_address: NotRequired[str]
    neighbors: NotRequired[int]
    flooding_to: NotRequired[int]
    adjacent_with: NotRequired[int]
    hello_interval: NotRequired[int]
    dead_interval: NotRequired[int]
    wait_interval: NotRequired[int]
    retransmit_interval: NotRequired[int]
    hello_timer_due: NotRequired[str]
    authentication: NotRequired[str]
    authentication_keychain: NotRequired[str]
    authentication_key_id: NotRequired[int]
    opaque_link_lsas: NotRequired[int]
    opaque_link_lsas_checksum: NotRequired[str]


class ShowIpOspfInterfaceResult(TypedDict):
    """Schema for 'show ip ospf interface' parsed output."""

    interfaces: dict[str, OspfInterfaceEntry]


# --- Interface status line ---
_STATUS_RE = re.compile(r"^\s*(\S+) is (.+?),\s*line protocol is (\S+)\s*$")

# --- IP address (separate line) ---
_IP_ADDR_RE = re.compile(r"^\s+IP address (\S+)\s*$")

# --- Unnumbered interface ---
_UNNUMBERED_RE = re.compile(
    r"^\s+Unnumbered interface using IP address of (\S+)\s+\((\S+)\)\s*$"
)

# --- Process ID / VRF / Area (separate line) ---
_PROCESS_RE = re.compile(r"^\s+Process ID (\S+) VRF (\S+),\s*area (\S+)\s*$")

# --- Combined IP + Process line (golden_output_2 format) ---
_IP_PROCESS_RE = re.compile(
    r"^\s+IP address (\S+),\s*Process ID (\S+) VRF (\S+),\s*area (\S+)\s*$"
)

# --- State / Network type / Cost ---
_STATE_RE = re.compile(r"^\s+State (\S+),\s*Network type (\S+),\s*cost (\d+)\s*$")

# --- Index line with optional Transmit delay and Router Priority ---
_INDEX_FULL_RE = re.compile(
    r"^\s+Index (\d+),\s*Transmit delay (\d+) sec"
    r"(?:,\s*Router Priority (\d+))?\s*$"
)

# --- Index line for loopback (just index) ---
_INDEX_SIMPLE_RE = re.compile(r"^\s+Index (\d+)\s*$")

# --- Index line with Passive interface ---
_INDEX_PASSIVE_RE = re.compile(r"^\s+Index (\d+),\s*Passive interface\s*$")

# --- DR / BDR ---
_DR_RE = re.compile(r"^\s+Designated Router ID:\s*(\S+),\s*address:\s*(\S+)\s*$")
_BDR_RE = re.compile(
    r"^\s+Backup Designated Router ID:\s*(\S+),\s*address:\s*(\S+)\s*$"
)

# --- Neighbors / flooding / adjacent ---
_NEIGHBORS_RE = re.compile(
    r"^\s+(\d+) Neighbors,\s*flooding to (\d+),\s*adjacent with (\d+)\s*$"
)

# --- Timer intervals ---
_TIMERS_RE = re.compile(
    r"^\s+Timer intervals:\s*Hello (\d+),\s*Dead (\d+),"
    r"\s*Wait (\d+),\s*Retransmit (\d+)\s*$"
)

# --- Hello timer due ---
_HELLO_DUE_RE = re.compile(r"^\s+Hello timer due in (\S+)\s*$")

# --- Authentication ---
_NO_AUTH_RE = re.compile(r"^\s+No authentication\s*$")
_SIMPLE_AUTH_RE = re.compile(
    r"^\s+Simple authentication, using keychain (\S+)\s*\(.*\)\s*$"
)
_MD_AUTH_RE = re.compile(r"^\s+Message-digest authentication, using key id (\d+)\s*$")

# --- Opaque link LSAs ---
_OPAQUE_RE = re.compile(
    r"^\s+Number of opaque link LSAs:\s*(\d+),\s*checksum sum (\S+)\s*$"
)

# --- BFD ---
_BFD_RE = re.compile(r"^\s+BFD is enabled\s*$")

# --- Enabled by interface configuration ---
_ENABLED_RE = re.compile(r"^\s+Enabled by interface configuration\s*$")


def _normalize_area(area: str) -> str:
    """Normalize area to dotted notation. '0' -> '0.0.0.0', '1' -> '0.0.0.1'."""
    if "." in area:
        return area
    num = int(area)
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"


def _split_blocks(output: str) -> list[tuple[str, list[str]]]:
    """Split output into per-interface blocks based on status lines."""
    blocks: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _STATUS_RE.match(line)
        if m:
            if current_name is not None:
                blocks.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = [line]
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        blocks.append((current_name, current_lines))

    return blocks


def _parse_status(line: str) -> dict:
    """Parse the interface status line."""
    m = _STATUS_RE.match(line)
    if not m:
        return {}
    return {"status": m.group(2).strip(), "line_protocol": m.group(3)}


def _parse_address_and_process(lines: list[str], entry: dict) -> None:
    """Parse IP address, unnumbered, and process/VRF/area fields."""
    for line in lines:
        m = _IP_PROCESS_RE.match(line)
        if m:
            entry["ip_address"] = m.group(1)
            entry["process_id"] = m.group(2)
            entry["vrf"] = m.group(3)
            entry["area"] = _normalize_area(m.group(4))
            continue

        m = _UNNUMBERED_RE.match(line)
        if m:
            entry["unnumbered_interface"] = canonical_interface_name(
                m.group(1), os=OS.CISCO_NXOS
            )
            entry["ip_address"] = m.group(2)
            continue

        m = _IP_ADDR_RE.match(line)
        if m:
            entry["ip_address"] = m.group(1)
            continue

        m = _PROCESS_RE.match(line)
        if m:
            entry["process_id"] = m.group(1)
            entry["vrf"] = m.group(2)
            entry["area"] = _normalize_area(m.group(3))


def _parse_state_and_index(lines: list[str], entry: dict) -> None:
    """Parse state, network type, cost, index, and transmit delay."""
    for line in lines:
        m = _STATE_RE.match(line)
        if m:
            entry["state"] = m.group(1)
            entry["network_type"] = m.group(2)
            entry["cost"] = int(m.group(3))
            continue

        m = _INDEX_PASSIVE_RE.match(line)
        if m:
            entry["index"] = int(m.group(1))
            entry["passive"] = True
            continue

        m = _INDEX_FULL_RE.match(line)
        if m:
            entry["index"] = int(m.group(1))
            entry["transmit_delay"] = int(m.group(2))
            if m.group(3) is not None:
                entry["router_priority"] = int(m.group(3))
            continue

        m = _INDEX_SIMPLE_RE.match(line)
        if m:
            entry["index"] = int(m.group(1))


def _parse_dr_bdr(lines: list[str], entry: dict) -> None:
    """Parse designated router and backup designated router."""
    for line in lines:
        m = _DR_RE.match(line)
        if m:
            entry["dr_router_id"] = m.group(1)
            entry["dr_address"] = m.group(2)
            continue

        m = _BDR_RE.match(line)
        if m:
            entry["bdr_router_id"] = m.group(1)
            entry["bdr_address"] = m.group(2)


def _parse_neighbors_and_timers(lines: list[str], entry: dict) -> None:
    """Parse neighbor counts, timer intervals, and hello timer."""
    for line in lines:
        m = _NEIGHBORS_RE.match(line)
        if m:
            entry["neighbors"] = int(m.group(1))
            entry["flooding_to"] = int(m.group(2))
            entry["adjacent_with"] = int(m.group(3))
            continue

        m = _TIMERS_RE.match(line)
        if m:
            entry["hello_interval"] = int(m.group(1))
            entry["dead_interval"] = int(m.group(2))
            entry["wait_interval"] = int(m.group(3))
            entry["retransmit_interval"] = int(m.group(4))
            continue

        m = _HELLO_DUE_RE.match(line)
        if m:
            entry["hello_timer_due"] = m.group(1)


def _parse_auth(lines: list[str], entry: dict) -> None:
    """Parse authentication configuration."""
    for line in lines:
        if _NO_AUTH_RE.match(line):
            entry["authentication"] = "none"
            continue

        m = _SIMPLE_AUTH_RE.match(line)
        if m:
            entry["authentication"] = "simple"
            entry["authentication_keychain"] = m.group(1)
            continue

        m = _MD_AUTH_RE.match(line)
        if m:
            entry["authentication"] = "message-digest"
            entry["authentication_key_id"] = int(m.group(1))


def _parse_features(lines: list[str], entry: dict) -> None:
    """Parse BFD, enabled-by-interface, and opaque LSA fields."""
    for line in lines:
        if _BFD_RE.match(line):
            entry["bfd_enabled"] = True
            continue

        if _ENABLED_RE.match(line):
            entry["enabled_by_interface_config"] = True
            continue

        m = _OPAQUE_RE.match(line)
        if m:
            entry["opaque_link_lsas"] = int(m.group(1))
            entry["opaque_link_lsas_checksum"] = m.group(2)


def _parse_block(lines: list[str]) -> OspfInterfaceEntry | None:
    """Parse a single interface block into a structured entry."""
    if not lines:
        return None

    entry: dict = _parse_status(lines[0])
    if not entry:
        return None

    body = lines[1:]
    _parse_address_and_process(body, entry)
    _parse_state_and_index(body, entry)
    _parse_dr_bdr(body, entry)
    _parse_neighbors_and_timers(body, entry)
    _parse_auth(body, entry)
    _parse_features(body, entry)

    return entry  # type: ignore[return-value]


def _normalize_interface_name(raw_name: str) -> str:
    """Normalize interface name, handling sham-links and virtual-links."""
    # SL/VL names like "SL1-0.0.0.0-10.151.22.22-10.229.11.11" should not
    # be passed through canonical_interface_name
    if raw_name.startswith(("SL", "VL")):
        return raw_name
    return canonical_interface_name(raw_name, os=OS.CISCO_NXOS)


@register(OS.CISCO_NXOS, "show ip ospf interface")
class ShowIpOspfInterfaceParser(BaseParser[ShowIpOspfInterfaceResult]):
    """Parser for 'show ip ospf interface' on NX-OS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfInterfaceResult:
        """Parse 'show ip ospf interface' output."""
        blocks = _split_blocks(output)
        interfaces: dict[str, OspfInterfaceEntry] = {}

        for raw_name, block_lines in blocks:
            parsed = _parse_block(block_lines)
            if parsed is None:
                continue
            name = _normalize_interface_name(raw_name)
            interfaces[name] = parsed

        return {"interfaces": interfaces}
