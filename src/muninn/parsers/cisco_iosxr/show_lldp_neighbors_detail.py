"""Parser for 'show lldp neighbors detail' command on Cisco IOS-XR.

IOS-XR ``show lldp neighbors detail`` displays per-neighbor LLDP information
separated by dashed lines.  Each block contains the local interface, chassis
ID, port ID, port description, system name, a multi-line system description,
timers, capabilities, and management addresses.

Output is keyed by canonical local interface name.
"""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class LldpNeighborDetailEntry(TypedDict):
    """Schema for a single LLDP neighbor detail entry on IOS-XR."""

    chassis_id: str
    port_id: str
    port_description: NotRequired[str]
    system_name: NotRequired[str]
    system_description: NotRequired[str]
    time_remaining: int
    hold_time: int
    age: NotRequired[int]
    system_capabilities: NotRequired[str]
    enabled_capabilities: NotRequired[str]
    management_addresses: NotRequired[list[str]]
    peer_mac_address: NotRequired[str]


class ShowLldpNeighborsDetailResult(TypedDict):
    """Schema for 'show lldp neighbors detail' parsed output on IOS-XR."""

    neighbors: dict[str, LldpNeighborDetailEntry]
    total_entries: NotRequired[int]


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_LOCAL_INTF_RE = re.compile(r"^Local Interface:\s+(?P<v>\S+)")
_CHASSIS_ID_RE = re.compile(r"^Chassis id:\s+(?P<v>.+)$")
_PORT_ID_RE = re.compile(r"^Port id:\s+(?P<v>.+)$")
_PORT_DESC_RE = re.compile(r"^Port Description:\s+(?P<v>.+)$")
_SYS_NAME_RE = re.compile(r"^System Name:\s+(?P<v>.+)$")
_SYS_DESC_HDR_RE = re.compile(r"^System Description:\s*$")
_TIME_REMAINING_RE = re.compile(r"^Time remaining:\s+(?P<v>\d+)\s+seconds")
_HOLD_TIME_RE = re.compile(r"^Hold Time:\s+(?P<v>\d+)\s+seconds")
_AGE_RE = re.compile(r"^Age:\s+(?P<v>\d+)\s+seconds")
_SYS_CAP_RE = re.compile(r"^System Capabilities:\s+(?P<v>.+)$")
_ENA_CAP_RE = re.compile(r"^Enabled Capabilities:\s+(?P<v>.+)$")
_MGMT_ADDR_HDR_RE = re.compile(r"^Management Addresses:\s*$")
_MGMT_IPV4_RE = re.compile(r"^\s+IPv4 address:\s+(?P<v>\S+)")
_MGMT_IPV6_RE = re.compile(r"^\s+IPv6 address:\s+(?P<v>\S+)")
_PEER_MAC_RE = re.compile(r"^Peer MAC Address:\s+(?P<v>\S+)")
_TOTAL_RE = re.compile(r"^Total entries displayed:\s*(?P<v>\d+)", re.I)

# Lines to skip: timestamp, capability legend, blank
_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+",
    re.I,
)

# Interface-like pattern for port_id canonicalization
_INTERFACE_LIKE_RE = re.compile(
    r"^(?:Gi(?:gabitEthernet)?|Fa(?:stEthernet)?|Eth(?:ernet)?|"
    r"Te(?:nGigE)?|Fo(?:urHundredGigE)?|Fou|"
    r"Hu(?:ndredGigE)?|mgmt|MgmtEth|Lo(?:opback)?|"
    r"Vlan|Po(?:rt-channel)?|Tu(?:nnel)?|Se(?:rial)?|"
    r"nve|BDI|Twe(?:ntyFiveGigE)?|Bundle-Ether)\d",
    re.IGNORECASE,
)


def _normalize_capabilities(cap_str: str) -> str:
    """Normalize capability string, stripping extra whitespace."""
    return ", ".join(part.strip() for part in cap_str.split(","))


def _canonicalize_if_interface(value: str) -> str:
    """Return canonical form if value looks like an interface name."""
    if _INTERFACE_LIKE_RE.match(value):
        return canonical_interface_name(value, os=OS.CISCO_IOSXR)
    return value


def _is_noise_line(stripped: str) -> bool:
    """Return True if the line is noise (timestamp, legend, blank)."""
    if not stripped:
        return True
    if _TIMESTAMP_RE.match(stripped):
        return True
    if stripped.startswith(("Capability codes:", "(R)", "(W)")):
        return True
    return SEPARATOR_DASH_RE.match(stripped) is not None


def _collect_system_description(lines: list[str], start: int) -> tuple[str | None, int]:
    """Collect multi-line system description until Time remaining line.

    Args:
        lines: All block lines.
        start: Index of first line after the "System Description:" header.

    Returns:
        Tuple of (description_text_or_None, next_unprocessed_index).
    """
    desc_parts: list[str] = []
    idx = start
    while idx < len(lines):
        stripped = lines[idx].strip()
        if _TIME_REMAINING_RE.match(stripped):
            break
        desc_parts.append(stripped)
        idx += 1
    text = "\n".join(desc_parts).strip() or None
    return text, idx


def _collect_management_addresses(
    lines: list[str],
    start: int,
) -> tuple[list[str], int]:
    """Collect management addresses from indented lines.

    Args:
        lines: All block lines.
        start: Index of first line after the "Management Addresses:" header.

    Returns:
        Tuple of (address_list, next_unprocessed_index).
    """
    addrs: list[str] = []
    idx = start
    while idx < len(lines):
        raw = lines[idx]
        stripped = raw.strip()
        m = _MGMT_IPV4_RE.match(raw) or _MGMT_IPV6_RE.match(raw)
        if m:
            addrs.append(m.group("v"))
            idx += 1
            continue
        # Indented continuation lines belong to the address block
        if raw.startswith("  ") and stripped:
            idx += 1
            continue
        break
    return addrs, idx


_FieldTransform = str | type[int]

# Table-driven single-line field specs: (pattern, field_name, transform).
# str.strip for string fields, int for integer fields, _normalize_capabilities
# for capability fields.
_SINGLE_LINE_FIELDS: tuple[
    tuple[re.Pattern[str], str, _FieldTransform],
    ...,
] = (
    (_LOCAL_INTF_RE, "local_intf", str),
    (_CHASSIS_ID_RE, "chassis_id", str),
    (_PORT_ID_RE, "port_id", str),
    (_PORT_DESC_RE, "port_description", str),
    (_SYS_NAME_RE, "system_name", str),
    (_TIME_REMAINING_RE, "time_remaining", int),
    (_HOLD_TIME_RE, "hold_time", int),
    (_AGE_RE, "age", int),
    (_PEER_MAC_RE, "peer_mac_address", str),
)


def _try_match_single_line(
    stripped: str,
    fields: dict[str, str | int | list[str] | None],
) -> bool:
    """Try table-driven single-line patterns. Returns True if matched."""
    for pattern, key, transform in _SINGLE_LINE_FIELDS:
        m = pattern.match(stripped)
        if m:
            raw = m.group("v").strip()
            fields[key] = int(raw) if transform is int else raw
            return True

    # Capability fields need normalization
    for pattern, key in (
        (_SYS_CAP_RE, "system_capabilities"),
        (_ENA_CAP_RE, "enabled_capabilities"),
    ):
        m = pattern.match(stripped)
        if m:
            fields[key] = _normalize_capabilities(m.group("v"))
            return True

    return False


def _parse_block_line(
    lines: list[str],
    idx: int,
    fields: dict[str, str | int | list[str] | None],
) -> int:
    """Parse a single line within a neighbor block. Returns next line index."""
    stripped = lines[idx].strip()

    if not stripped:
        return idx + 1

    if _try_match_single_line(stripped, fields):
        return idx + 1

    # Multi-line System Description
    if _SYS_DESC_HDR_RE.match(stripped):
        desc, next_idx = _collect_system_description(lines, idx + 1)
        fields["system_description"] = desc
        return next_idx

    # Management Addresses block
    if _MGMT_ADDR_HDR_RE.match(stripped):
        addrs, next_idx = _collect_management_addresses(lines, idx + 1)
        if addrs:
            fields["management_addresses"] = addrs
        return next_idx

    return idx + 1


# Optional string fields to copy from parsed fields into the entry.
_OPTIONAL_STR_KEYS: tuple[str, ...] = (
    "port_description",
    "system_name",
    "system_description",
    "system_capabilities",
    "enabled_capabilities",
    "peer_mac_address",
)

_REQUIRED_KEYS: tuple[str, ...] = (
    "chassis_id",
    "port_id",
    "time_remaining",
    "hold_time",
)


def _build_entry(
    fields: dict[str, str | int | list[str] | None],
) -> tuple[str | None, LldpNeighborDetailEntry | None]:
    """Build a typed entry dict from parsed fields.

    Returns:
        Tuple of (local_interface, entry) or (None, None) if required
        fields are missing.
    """
    if any(fields.get(k) is None for k in _REQUIRED_KEYS):
        return None, None

    local_intf = fields.get("local_intf")
    canonical_local = (
        canonical_interface_name(str(local_intf), os=OS.CISCO_IOSXR)
        if local_intf is not None
        else None
    )

    entry: LldpNeighborDetailEntry = {
        "chassis_id": str(fields["chassis_id"]),
        "port_id": _canonicalize_if_interface(str(fields["port_id"])),
        "time_remaining": int(str(fields["time_remaining"])),
        "hold_time": int(str(fields["hold_time"])),
    }

    for key in _OPTIONAL_STR_KEYS:
        val = fields.get(key)
        if val is not None:
            entry[key] = str(val)  # type: ignore[literal-required]

    age = fields.get("age")
    if age is not None:
        entry["age"] = int(str(age))

    mgmt = fields.get("management_addresses")
    if mgmt:
        entry["management_addresses"] = list(mgmt)  # type: ignore[arg-type]

    return canonical_local, entry


@register(OS.CISCO_IOSXR, "show lldp neighbors detail")
class ShowLldpNeighborsDetailParser(BaseParser[ShowLldpNeighborsDetailResult]):
    """Parser for 'show lldp neighbors detail' on Cisco IOS-XR.

    Parses detailed LLDP neighbor information including chassis ID,
    port descriptions, system capabilities, and management addresses.
    Output is keyed by canonical local interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    @classmethod
    def _split_blocks(
        cls,
        output: str,
    ) -> tuple[list[list[str]], int | None]:
        """Split output into neighbor blocks separated by dashed lines.

        Returns:
            Tuple of (blocks, total_entries).
        """
        blocks: list[list[str]] = []
        current: list[str] = []
        total_entries: int | None = None

        for line in output.splitlines():
            stripped = line.strip()

            m = _TOTAL_RE.match(stripped)
            if m:
                total_entries = int(m.group("v"))

            if SEPARATOR_DASH_RE.match(stripped):
                if current:
                    blocks.append(current)
                    current = []
                continue

            if _is_noise_line(stripped):
                continue

            current.append(line)

        # Capture trailing block if it has content
        if current and any(s.strip() for s in current):
            blocks.append(current)

        return blocks, total_entries

    @classmethod
    def _parse_block(
        cls,
        lines: list[str],
    ) -> tuple[str | None, LldpNeighborDetailEntry | None]:
        """Parse a single neighbor block.

        Returns:
            Tuple of (local_interface, entry) or (None, None).
        """
        fields: dict[str, str | int | list[str] | None] = {}
        idx = 0
        while idx < len(lines):
            idx = _parse_block_line(lines, idx, fields)
        return _build_entry(fields)

    @classmethod
    def parse(cls, output: str) -> ShowLldpNeighborsDetailResult:
        """Parse 'show lldp neighbors detail' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LLDP neighbor details keyed by local interface.

        Raises:
            ValueError: If no LLDP neighbor entries found.
        """
        blocks, total_entries = cls._split_blocks(output)
        neighbors: dict[str, LldpNeighborDetailEntry] = {}

        for block in blocks:
            local_intf, entry = cls._parse_block(block)
            if local_intf is None or entry is None:
                continue
            neighbors[local_intf] = entry

        if not neighbors:
            msg = "No LLDP neighbor detail entries found in output"
            raise ValueError(msg)

        result: ShowLldpNeighborsDetailResult = {"neighbors": neighbors}
        if total_entries is not None:
            result["total_entries"] = total_entries

        return result
