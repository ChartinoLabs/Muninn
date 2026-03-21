"""Parser for 'show lldp neighbors detail' command on IOS."""

import re
from typing import ClassVar, Literal, NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag

_NOT_ADVERTISED = "- not advertised"

_INTERFACE_RE = re.compile(
    r"^(?:Gi(?:gabitEthernet)?|Fa(?:stEthernet)?|Eth(?:ernet)?|"
    r"Te(?:nGigabitEthernet)?|Fo(?:rtyGigabitEthernet)?|"
    r"Hu(?:ndredGigE)?|mgmt|Management|Lo(?:opback)?|"
    r"Vlan|Po(?:rt-channel)?|Tu(?:nnel)?|Se(?:rial)?|"
    r"nve|BDI|Twe(?:ntyFiveGigE)?)\d",
    re.IGNORECASE,
)


OptionalStrField = Literal[
    "port_description",
    "system_name",
    "system_description",
    "system_capabilities",
    "enabled_capabilities",
]


def _canonicalize_if_interface(value: str) -> str:
    """Return canonical form if value looks like an interface name."""
    if _INTERFACE_RE.match(value):
        return canonical_interface_name(value)
    return value


# Key prefixes that may have "- not advertised" appended
_OPTIONAL_FIELD_PREFIXES = (
    "Port Description",
    "System Name",
    "System Capabilities",
    "Enabled Capabilities",
    "Management Addresses",
)


class LldpNeighborDetailEntry(TypedDict):
    """Schema for a single LLDP neighbor detail entry."""

    chassis_id: str
    port_id: str
    port_description: NotRequired[str]
    system_name: NotRequired[str]
    system_description: NotRequired[str]
    time_remaining: int
    system_capabilities: NotRequired[str]
    enabled_capabilities: NotRequired[str]
    management_addresses: NotRequired[list[str]]


class ShowLldpNeighborsDetailResult(TypedDict):
    """Schema for 'show lldp neighbors detail' parsed output."""

    neighbors: dict[str, dict[str, dict[str, LldpNeighborDetailEntry]]]
    total_entries: NotRequired[int]


def _is_not_advertised(line: str) -> bool:
    """Check if a line indicates a field is not advertised."""
    return _NOT_ADVERTISED in line


def _outer_neighbor_key(local_intf: str | None, port_id_raw: str) -> str:
    """Top-level key: canonical local interface, or port id when local is absent."""
    if local_intf is not None:
        return canonical_interface_name(local_intf)
    return _canonicalize_if_interface(port_id_raw)


def _build_entry(
    fields: dict[str, str | int | list[str] | None],
) -> LldpNeighborDetailEntry | None:
    """Build a typed entry dict from parsed fields.

    Returns None if required fields are missing.
    """
    chassis_id = fields.get("chassis_id")
    port_id = fields.get("port_id")
    time_remaining = fields.get("time_remaining")

    if chassis_id is None or port_id is None or time_remaining is None:
        return None

    entry: LldpNeighborDetailEntry = {
        "chassis_id": str(chassis_id),
        "port_id": _canonicalize_if_interface(str(port_id)),
        "time_remaining": int(time_remaining),  # type: ignore[arg-type]
    }

    _optional_str_fields: tuple[OptionalStrField, ...] = (
        "port_description",
        "system_name",
        "system_description",
        "system_capabilities",
        "enabled_capabilities",
    )
    for key in _optional_str_fields:
        val = fields.get(key)
        if val is not None:
            entry[key] = _canonicalize_if_interface(str(val))

    mgmt = fields.get("management_addresses")
    if mgmt:
        entry["management_addresses"] = mgmt  # type: ignore[assignment]

    return entry


@register(OS.CISCO_IOS, "show lldp neighbors detail")
class ShowLldpNeighborsDetailParser(
    BaseParser[ShowLldpNeighborsDetailResult],
):
    """Parser for 'show lldp neighbors detail' command on IOS.

    Parses detailed LLDP neighbor information including system name,
    description, capabilities, and management addresses.

    Output ``neighbors`` is a mapping from a natural identifier to each entry:
    canonical local interface when ``Local Intf`` is present; otherwise the
    remote port id (canonicalized when it looks like an interface name). If the
    base key would collide, ``::<chassis_id>`` is appended (then ``#N`` if
    needed).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    _SEPARATOR = SEPARATOR_DASH_RE
    _LOCAL_INTF = re.compile(r"^Local Intf:\s+(?P<v>\S+)")
    _CHASSIS_ID = re.compile(r"^Chassis id:\s+(?P<v>.+)$")
    _PORT_ID = re.compile(r"^Port id:\s+(?P<v>.+)$")
    _PORT_DESC = re.compile(r"^Port Description:\s+(?P<v>.+)$")
    _SYS_NAME = re.compile(r"^System Name:\s+(?P<v>.+)$")
    _SYS_DESC_HDR = re.compile(r"^System Description:\s*$")
    _SYS_DESC_NA = re.compile(
        r"^System Description " + re.escape(_NOT_ADVERTISED) + r"$",
    )
    _TIME_REM = re.compile(
        r"^Time remaining:\s+(?P<v>\d+)\s+seconds",
    )
    _SYS_CAP = re.compile(r"^System Capabilities:\s+(?P<v>.+)$")
    _ENA_CAP = re.compile(r"^Enabled Capabilities:\s+(?P<v>.+)$")
    _MGMT_HDR = re.compile(r"^Management Addresses:\s*$")
    _MGMT_IP = re.compile(r"^\s+(?:IP|IPV6):\s+(?P<v>\S+)")
    _TOTAL = re.compile(
        r"^Total entries displayed:\s*(?P<total>\d+)",
        re.I,
    )

    @classmethod
    def _collect_sys_description(
        cls,
        lines: list[str],
        start: int,
    ) -> tuple[str | None, int]:
        """Collect multi-line system description.

        Args:
            lines: All block lines.
            start: Index of first line after the header.

        Returns:
            Tuple of (description_text, index_of_next_unprocessed).
        """
        desc_parts: list[str] = []
        idx = start
        while idx < len(lines):
            stripped = lines[idx].strip()
            if cls._TIME_REM.match(stripped):
                break
            desc_parts.append(stripped)
            idx += 1
        text = "\n".join(desc_parts).strip() or None
        return text, idx

    @classmethod
    def _collect_mgmt_addresses(
        cls,
        lines: list[str],
        start: int,
    ) -> tuple[list[str], int]:
        """Collect management addresses from indented lines.

        Args:
            lines: All block lines.
            start: Index of first line after the header.

        Returns:
            Tuple of (address_list, index_of_next_unprocessed).
        """
        addrs: list[str] = []
        idx = start
        while idx < len(lines):
            raw = lines[idx]
            m = cls._MGMT_IP.match(raw)
            if m:
                addrs.append(m.group("v"))
                idx += 1
                continue
            # Indented continuation (OID lines, etc.)
            if raw.startswith("    ") or raw.startswith("\t"):
                idx += 1
                continue
            break
        return addrs, idx

    @classmethod
    def _parse_simple_fields(
        cls,
        stripped: str,
        fields: dict[str, str | int | list[str] | None],
    ) -> bool:
        """Try to match simple single-line fields.

        Returns True if the line was consumed.
        """
        simple_patterns = (
            (cls._LOCAL_INTF, "local_intf"),
            (cls._CHASSIS_ID, "chassis_id"),
            (cls._PORT_ID, "port_id"),
            (cls._PORT_DESC, "port_description"),
            (cls._SYS_NAME, "system_name"),
            (cls._SYS_CAP, "system_capabilities"),
            (cls._ENA_CAP, "enabled_capabilities"),
        )
        for pattern, key in simple_patterns:
            m = pattern.match(stripped)
            if m:
                fields[key] = m.group("v").strip()
                return True
        return False

    @classmethod
    def _is_skippable(cls, stripped: str) -> bool:
        """Return True if the line should be skipped entirely."""
        if not stripped:
            return True
        if cls._SYS_DESC_NA.match(stripped):
            return True
        return any(
            stripped.startswith(p) and _is_not_advertised(stripped)
            for p in _OPTIONAL_FIELD_PREFIXES
        )

    @classmethod
    def _parse_block_line(
        cls,
        lines: list[str],
        idx: int,
        fields: dict[str, str | int | list[str] | None],
    ) -> int:
        """Advance one line in a neighbor block. Returns the next line index."""
        stripped = lines[idx].strip()

        if cls._is_skippable(stripped):
            return idx + 1

        if cls._parse_simple_fields(stripped, fields):
            return idx + 1

        m = cls._TIME_REM.match(stripped)
        if m:
            fields["time_remaining"] = int(m.group("v"))
            return idx + 1

        if cls._SYS_DESC_HDR.match(stripped):
            desc, next_idx = cls._collect_sys_description(lines, idx + 1)
            fields["system_description"] = desc
            return next_idx

        if cls._MGMT_HDR.match(stripped):
            addrs, next_idx = cls._collect_mgmt_addresses(lines, idx + 1)
            if addrs:
                fields["management_addresses"] = addrs
            return next_idx

        return idx + 1

    @classmethod
    def _parse_block(
        cls,
        lines: list[str],
    ) -> tuple[str | None, str | None, LldpNeighborDetailEntry | None]:
        """Parse a single neighbor block.

        Args:
            lines: Lines belonging to one neighbor block.

        Returns:
            Tuple of (local_interface, port_id_raw, entry) or (None, None, None).
        """
        fields: dict[str, str | int | list[str] | None] = {}
        idx = 0

        while idx < len(lines):
            idx = cls._parse_block_line(lines, idx, fields)

        port_id_raw = fields.get("port_id")
        local_intf = fields.pop("local_intf", None)
        entry = _build_entry(fields)
        if entry is None:
            return None, None, None
        pid = str(port_id_raw) if port_id_raw is not None else None
        return (
            str(local_intf) if local_intf else None,
            pid,
            entry,
        )

    @classmethod
    def _split_blocks(
        cls,
        output: str,
    ) -> tuple[list[list[str]], int | None]:
        """Split output into neighbor blocks and extract total.

        Returns:
            Tuple of (blocks, total_entries).
        """
        blocks: list[list[str]] = []
        current: list[str] = []
        total_entries: int | None = None

        for line in output.splitlines():
            stripped = line.strip()

            m = cls._TOTAL.match(stripped)
            if m:
                total_entries = int(m.group("total"))

            if cls._SEPARATOR.match(stripped):
                if current:
                    blocks.append(current)
                    current = []
                continue
            current.append(line)

        # Handle trailing block with actual neighbor data
        if current and any(
            s.strip() and not cls._TOTAL.match(s.strip()) for s in current
        ):
            blocks.append(current)

        return blocks, total_entries

    @classmethod
    def parse(
        cls,
        output: str,
    ) -> ShowLldpNeighborsDetailResult:
        """Parse 'show lldp neighbors detail' output on IOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LLDP neighbor details nested as
            ``local interface (or port) → chassis id → port id → entry``.

        Raises:
            ValueError: If no neighbors found in output.
        """
        blocks, total_entries = cls._split_blocks(output)
        neighbors: dict[str, dict[str, dict[str, LldpNeighborDetailEntry]]] = {}

        for block in blocks:
            local_intf, port_id_raw, entry = cls._parse_block(block)
            if entry is None or not port_id_raw:
                continue
            outer = _outer_neighbor_key(local_intf, port_id_raw)
            chassis = entry["chassis_id"]
            port = entry["port_id"]
            neighbors.setdefault(outer, {}).setdefault(chassis, {})[port] = entry

        if not neighbors:
            msg = "No LLDP neighbor details found in output"
            raise ValueError(msg)

        result: ShowLldpNeighborsDetailResult = {
            "neighbors": neighbors,
        }
        if total_entries is not None:
            result["total_entries"] = total_entries

        return result
