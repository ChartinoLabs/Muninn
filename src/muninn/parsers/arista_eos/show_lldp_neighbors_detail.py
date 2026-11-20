"""Parser for 'show lldp neighbors detail' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class LldpNeighborDetailEntry(TypedDict):
    """Schema for a single LLDP neighbor detail entry."""

    chassis_id: str
    port_id: str
    port_description: NotRequired[str]
    system_name: NotRequired[str]
    system_description: NotRequired[str]
    ttl: int
    system_capabilities: NotRequired[str]
    enabled_capabilities: NotRequired[str]
    management_addresses: NotRequired[list[str]]


class ShowLldpNeighborsDetailResult(TypedDict):
    """Schema for 'show lldp neighbors detail' parsed output on Arista EOS.

    Keyed as: local_interface -> chassis_id -> port_id -> entry.
    """

    neighbors: dict[str, dict[str, dict[str, LldpNeighborDetailEntry]]]


# Matches the interface header line: "Interface Ethernet1 detected 2 LLDP neighbors:"
_INTERFACE_HEADER_RE = re.compile(
    r"^Interface\s+(?P<intf>\S+)\s+detected\s+\d+\s+LLDP\s+neighbor",
)

# Field patterns for neighbor detail lines (varying indentation).
# "Chassis ID type" / "Port ID type" lines must be excluded from the simpler
# "Chassis ID" / "Port ID" matches, which is handled at the call site.
_CHASSIS_ID_RE = re.compile(r"^\s*Chassis ID\s*:\s*(?P<v>\S+)")
_PORT_ID_RE = re.compile(r"^\s*Port ID\s*:\s*(?P<v>.+)$")
_TTL_RE = re.compile(r"^\s*-\s*Time To Live:\s*(?P<v>\d+)\s+seconds")
_MGMT_ADDR_RE = re.compile(r"^\s*Management Address\s*:\s*(?P<v>\S+)")
_NEIGHBOR_HEADER_RE = re.compile(r"^\s*Neighbor\s+\S+")

# Simple single-value patterns: (compiled regex, field key, apply _clean_quoted)
_SYS_CAP_RE = re.compile(r"^\s*-\s*System Capabilities\s*:\s*(?P<v>.+)$")
_ENA_CAP_RE = re.compile(r"^\s*Enabled Capabilities\s*:\s*(?P<v>.+)$")

_SIMPLE_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^\s*-\s*Port Description:\s*(?P<v>.+)$"), "port_description"),
    (re.compile(r"^\s*-\s*System Name:\s*(?P<v>.+)$"), "system_name"),
    (re.compile(r"^\s*-\s*System Description:\s*(?P<v>.+)$"), "system_description"),
    (_SYS_CAP_RE, "system_capabilities"),
    (_ENA_CAP_RE, "enabled_capabilities"),
)

# Interface-like patterns for port ID canonicalization
_INTERFACE_PORT_ID_RE = re.compile(
    r"^(?:Eth(?:ernet)?|Et|Ma(?:nagement)?|Po(?:rt-Channel)?|"
    r"Lo(?:opback)?|Vl(?:an)?|Tu(?:nnel)?|Gi|Te|Fo|Hu)\d",
    re.IGNORECASE,
)


def _clean_quoted(value: str) -> str:
    """Strip surrounding quotes and whitespace from a value."""
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        return stripped[1:-1]
    return stripped


def _normalize_port_id(port_id: str) -> str:
    """Canonicalize port_id if it looks like an interface name."""
    if _INTERFACE_PORT_ID_RE.match(port_id):
        return canonical_interface_name(port_id, os=OS.ARISTA_EOS)
    return port_id


def _build_entry(
    fields: dict[str, str | int | list[str] | None],
) -> LldpNeighborDetailEntry | None:
    """Build a typed entry dict from collected fields.

    Returns None if required fields (chassis_id, port_id, ttl) are missing.
    """
    chassis_id = fields.get("chassis_id")
    port_id = fields.get("port_id")
    ttl = fields.get("ttl")

    if chassis_id is None or port_id is None or ttl is None:
        return None

    entry: LldpNeighborDetailEntry = {
        "chassis_id": str(chassis_id),
        "port_id": _normalize_port_id(str(port_id)),
        "ttl": int(str(ttl)),
    }

    optional_str_keys: tuple[str, ...] = (
        "port_description",
        "system_name",
        "system_description",
        "system_capabilities",
        "enabled_capabilities",
    )
    for key in optional_str_keys:
        val = fields.get(key)
        if val is not None:
            entry[key] = str(val)  # type: ignore[literal-required]

    mgmt = fields.get("management_addresses")
    if mgmt:
        entry["management_addresses"] = cast(list[str], mgmt)

    return entry


def _try_match_simple_fields(
    line: str,
    fields: dict[str, str | int | list[str] | None],
) -> bool:
    """Try to match simple single-value fields. Returns True if matched."""
    for pattern, key in _SIMPLE_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            fields[key] = _clean_quoted(m.group("v"))
            return True
    return False


def _try_match_special_fields(
    line: str,
    fields: dict[str, str | int | list[str] | None],
    mgmt_addrs: list[str],
) -> bool:
    """Match chassis_id, port_id, ttl, and management address fields.

    Returns True if the line was consumed.
    """
    m = _CHASSIS_ID_RE.match(line)
    if m and "Chassis ID type" not in line and "chassis_id" not in fields:
        fields["chassis_id"] = m.group("v").strip()
        return True

    m = _PORT_ID_RE.match(line)
    if m and "Port ID type" not in line and "port_id" not in fields:
        fields["port_id"] = _clean_quoted(m.group("v"))
        return True

    m = _TTL_RE.match(line)
    if m:
        fields["ttl"] = int(m.group("v"))
        return True

    m = _MGMT_ADDR_RE.match(line)
    if m:
        mgmt_addrs.append(m.group("v").strip())
        return True

    return False


@register(OS.ARISTA_EOS, "show lldp neighbors detail")
class ShowLldpNeighborsDetailParser(
    BaseParser[ShowLldpNeighborsDetailResult],
):
    """Parser for 'show lldp neighbors detail' command on Arista EOS.

    Output is keyed as:
    ``local_interface -> chassis_id -> port_id -> entry``.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    @classmethod
    def _parse_neighbor_fields(
        cls,
        lines: list[str],
    ) -> dict[str, str | int | list[str] | None]:
        """Extract fields from a single neighbor's lines."""
        fields: dict[str, str | int | list[str] | None] = {}
        mgmt_addrs: list[str] = []

        for line in lines:
            if _try_match_simple_fields(line, fields):
                continue
            _try_match_special_fields(line, fields, mgmt_addrs)

        if mgmt_addrs:
            fields["management_addresses"] = mgmt_addrs

        return fields

    @classmethod
    def _flush_interface(
        cls,
        result: list[tuple[str, list[list[str]]]],
        intf: str | None,
        neighbor_blocks: list[list[str]],
        current_lines: list[str],
    ) -> None:
        """Append accumulated neighbor lines to the interface block list."""
        if current_lines and intf is not None:
            neighbor_blocks.append(current_lines)
        if intf is not None and neighbor_blocks:
            result.append((intf, neighbor_blocks))

    @classmethod
    def _split_into_interface_blocks(
        cls,
        output: str,
    ) -> list[tuple[str, list[list[str]]]]:
        """Split output into (local_interface, [neighbor_lines, ...]) tuples.

        Each interface block starts with "Interface X detected N LLDP neighbors:"
        and contains zero or more neighbor sub-blocks starting with "Neighbor ...".
        """
        result: list[tuple[str, list[list[str]]]] = []
        current_intf: str | None = None
        neighbor_blocks: list[list[str]] = []
        current_neighbor_lines: list[str] = []

        for line in output.splitlines():
            m = _INTERFACE_HEADER_RE.match(line)
            if m:
                cls._flush_interface(
                    result, current_intf, neighbor_blocks, current_neighbor_lines
                )
                current_intf = canonical_interface_name(
                    m.group("intf"), os=OS.ARISTA_EOS
                )
                neighbor_blocks = []
                current_neighbor_lines = []
                continue

            if current_intf is None:
                continue

            # Detect start of a new neighbor sub-block
            if _NEIGHBOR_HEADER_RE.match(line):
                if current_neighbor_lines:
                    neighbor_blocks.append(current_neighbor_lines)
                current_neighbor_lines = [line]
                continue

            if current_neighbor_lines:
                current_neighbor_lines.append(line)

        cls._flush_interface(
            result, current_intf, neighbor_blocks, current_neighbor_lines
        )
        return result

    @classmethod
    def parse(cls, output: str) -> ShowLldpNeighborsDetailResult:
        """Parse 'show lldp neighbors detail' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LLDP neighbor details nested as
            ``local_interface -> chassis_id -> port_id -> entry``.

        Raises:
            ValueError: If no LLDP neighbor details are found in output.
        """
        neighbors: dict[str, dict[str, dict[str, LldpNeighborDetailEntry]]] = {}

        for local_intf, neighbor_blocks in cls._split_into_interface_blocks(output):
            for block_lines in neighbor_blocks:
                fields = cls._parse_neighbor_fields(block_lines)
                entry = _build_entry(fields)
                if entry is None:
                    continue
                chassis = entry["chassis_id"]
                port = entry["port_id"]
                neighbors.setdefault(local_intf, {}).setdefault(chassis, {})[port] = (
                    entry
                )

        if not neighbors:
            msg = "No LLDP neighbor details found in output"
            raise ValueError(msg)

        return cast(ShowLldpNeighborsDetailResult, {"neighbors": neighbors})
