"""Parser for 'show lldp neighbors detail' command on NX-OS."""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_NOT_ADVERTISED = "not advertised"

_Transform = Callable[[str], str | int]
_FieldSpec = tuple[re.Pattern[str], str, _Transform]


class LldpNeighborDetailEntry(TypedDict):
    """Schema for a single LLDP neighbor detail entry."""

    chassis_id: str
    port_id: str
    port_description: NotRequired[str]
    system_name: NotRequired[str]
    system_description: NotRequired[str]
    time_remaining: NotRequired[int]
    system_capabilities: NotRequired[str]
    enabled_capabilities: NotRequired[str]
    management_address: NotRequired[str]
    management_address_ipv6: NotRequired[str]
    vlan_id: NotRequired[int]


class ShowLldpNeighborsDetailResult(TypedDict):
    """Schema for 'show lldp neighbors detail' parsed output."""

    neighbors: dict[str, LldpNeighborDetailEntry]
    total_entries: NotRequired[int]


def _normalize_capabilities(cap_str: str) -> str:
    """Normalize capability string, stripping extra whitespace."""
    return ", ".join(part.strip() for part in cap_str.split(","))


_INTERFACE_LIKE_PATTERN = re.compile(
    r"^(?:Gi(?:g(?:abit)?)?|Fa(?:s(?:t)?)?|Eth?|Te(?:n)?|Fo(?:r(?:ty)?)?|"
    r"Hu(?:n(?:dred)?)?|mgmt|Lo|Vlan|Po|Tu|Se|nve)(?:Ethernet)?\d",
    re.IGNORECASE,
)


def _normalize_interface_description(value: str) -> str:
    """Normalize a port description, canonicalizing if it looks like an interface."""
    stripped = value.strip()
    if _INTERFACE_LIKE_PATTERN.match(stripped):
        return canonical_interface_name(stripped, os=OS.CISCO_NXOS)
    return stripped


@register(OS.CISCO_NXOS, "show lldp neighbors detail")
class ShowLldpNeighborsDetailParser(BaseParser[ShowLldpNeighborsDetailResult]):
    """Parser for 'show lldp neighbors detail' command on NX-OS.

    Parses detailed LLDP neighbor information including chassis ID,
    port descriptions, system capabilities, and management addresses.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    _CHASSIS_ID_PATTERN = re.compile(r"^Chassis\s+id:\s+(?P<value>.+)$", re.I)
    _PORT_ID_PATTERN = re.compile(r"^Port\s+id:\s+(?P<value>.+)$", re.I)
    _LOCAL_PORT_PATTERN = re.compile(r"^Local\s+Port\s+id:\s+(?P<value>\S+)$", re.I)
    _TOTAL_PATTERN = re.compile(
        r"^Total\s+entries\s+displayed:\s*(?P<total>\d+)$", re.I
    )

    # Interface pattern for detecting if port_id is an interface name
    _INTERFACE_PATTERN = re.compile(
        r"^(?:Gi(?:g(?:abit)?)?|Fa(?:s(?:t)?)?|Eth?|Te(?:n)?|Fo(?:r(?:ty)?)?|"
        r"Hu(?:n(?:dred)?)?|mgmt|Lo|Vlan|Po|Tu|Se|nve)(?:Ethernet)?\d",
        re.IGNORECASE,
    )

    # Table-driven field patterns: (pattern, field_name, transform)
    # Transform is a callable that converts the matched value string.
    # A transform returning None means the field should be omitted.
    _FIELD_PATTERNS: tuple[_FieldSpec, ...] = (
        (
            re.compile(r"^Port\s+Description:\s+(?P<value>.+)$", re.I),
            "port_description",
            _normalize_interface_description,
        ),
        (
            re.compile(r"^System\s+Name:\s+(?P<value>.+)$", re.I),
            "system_name",
            str.strip,
        ),
        (
            re.compile(r"^System\s+Description:\s+(?P<value>.+)$", re.I),
            "system_description",
            str.strip,
        ),
        (
            re.compile(r"^Time\s+remaining:\s+(?P<value>\d+)\s+seconds$", re.I),
            "time_remaining",
            int,
        ),
        (
            re.compile(r"^System\s+Capabilities:\s+(?P<value>.+)$", re.I),
            "system_capabilities",
            _normalize_capabilities,
        ),
        (
            re.compile(r"^Enabled\s+Capabilities:\s+(?P<value>.+)$", re.I),
            "enabled_capabilities",
            _normalize_capabilities,
        ),
    )

    # Fields that use "not advertised" sentinel and should be omitted when so
    _OPTIONAL_ADDR_PATTERNS: tuple[_FieldSpec, ...] = (
        (
            re.compile(r"^Management\s+Address\s+IPV6:\s+(?P<value>.+)$", re.I),
            "management_address_ipv6",
            str.strip,
        ),
        (
            re.compile(r"^Management\s+Address:\s+(?P<value>.+)$", re.I),
            "management_address",
            str.strip,
        ),
        (
            re.compile(r"^Vlan\s+ID:\s+(?P<value>.+)$", re.I),
            "vlan_id",
            int,
        ),
    )

    @classmethod
    def _normalize_port_id(cls, port_id: str) -> str:
        """Normalize port_id if it looks like an interface name."""
        if cls._INTERFACE_PATTERN.match(port_id):
            return canonical_interface_name(port_id, os=OS.CISCO_NXOS)
        return port_id

    @classmethod
    def _is_skippable_line(cls, line: str) -> bool:
        """Return True if the line is a header/legend or blank."""
        return line.startswith(("Capability codes:", "(R)", "(W)", "Device ID"))

    @classmethod
    def _save_entry(
        cls,
        neighbors: dict[str, LldpNeighborDetailEntry],
        local_port: str | None,
        entry: dict[str, str | int],
    ) -> None:
        """Save a completed entry into the neighbors dict if valid."""
        if local_port and entry.get("chassis_id"):
            neighbors[local_port] = cast(LldpNeighborDetailEntry, entry)

    @classmethod
    def _try_match_field(cls, stripped: str, entry: dict[str, str | int]) -> bool:
        """Try to match a standard field pattern. Returns True if matched."""
        for pattern, field, transform in cls._FIELD_PATTERNS:
            match = pattern.match(stripped)
            if match:
                entry[field] = transform(match.group("value"))
                return True
        return False

    @classmethod
    def _try_match_optional_addr(
        cls, stripped: str, entry: dict[str, str | int]
    ) -> bool:
        """Try to match optional address/vlan fields. Returns True if matched."""
        for pattern, field, transform in cls._OPTIONAL_ADDR_PATTERNS:
            match = pattern.match(stripped)
            if match:
                value = match.group("value").strip()
                if value.lower() != _NOT_ADVERTISED:
                    entry[field] = transform(value)
                return True
        return False

    @classmethod
    def _process_line(
        cls,
        stripped: str,
        neighbors: dict[str, LldpNeighborDetailEntry],
        current_entry: dict[str, str | int],
        current_local_port: str | None,
    ) -> tuple[dict[str, str | int], str | None, int | None]:
        """Process a single non-empty, non-header line.

        Returns:
            Tuple of (current_entry, current_local_port, total_entries_or_none).
        """
        total_match = cls._TOTAL_PATTERN.match(stripped)
        if total_match:
            return current_entry, current_local_port, int(total_match.group("total"))

        # Chassis ID starts a new neighbor block
        match = cls._CHASSIS_ID_PATTERN.match(stripped)
        if match:
            cls._save_entry(neighbors, current_local_port, current_entry)
            return {"chassis_id": match.group("value").strip()}, None, None

        # Port ID
        match = cls._PORT_ID_PATTERN.match(stripped)
        if match:
            current_entry["port_id"] = cls._normalize_port_id(
                match.group("value").strip()
            )
            return current_entry, current_local_port, None

        # Local Port ID
        match = cls._LOCAL_PORT_PATTERN.match(stripped)
        if match:
            local_port = canonical_interface_name(
                match.group("value").strip(),
                os=OS.CISCO_NXOS,
            )
            return current_entry, local_port, None

        # Try table-driven field patterns, then optional address/vlan patterns
        if not cls._try_match_field(stripped, current_entry):
            cls._try_match_optional_addr(stripped, current_entry)

        return current_entry, current_local_port, None

    @classmethod
    def parse(cls, output: str) -> ShowLldpNeighborsDetailResult:
        """Parse 'show lldp neighbors detail' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LLDP neighbor details keyed by local interface.

        Raises:
            ValueError: If no LLDP neighbor entries found.
        """
        neighbors: dict[str, LldpNeighborDetailEntry] = {}
        total_entries: int | None = None
        current_entry: dict[str, str | int] = {}
        current_local_port: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                cls._save_entry(neighbors, current_local_port, current_entry)
                current_entry = {}
                current_local_port = None
                continue

            if cls._is_skippable_line(stripped):
                continue

            current_entry, current_local_port, total = cls._process_line(
                stripped, neighbors, current_entry, current_local_port
            )
            if total is not None:
                total_entries = total

        # Finalize last entry if pending
        cls._save_entry(neighbors, current_local_port, current_entry)

        if not neighbors:
            msg = "No LLDP neighbor detail entries found in output"
            raise ValueError(msg)

        result: ShowLldpNeighborsDetailResult = {"neighbors": neighbors}
        if total_entries is not None:
            result["total_entries"] = total_entries

        return result
