"""Parser for 'show cdp neighbors detail' command on NX-OS."""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

OptionalStringField = Literal[
    "system_name",
    "duplex",
    "physical_location",
    "vtp_management_domain",
    "local_interface_mac",
    "remote_interface_mac",
]

OptionalIntField = Literal["native_vlan", "mtu"]
OptionalListField = Literal["interface_addresses", "mgmt_addresses"]


class CdpNeighborDetailEntry(TypedDict):
    """Schema for a single CDP neighbor detail entry."""

    device_id: str
    platform: str
    capabilities: str
    port_id: str
    hold_time: int
    version: str
    advertisement_version: int
    system_name: NotRequired[str]
    interface_addresses: NotRequired[list[str]]
    mgmt_addresses: NotRequired[list[str]]
    native_vlan: NotRequired[int]
    duplex: NotRequired[str]
    mtu: NotRequired[int]
    physical_location: NotRequired[str]
    vtp_management_domain: NotRequired[str]
    local_interface_mac: NotRequired[str]
    remote_interface_mac: NotRequired[str]


class ShowCdpNeighborsDetailResult(TypedDict):
    """Schema for 'show cdp neighbors detail' parsed output."""

    neighbors: dict[str, dict[str, dict[str, CdpNeighborDetailEntry]]]


# Required fields that must be present to build a valid entry
_REQUIRED_FIELDS = (
    "device_id",
    "platform",
    "capabilities",
    "port_id",
    "hold_time",
    "version",
    "advertisement_version",
)

# Optional string fields copied directly from parsed fields
_OPTIONAL_STR_FIELDS: tuple[OptionalStringField, ...] = (
    "system_name",
    "duplex",
    "physical_location",
    "vtp_management_domain",
    "local_interface_mac",
    "remote_interface_mac",
)

# Optional integer fields that need int() conversion
_OPTIONAL_INT_FIELDS: tuple[OptionalIntField, ...] = ("native_vlan", "mtu")

# Optional list fields copied as lists
_OPTIONAL_LIST_FIELDS: tuple[OptionalListField, ...] = (
    "interface_addresses",
    "mgmt_addresses",
)


@dataclass
class _ParseState:
    """Mutable state for the detail parser's line-by-line loop."""

    neighbors: dict[str, dict[str, dict[str, CdpNeighborDetailEntry]]] = field(
        default_factory=dict,
    )
    fields: dict[str, object] = field(default_factory=dict)
    local_intf: str | None = None
    addr_section: str | None = None
    version_lines: list[str] = field(default_factory=list)
    in_version: bool = False

    def finalize_version(self) -> None:
        """Store collected version lines into fields."""
        if self.version_lines:
            self.fields["version"] = "\n".join(self.version_lines)
        self.version_lines = []
        self.in_version = False

    def reset(self) -> None:
        """Reset state for a new record."""
        self.fields = {}
        self.local_intf = None
        self.addr_section = None
        self.version_lines = []
        self.in_version = False


@register(OS.CISCO_NXOS, "show cdp neighbors detail")
class ShowCdpNeighborsDetailParser(
    BaseParser[ShowCdpNeighborsDetailResult],
):
    """Parser for 'show cdp neighbors detail' command on NX-OS.

    Parses detailed CDP neighbor information showing connected devices
    with full platform, version, and address details.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CDP})

    _DEVICE_ID_PATTERN = re.compile(r"^Device ID:\s*(.+)$")
    _SYSTEM_NAME_PATTERN = re.compile(r"^System Name:\s*(.+)$")
    _IPV4_ADDRESSESS_PATTERN = re.compile(
        r"^\s+IPv4 Address:\s*(\S+)$",
    )
    _PLATFORM_CAPS_PATTERN = re.compile(
        r"^Platform:\s*(.+?),\s*Capabilities:\s*(.+)$",
    )
    _INTERFACE_PORT_PATTERN = re.compile(
        r"^Interface:\s*(\S+),\s*"
        r"Port ID \(outgoing port\):\s*(\S+)$",
    )
    _HOLDTIME_PATTERN = re.compile(r"^Holdtime:\s*(\d+)\s*sec$")
    _ADV_VERSION_PATTERN = re.compile(
        r"^Advertisement Version:\s*(\d+)$",
    )
    _NATIVE_VLAN_PATTERN = re.compile(r"^Native VLAN:\s*(\d+)$")
    _DUPLEX_PATTERN = re.compile(r"^Duplex:\s*(\S+)$")
    _MTU_PATTERN = re.compile(r"^MTU:\s*(\d+)$")
    _PHYSICAL_LOCATION_PATTERN = re.compile(
        r"^Physical Location:\s*(.+)$",
    )
    _VTP_DOMAIN_PATTERN = re.compile(
        r"^VTP Management Domain Name:\s*(.*)$",
    )
    _LOCAL_MAC_PATTERN = re.compile(
        r"^Local Interface MAC:\s*(\S+)$",
    )
    _REMOTE_MAC_PATTERN = re.compile(
        r"^Remote Interface MAC:\s*(\S+)$",
    )
    _SEPARATOR_PATTERN = re.compile(r"^-{5,}$")
    _INTERFACE_ADDR_HEADER = "Interface address(es):"
    _MGMT_ADDR_HEADER = "Mgmt address(es):"

    # Pattern to detect if port_id looks like an interface
    _INTF_DETECT_PATTERN = re.compile(
        r"^(?:Gi(?:g(?:abit)?)?|Fa(?:s(?:t)?)?|Eth?|Te(?:n)?|"
        r"Fo(?:r(?:ty)?)?|Hu(?:n(?:dred)?)?|mgmt|Lo|Vlan|Po|"
        r"Tu|Se|nve)(?:Ethernet)?\d",
        re.IGNORECASE,
    )

    # Maps regex patterns to their target field names for simple
    # single-group matches.
    _SIMPLE_FIELD_PATTERNS: list[tuple[str, str]] = [
        ("_SYSTEM_NAME_PATTERN", "system_name"),
        ("_HOLDTIME_PATTERN", "hold_time"),
        ("_ADV_VERSION_PATTERN", "advertisement_version"),
        ("_NATIVE_VLAN_PATTERN", "native_vlan"),
        ("_DUPLEX_PATTERN", "duplex"),
        ("_MTU_PATTERN", "mtu"),
        ("_PHYSICAL_LOCATION_PATTERN", "physical_location"),
        ("_LOCAL_MAC_PATTERN", "local_interface_mac"),
        ("_REMOTE_MAC_PATTERN", "remote_interface_mac"),
    ]

    @classmethod
    def _normalize_port_id(cls, port_id: str) -> str:
        """Normalize port_id if it looks like an interface name."""
        if cls._INTF_DETECT_PATTERN.match(port_id):
            return canonical_interface_name(port_id, os=OS.CISCO_NXOS)
        return port_id

    @classmethod
    def _build_entry(
        cls,
        fields: dict[str, object],
    ) -> CdpNeighborDetailEntry | None:
        """Build a CdpNeighborDetailEntry from collected fields.

        Returns None if required fields are missing.
        """
        for key in _REQUIRED_FIELDS:
            if fields.get(key) is None:
                return None

        entry: CdpNeighborDetailEntry = {
            "device_id": str(fields["device_id"]),
            "platform": str(fields["platform"]),
            "capabilities": str(fields["capabilities"]),
            "port_id": cls._normalize_port_id(str(fields["port_id"])),
            "hold_time": int(str(fields["hold_time"])),
            "version": str(fields["version"]),
            "advertisement_version": int(
                str(fields["advertisement_version"]),
            ),
        }

        cls._add_optional_fields(entry, fields)
        return entry

    @classmethod
    def _add_optional_fields(
        cls,
        entry: CdpNeighborDetailEntry,
        fields: dict[str, object],
    ) -> None:
        """Add optional fields to an entry if present."""
        for key in _OPTIONAL_STR_FIELDS:
            if key in fields:
                entry[key] = str(fields[key])

        for key in _OPTIONAL_INT_FIELDS:
            if key in fields:
                entry[key] = int(str(fields[key]))

        for key in _OPTIONAL_LIST_FIELDS:
            if fields.get(key):
                value = fields[key]
                _d = cast(dict[str, Any], entry)
                _d[key] = list(value) if isinstance(value, Iterable) else [value]

    @classmethod
    def _save_record(cls, state: _ParseState) -> None:
        """Save a completed record into the neighbors dict."""
        if not state.fields.get("device_id") or not state.local_intf:
            return
        entry = cls._build_entry(state.fields)
        if entry is None:
            return
        intf = state.local_intf
        device_id = entry["device_id"]
        port_key = entry["port_id"]
        by_local = state.neighbors.setdefault(intf, {})
        by_device = by_local.setdefault(device_id, {})
        by_device[port_key] = entry

    @classmethod
    def _handle_record_boundary(
        cls,
        stripped: str,
        state: _ParseState,
    ) -> bool:
        """Handle separator lines and Device ID lines.

        Returns True if the line was a record boundary.
        """
        is_sep = bool(cls._SEPARATOR_PATTERN.match(stripped))
        device_match = cls._DEVICE_ID_PATTERN.match(stripped)

        if not is_sep and not device_match:
            return False

        state.finalize_version()
        cls._save_record(state)
        state.reset()
        if device_match:
            state.fields["device_id"] = device_match.group(1).strip()
        return True

    @classmethod
    def _handle_address_line(
        cls,
        line: str,
        state: _ParseState,
    ) -> bool:
        """Handle IPv4 address lines within address sections.

        Returns True if the line was consumed.
        """
        if not state.addr_section:
            return False
        ipv4_match = cls._IPV4_ADDRESSESS_PATTERN.match(line)
        if not ipv4_match:
            return False

        addr = ipv4_match.group(1)
        key = (
            "interface_addresses"
            if state.addr_section == "interface"
            else "mgmt_addresses"
        )
        _d = cast(dict[str, Any], state.fields)
        if key not in _d:
            _d[key] = []
        addr_list = _d[key]
        if isinstance(addr_list, list):
            addr_list.append(addr)
        return True

    @classmethod
    def _handle_addr_header(
        cls,
        stripped: str,
        state: _ParseState,
    ) -> bool:
        """Check for address section headers.

        Returns True if the line was an address header.
        """
        if stripped.startswith(cls._INTERFACE_ADDR_HEADER):
            suffix = stripped[len(cls._INTERFACE_ADDR_HEADER) :].strip()
            state.addr_section = None if suffix == "0" else "interface"
            return True

        if stripped.startswith(cls._MGMT_ADDR_HEADER):
            state.addr_section = "mgmt"
            return True

        return False

    @classmethod
    def _try_simple_fields(
        cls,
        stripped: str,
        fields: dict[str, object],
    ) -> bool:
        """Try matching simple single-group field patterns.

        Returns True if a match was found.
        """
        for pattern_attr, field_name in cls._SIMPLE_FIELD_PATTERNS:
            pattern = getattr(cls, pattern_attr)
            match = pattern.match(stripped)
            if match:
                fields[field_name] = match.group(1).strip()
                return True
        return False

    @classmethod
    def _try_complex_fields(
        cls,
        stripped: str,
        state: _ParseState,
    ) -> bool:
        """Try matching multi-group field patterns.

        Returns True if a match was found.
        """
        plat_match = cls._PLATFORM_CAPS_PATTERN.match(stripped)
        if plat_match:
            state.fields["platform"] = plat_match.group(1).strip()
            state.fields["capabilities"] = plat_match.group(2).strip()
            return True

        intf_match = cls._INTERFACE_PORT_PATTERN.match(stripped)
        if intf_match:
            state.local_intf = canonical_interface_name(
                intf_match.group(1).strip(),
                os=OS.CISCO_NXOS,
            )
            state.fields["port_id"] = intf_match.group(2).strip()
            return True

        vtp_match = cls._VTP_DOMAIN_PATTERN.match(stripped)
        if vtp_match:
            domain = vtp_match.group(1).strip()
            if domain:
                state.fields["vtp_management_domain"] = domain
            return True

        return False

    @classmethod
    def _process_line(
        cls,
        line: str,
        state: _ParseState,
    ) -> None:
        """Process a single line of output, updating state."""
        stripped = line.strip()

        if cls._handle_record_boundary(stripped, state):
            return

        if not stripped:
            state.finalize_version()
            state.addr_section = None
            return

        if state.in_version:
            state.version_lines.append(stripped)
            return

        if stripped == "Version:":
            state.in_version = True
            state.version_lines = []
            state.addr_section = None
            return

        if cls._handle_addr_header(stripped, state):
            return

        if cls._handle_address_line(line, state):
            return

        state.addr_section = None

        if cls._try_simple_fields(stripped, state.fields):
            return

        cls._try_complex_fields(stripped, state)

    @classmethod
    def parse(cls, output: str) -> ShowCdpNeighborsDetailResult:
        """Parse 'show cdp neighbors detail' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed CDP neighbor details keyed by local interface.

        Raises:
            ValueError: If no CDP neighbor entries found.
        """
        state = _ParseState()

        for line in output.splitlines():
            cls._process_line(line, state)

        # Finalize last record
        state.finalize_version()
        cls._save_record(state)

        if not state.neighbors:
            msg = "No CDP neighbor detail entries found in output"
            raise ValueError(msg)

        return ShowCdpNeighborsDetailResult(
            neighbors=state.neighbors,
        )
