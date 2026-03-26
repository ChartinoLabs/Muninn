"""Parser for 'show interface switchport' command on NX-OS."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# ---------------------------------------------------------------------------
# TypedDict schemas
# ---------------------------------------------------------------------------


class SwitchportEntry(TypedDict):
    """Schema for a single interface switchport entry."""

    switchport: str
    operational_mode: str
    access_vlan: int
    trunk_native_vlan: int
    trunk_vlans_allowed: str
    switchport_monitor: NotRequired[str]
    switchport_isolated: NotRequired[str]
    switchport_block_multicast: NotRequired[str]
    switchport_block_unicast: NotRequired[str]
    access_vlan_name: NotRequired[str]
    trunk_native_vlan_name: NotRequired[str]
    voice_vlan: NotRequired[int]
    extended_trust_state: NotRequired[str]
    admin_private_vlan: NotRequired[dict[str, str]]
    operational_private_vlan: NotRequired[str]


class ShowInterfaceSwitchportResult(TypedDict):
    """Schema for 'show interface switchport' parsed output."""

    interfaces: dict[str, SwitchportEntry]


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"^Name:\s+(\S+)\s*$")

# Key-value line pattern: leading whitespace, label, colon, value
_KV_RE = re.compile(r"^\s+(.+?)\s*:\s+(.*?)\s*$")

# VLAN field pattern: "3 (Vlan not created)" or "1 (default)" or "none"
_VLAN_WITH_NAME_RE = re.compile(r"^(\d+)\s+\((.+)\)$")


# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------

# Maps raw CLI labels to (dict_key, parser_function) pairs.
# Labels are lowercased and stripped for matching.
_FIELD_LABEL_MAP: dict[str, str] = {
    "switchport": "switchport",
    "switchport monitor": "switchport_monitor",
    "switchport isolated": "switchport_isolated",
    "switchport block multicast": "switchport_block_multicast",
    "switchport block unicast": "switchport_block_unicast",
    "operational mode": "operational_mode",
    "access mode vlan": "_access_vlan",
    "trunking native mode vlan": "_trunk_native_vlan",
    "trunking vlans allowed": "trunk_vlans_allowed",
    "voice vlan": "_voice_vlan",
    "extended trust state": "extended_trust_state",
    "operational private-vlan": "operational_private_vlan",
}

# Labels that map into the admin_private_vlan nested dict
_ADMIN_PV_PREFIX = "administrative private-vlan"

_ADMIN_PV_MAP: dict[str, str] = {
    "administrative private-vlan primary host-association": "primary_host_association",
    "administrative private-vlan secondary host-association": (
        "secondary_host_association"
    ),
    "administrative private-vlan primary mapping": "primary_mapping",
    "administrative private-vlan secondary mapping": "secondary_mapping",
    "administrative private-vlan trunk native vlan": "trunk_native_vlan",
    "administrative private-vlan trunk encapsulation": "trunk_encapsulation",
    "administrative private-vlan trunk normal vlans": "trunk_normal_vlans",
    "administrative private-vlan trunk private vlans": "trunk_private_vlans",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_vlan_field(value: str) -> tuple[int, str | None]:
    """Parse a VLAN field value like '3 (Vlan not created)' or '1 (default)'.

    Returns:
        Tuple of (vlan_id, vlan_name_or_none).

    Raises:
        ValueError: If the VLAN ID is not a valid integer.
    """
    m = _VLAN_WITH_NAME_RE.match(value)
    if m:
        return int(m.group(1)), m.group(2)
    msg = f"Unable to parse VLAN field: {value!r}"
    raise ValueError(msg)


def _parse_voice_vlan(value: str) -> int | None:
    """Parse a Voice VLAN field value.

    Returns:
        Integer VLAN ID, or None if 'none'.
    """
    stripped = value.strip().lower()
    if stripped == "none":
        return None
    try:
        return int(stripped)
    except ValueError:
        return None


def _normalize_label(label: str) -> str:
    """Normalize a CLI label for consistent matching."""
    return label.lower().strip()


def _apply_vlan_fields(
    entry: SwitchportEntry,
    fields: dict[str, str],
) -> None:
    """Parse and apply VLAN fields (access, trunk native, voice)."""
    raw_access = fields.get("_access_vlan", "")
    if raw_access:
        access_id, access_name = _parse_vlan_field(raw_access)
        entry["access_vlan"] = access_id
        if access_name:
            entry["access_vlan_name"] = access_name

    raw_native = fields.get("_trunk_native_vlan", "")
    if raw_native:
        native_id, native_name = _parse_vlan_field(raw_native)
        entry["trunk_native_vlan"] = native_id
        if native_name:
            entry["trunk_native_vlan_name"] = native_name

    raw_voice = fields.get("_voice_vlan", "")
    if raw_voice:
        voice_id = _parse_voice_vlan(raw_voice)
        if voice_id is not None:
            entry["voice_vlan"] = voice_id


# Fields included only when present, non-empty, and not "none"
_OPTIONAL_STR_FIELDS = [
    "switchport_monitor",
    "switchport_isolated",
    "switchport_block_multicast",
    "switchport_block_unicast",
    "extended_trust_state",
    "operational_private_vlan",
]


def _apply_optional_fields(
    entry: SwitchportEntry,
    fields: dict[str, str],
) -> None:
    """Apply optional string fields and admin private-vlan dict."""
    _d = cast(dict[str, Any], entry)
    for field in _OPTIONAL_STR_FIELDS:
        val = fields.get(field)
        if val and val.lower() != "none":
            _d[field] = val

    admin_pv: dict[str, str] = {}
    for raw_label, dict_key in _ADMIN_PV_MAP.items():
        val = fields.get(raw_label)
        if val and val.lower() != "none":
            admin_pv[dict_key] = val
    if admin_pv:
        entry["admin_private_vlan"] = admin_pv


def _build_entry(fields: dict[str, str]) -> SwitchportEntry:
    """Build a SwitchportEntry from raw field values.

    Raises:
        ValueError: If required VLAN fields cannot be parsed.
    """
    entry: SwitchportEntry = {
        "switchport": fields.get("switchport", ""),
        "operational_mode": fields.get("operational_mode", ""),
        "access_vlan": 0,
        "trunk_native_vlan": 0,
        "trunk_vlans_allowed": fields.get("trunk_vlans_allowed", ""),
    }

    _apply_vlan_fields(entry, fields)
    _apply_optional_fields(entry, fields)

    return entry


def _process_kv_line(
    label: str,
    value: str,
    fields: dict[str, str],
) -> None:
    """Process a single key-value line and store in fields dict."""
    normalized = _normalize_label(label)

    # Check standard field map
    dict_key = _FIELD_LABEL_MAP.get(normalized)
    if dict_key is not None:
        fields[dict_key] = value
        return

    # Check admin private-vlan fields
    if normalized.startswith(_ADMIN_PV_PREFIX):
        if normalized in _ADMIN_PV_MAP:
            fields[normalized] = value


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


@register(OS.CISCO_NXOS, "show interface switchport")
class ShowInterfaceSwitchportParser(BaseParser["ShowInterfaceSwitchportResult"]):
    """Parser for 'show interface switchport' on NX-OS.

    Parses switchport configuration for each interface including mode,
    VLANs, trunking, and private VLAN settings.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceSwitchportResult:
        """Parse 'show interface switchport' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed switchport data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, SwitchportEntry] = {}
        current_name: str | None = None
        current_fields: dict[str, str] = {}

        for line in output.splitlines():
            # Check for interface name header
            m_name = _NAME_RE.match(line)
            if m_name:
                # Flush previous interface
                if current_name is not None:
                    interfaces[current_name] = _build_entry(current_fields)
                current_name = canonical_interface_name(
                    m_name.group(1), os=OS.CISCO_NXOS
                )
                current_fields = {}
                continue

            # Parse key-value lines within an interface block
            if current_name is not None:
                m_kv = _KV_RE.match(line)
                if m_kv:
                    _process_kv_line(m_kv.group(1), m_kv.group(2), current_fields)

        # Flush last interface
        if current_name is not None:
            interfaces[current_name] = _build_entry(current_fields)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowInterfaceSwitchportResult(interfaces=interfaces)
