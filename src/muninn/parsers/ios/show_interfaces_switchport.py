"""Parser for 'show interfaces switchport' command on Cisco IOS."""

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
    administrative_mode: NotRequired[str]
    operational_mode: NotRequired[str]
    operational_mode_bundle: NotRequired[str]
    administrative_trunking_encapsulation: NotRequired[str]
    operational_trunking_encapsulation: NotRequired[str]
    negotiation_of_trunking: NotRequired[str]
    access_vlan: NotRequired[int]
    access_vlan_name: NotRequired[str]
    trunk_native_vlan: NotRequired[int]
    trunk_native_vlan_name: NotRequired[str]
    administrative_native_vlan_tagging: NotRequired[str]
    voice_vlan: NotRequired[int]
    voice_vlan_name: NotRequired[str]
    trunk_vlans_allowed: NotRequired[str]
    pruning_vlans_enabled: NotRequired[str]
    capture_mode: NotRequired[str]
    capture_vlans_allowed: NotRequired[str]
    protected: NotRequired[str]
    unknown_unicast_blocked: NotRequired[str]
    unknown_multicast_blocked: NotRequired[str]
    appliance_trust: NotRequired[str]
    operational_private_vlan: NotRequired[str]
    admin_private_vlan: NotRequired[dict[str, str]]


class ShowInterfacesSwitchportResult(TypedDict):
    """Schema for 'show interfaces switchport' parsed output."""

    interfaces: dict[str, SwitchportEntry]


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Interface name header, e.g. "Name: Gi1/0/1"
_NAME_RE = re.compile(r"^Name:\s+(\S+)\s*$")

# Key-value line: label, colon, value (no leading whitespace on IOS)
_KV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 \-/]+?)\s*:\s*(.*?)\s*$")

# Capture Mode flag line, e.g. "Capture Mode Disabled" (no colon)
_CAPTURE_MODE_RE = re.compile(r"^Capture Mode\s+(Enabled|Disabled)\s*$")

# VLAN field with name, e.g. "1 (default)" or "21 (Corp-10-225-207-0)"
_VLAN_WITH_NAME_RE = re.compile(r"^(\d+)\s+\((.+)\)$")

# Operational Mode with bundle suffix, e.g.
# "trunk (member of bundle Po1)" or "static access (member of bundle Po10)"
_OP_MODE_BUNDLE_RE = re.compile(r"^(.*?)\s+\(member of bundle (\S+)\)\s*$")


# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------

# Maps normalized (lowercased) raw CLI labels to internal field keys.
# Internal keys prefixed with "_" need further parsing (e.g. VLAN id+name).
_FIELD_LABEL_MAP: dict[str, str] = {
    "switchport": "switchport",
    "administrative mode": "administrative_mode",
    "operational mode": "_operational_mode",
    "administrative trunking encapsulation": "administrative_trunking_encapsulation",
    "operational trunking encapsulation": "operational_trunking_encapsulation",
    "negotiation of trunking": "negotiation_of_trunking",
    "access mode vlan": "_access_vlan",
    "trunking native mode vlan": "_trunk_native_vlan",
    "administrative native vlan tagging": "administrative_native_vlan_tagging",
    "voice vlan": "_voice_vlan",
    "trunking vlans enabled": "trunk_vlans_allowed",
    "pruning vlans enabled": "pruning_vlans_enabled",
    "capture vlans allowed": "capture_vlans_allowed",
    "protected": "protected",
    "unknown unicast blocked": "unknown_unicast_blocked",
    "unknown multicast blocked": "unknown_multicast_blocked",
    "appliance trust": "appliance_trust",
    "operational private-vlan": "operational_private_vlan",
}

# Administrative private-vlan sub-labels mapped into admin_private_vlan dict
_ADMIN_PV_PREFIX = "administrative private-vlan"

_ADMIN_PV_MAP: dict[str, str] = {
    "administrative private-vlan host-association": "host_association",
    "administrative private-vlan mapping": "mapping",
    "administrative private-vlan trunk native vlan": "trunk_native_vlan",
    "administrative private-vlan trunk native vlan tagging": (
        "trunk_native_vlan_tagging"
    ),
    "administrative private-vlan trunk encapsulation": "trunk_encapsulation",
    "administrative private-vlan trunk normal vlans": "trunk_normal_vlans",
    "administrative private-vlan trunk associations": "trunk_associations",
    "administrative private-vlan trunk mappings": "trunk_mappings",
}

# Optional string fields written only when present and not a placeholder
_OPTIONAL_STR_FIELDS: tuple[str, ...] = (
    "administrative_mode",
    "administrative_trunking_encapsulation",
    "operational_trunking_encapsulation",
    "negotiation_of_trunking",
    "administrative_native_vlan_tagging",
    "trunk_vlans_allowed",
    "pruning_vlans_enabled",
    "capture_mode",
    "capture_vlans_allowed",
    "protected",
    "unknown_unicast_blocked",
    "unknown_multicast_blocked",
    "appliance_trust",
    "operational_private_vlan",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_placeholder(value: str) -> bool:
    """Return True for placeholder values that should be omitted."""
    return value.strip().lower() in {"", "none", "n/a", "-"}


def _parse_vlan_field(value: str) -> tuple[int, str | None]:
    """Parse a VLAN field value like '1 (default)' or '21 (Corp-10)'.

    Returns:
        Tuple of (vlan_id, vlan_name_or_none).
    """
    m = _VLAN_WITH_NAME_RE.match(value)
    if m:
        return int(m.group(1)), m.group(2)
    # Pure integer fallback
    return int(value), None


def _normalize_label(label: str) -> str:
    """Normalize a CLI label for consistent matching."""
    return label.lower().strip()


def _apply_operational_mode(
    entry: dict[str, Any],
    raw: str,
) -> None:
    """Apply operational_mode and optional bundle membership.

    When a bundle is named (e.g. "Po1"), it is canonicalized to the long
    form (e.g. "Port-channel1") for consistency with the rest of the schema.
    """
    if not raw:
        return
    m = _OP_MODE_BUNDLE_RE.match(raw)
    if m:
        entry["operational_mode"] = m.group(1).strip()
        entry["operational_mode_bundle"] = canonical_interface_name(
            m.group(2).strip(), os=OS.CISCO_IOS
        )
    else:
        entry["operational_mode"] = raw.strip()


def _apply_vlan_fields(
    entry: dict[str, Any],
    fields: dict[str, str],
) -> None:
    """Parse and apply VLAN id+name fields (access, trunk native, voice)."""
    raw_access = fields.get("_access_vlan", "")
    if raw_access and not _is_placeholder(raw_access):
        access_id, access_name = _parse_vlan_field(raw_access)
        entry["access_vlan"] = access_id
        if access_name:
            entry["access_vlan_name"] = access_name

    raw_native = fields.get("_trunk_native_vlan", "")
    if raw_native and not _is_placeholder(raw_native):
        native_id, native_name = _parse_vlan_field(raw_native)
        entry["trunk_native_vlan"] = native_id
        if native_name:
            entry["trunk_native_vlan_name"] = native_name

    raw_voice = fields.get("_voice_vlan", "")
    if raw_voice and not _is_placeholder(raw_voice):
        voice_id, voice_name = _parse_vlan_field(raw_voice)
        entry["voice_vlan"] = voice_id
        if voice_name:
            entry["voice_vlan_name"] = voice_name


def _apply_optional_fields(
    entry: dict[str, Any],
    fields: dict[str, str],
) -> None:
    """Apply optional string fields, omitting placeholders."""
    for field in _OPTIONAL_STR_FIELDS:
        val = fields.get(field)
        if val is not None and not _is_placeholder(val):
            entry[field] = val


def _apply_admin_private_vlan(
    entry: dict[str, Any],
    fields: dict[str, str],
) -> None:
    """Build and apply the admin_private_vlan nested dict."""
    admin_pv: dict[str, str] = {}
    for raw_label, dict_key in _ADMIN_PV_MAP.items():
        val = fields.get(raw_label)
        if val is not None and not _is_placeholder(val):
            admin_pv[dict_key] = val
    if admin_pv:
        entry["admin_private_vlan"] = admin_pv


def _build_entry(fields: dict[str, str]) -> SwitchportEntry:
    """Build a SwitchportEntry from the collected raw field values."""
    entry: dict[str, Any] = {}

    switchport = fields.get("switchport", "").strip()
    entry["switchport"] = switchport

    _apply_operational_mode(entry, fields.get("_operational_mode", ""))
    _apply_vlan_fields(entry, fields)
    _apply_optional_fields(entry, fields)
    _apply_admin_private_vlan(entry, fields)

    return cast(SwitchportEntry, entry)


def _process_kv_line(
    label: str,
    value: str,
    fields: dict[str, str],
) -> None:
    """Process a single key-value line and store in fields dict."""
    normalized = _normalize_label(label)

    # Admin private-vlan sub-fields take precedence: their labels share the
    # "administrative private-vlan" prefix and must be routed to their own
    # bucket rather than treated as ordinary fields.
    if normalized.startswith(_ADMIN_PV_PREFIX) and normalized in _ADMIN_PV_MAP:
        fields[normalized] = value
        return

    dict_key = _FIELD_LABEL_MAP.get(normalized)
    if dict_key is not None:
        fields[dict_key] = value


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


@register(OS.CISCO_IOS, "show interfaces switchport")
class ShowInterfacesSwitchportParser(BaseParser["ShowInterfacesSwitchportResult"]):
    """Parser for 'show interfaces switchport' on Cisco IOS.

    Parses switchport configuration for each interface including
    administrative/operational mode, trunking encapsulation, VLANs,
    private-VLAN configuration, capture mode, and port-protection flags.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.INTERFACES, ParserTag.SWITCHING, ParserTag.VLAN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesSwitchportResult:
        """Parse 'show interfaces switchport' output on Cisco IOS.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed switchport data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces are found in the output.
        """
        interfaces: dict[str, SwitchportEntry] = {}
        current_name: str | None = None
        current_fields: dict[str, str] = {}

        for line in output.splitlines():
            # Interface name header — flush previous block first
            m_name = _NAME_RE.match(line)
            if m_name:
                if current_name is not None:
                    interfaces[current_name] = _build_entry(current_fields)
                current_name = canonical_interface_name(
                    m_name.group(1), os=OS.CISCO_IOS
                )
                current_fields = {}
                continue

            if current_name is None:
                continue

            # Special-case: "Capture Mode Disabled" (no colon).
            m_cap = _CAPTURE_MODE_RE.match(line)
            if m_cap:
                current_fields["capture_mode"] = m_cap.group(1)
                continue

            # Standard "Label: value" line
            m_kv = _KV_RE.match(line)
            if m_kv:
                _process_kv_line(m_kv.group(1), m_kv.group(2), current_fields)

        # Flush trailing interface block
        if current_name is not None:
            interfaces[current_name] = _build_entry(current_fields)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowInterfacesSwitchportResult(interfaces=interfaces)
