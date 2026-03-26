"""Parser for 'show interface capabilities' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceCapabilitiesEntry(TypedDict):
    """Schema for a single interface capabilities entry."""

    model: str
    speed: str
    duplex: str
    trunk_encap_type: str
    channel: str
    broadcast_suppression: str
    flowcontrol: str
    qos_scheduling: str
    cos_rewrite: str
    tos_rewrite: str
    span: str
    udld: str
    link_debounce: str
    link_debounce_time: str
    mdix: str
    type: NotRequired[str]
    rate_mode: NotRequired[str]
    port_group_members: NotRequired[str]
    pvlan_trunk_capable: NotRequired[str]
    tdr_capable: NotRequired[str]
    fabricpath_capable: NotRequired[str]
    port_mode: NotRequired[str]
    fex_fabric: NotRequired[str]
    switched_fex_fabric: NotRequired[str]


class ShowInterfaceCapabilitiesResult(TypedDict):
    """Schema for 'show interface capabilities' parsed output."""

    interfaces: dict[str, InterfaceCapabilitiesEntry]


# Maps raw CLI field labels to normalized dictionary keys.
_FIELD_MAP: dict[str, str] = {
    "model": "model",
    "type": "type",
    "type (sfp capable)": "type",
    "speed": "speed",
    "duplex": "duplex",
    "trunk encap. type": "trunk_encap_type",
    "channel": "channel",
    "broadcast suppression": "broadcast_suppression",
    "flowcontrol": "flowcontrol",
    "rate mode": "rate_mode",
    "qos scheduling": "qos_scheduling",
    "cos rewrite": "cos_rewrite",
    "tos rewrite": "tos_rewrite",
    "span": "span",
    "udld": "udld",
    "link debounce": "link_debounce",
    "link debounce time": "link_debounce_time",
    "mdix": "mdix",
    "port group members": "port_group_members",
    "pvlan trunk capable": "pvlan_trunk_capable",
    "tdr capable": "tdr_capable",
    "fabricpath capable": "fabricpath_capable",
    "port mode": "port_mode",
    "fex fabric": "fex_fabric",
    "switched fex fabric": "switched_fex_fabric",
}

# Fields that are always required in the output.
_REQUIRED_FIELDS = frozenset(
    {
        "model",
        "speed",
        "duplex",
        "trunk_encap_type",
        "channel",
        "broadcast_suppression",
        "flowcontrol",
        "qos_scheduling",
        "cos_rewrite",
        "tos_rewrite",
        "span",
        "udld",
        "link_debounce",
        "link_debounce_time",
        "mdix",
    }
)

# Optional fields to add when present in mapped data.
_OPTIONAL_FIELDS = (
    "type",
    "rate_mode",
    "port_group_members",
    "pvlan_trunk_capable",
    "tdr_capable",
    "fabricpath_capable",
    "port_mode",
    "fex_fabric",
    "switched_fex_fabric",
)

# Pattern matching an interface name at the start of a block.
_INTERFACE_HEADER_PATTERN = re.compile(
    r"^(?:Eth(?:ernet)?|mgmt|Po(?:rt-channel)?|Lo(?:opback)?|Vlan|nve|"
    r"Ser(?:ial)?|Tu(?:nnel)?|Fa(?:stEthernet)?|Gi(?:gabitEthernet)?)\S*$",
    re.IGNORECASE,
)

# Pattern matching a key-value line like "  Model:  N5K-C5020P-BF-XL-SU"
_KEY_VALUE_PATTERN = re.compile(
    r"^\s+(?P<key>[^:]+?):\s+(?P<value>.+)$",
)


def _map_raw_fields(raw_fields: dict[str, str]) -> dict[str, str]:
    """Normalize raw CLI key-value pairs to canonical field names."""
    mapped: dict[str, str] = {}
    for raw_key, value in raw_fields.items():
        normalized_key = _FIELD_MAP.get(raw_key.lower())
        if normalized_key is not None:
            mapped[normalized_key] = value
    return mapped


def _build_entry(
    mapped: dict[str, str],
) -> InterfaceCapabilitiesEntry | None:
    """Build an InterfaceCapabilitiesEntry from mapped fields.

    Returns None if required fields are missing.
    """
    if not _REQUIRED_FIELDS.issubset(mapped):
        return None

    entry: InterfaceCapabilitiesEntry = {
        "model": mapped["model"],
        "speed": mapped["speed"],
        "duplex": mapped["duplex"],
        "trunk_encap_type": mapped["trunk_encap_type"],
        "channel": mapped["channel"],
        "broadcast_suppression": mapped["broadcast_suppression"],
        "flowcontrol": mapped["flowcontrol"],
        "qos_scheduling": mapped["qos_scheduling"],
        "cos_rewrite": mapped["cos_rewrite"],
        "tos_rewrite": mapped["tos_rewrite"],
        "span": mapped["span"],
        "udld": mapped["udld"],
        "link_debounce": mapped["link_debounce"],
        "link_debounce_time": mapped["link_debounce_time"],
        "mdix": mapped["mdix"],
    }

    for field_key in _OPTIONAL_FIELDS:
        if field_key in mapped:
            entry[field_key] = mapped[field_key]

    return entry


def _save_block(
    intf: str | None,
    raw_fields: dict[str, str],
    interfaces: dict[str, InterfaceCapabilitiesEntry],
) -> None:
    """Finalize and store a parsed interface block if valid."""
    if not intf or not raw_fields:
        return
    mapped = _map_raw_fields(raw_fields)
    entry = _build_entry(mapped)
    if entry is not None:
        interfaces[intf] = entry


@register(OS.CISCO_NXOS, "show interface capabilities")
class ShowInterfaceCapabilitiesParser(
    BaseParser[ShowInterfaceCapabilitiesResult],
):
    """Parser for 'show interface capabilities' command on NX-OS.

    Parses per-interface capability information including model, speed,
    duplex, trunk encapsulation, and feature support flags.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceCapabilitiesResult:
        """Parse 'show interface capabilities' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface capabilities keyed by canonical interface name.

        Raises:
            ValueError: If no interface capability blocks found.
        """
        interfaces: dict[str, InterfaceCapabilitiesEntry] = {}
        current_intf: str | None = None
        current_fields: dict[str, str] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if _INTERFACE_HEADER_PATTERN.match(stripped):
                _save_block(current_intf, current_fields, interfaces)
                current_intf = canonical_interface_name(
                    stripped,
                    os=OS.CISCO_NXOS,
                )
                current_fields = {}
                continue

            kv_match = _KEY_VALUE_PATTERN.match(line)
            if kv_match and current_intf is not None:
                current_fields[kv_match.group("key").strip()] = kv_match.group(
                    "value"
                ).strip()

        _save_block(current_intf, current_fields, interfaces)

        if not interfaces:
            msg = "No interface capability blocks found in output"
            raise ValueError(msg)

        return ShowInterfaceCapabilitiesResult(interfaces=interfaces)
