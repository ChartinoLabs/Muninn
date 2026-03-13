"""Parser for 'show port-security interface <interface>' on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowPortSecurityInterfaceResult(TypedDict):
    """Schema for 'show port-security interface <interface>' parsed output.

    Flat dict representing port-security status for a single interface.
    """

    port_security: str
    port_status: str
    violation_mode: str
    aging_time: int
    aging_type: str
    secure_static_address_aging: str
    maximum_mac_addresses: int
    total_mac_addresses: int
    configured_mac_addresses: int
    sticky_mac_addresses: int
    security_violation_count: int
    last_source_address: NotRequired[str]
    last_source_address_vlan: NotRequired[int]


# Pattern for key-value lines with " : " separator
_KV_RE = re.compile(r"^\s*(.+?)\s*:\s*(.+?)\s*$")

# Pattern for the combined "Last Source Address:Vlan" field
_LAST_SRC_RE = re.compile(r"^\s*Last Source Address:Vlan\s*:\s*(\S+):(\d+)\s*$")

# Map of normalized field labels to output keys and value types
_FIELD_MAP: dict[str, tuple[str, type]] = {
    "port security": ("port_security", str),
    "port status": ("port_status", str),
    "violation mode": ("violation_mode", str),
    "aging time": ("aging_time", int),
    "aging type": ("aging_type", str),
    "securestatic address aging": ("secure_static_address_aging", str),
    "maximum mac addresses": ("maximum_mac_addresses", int),
    "total mac addresses": ("total_mac_addresses", int),
    "configured mac addresses": ("configured_mac_addresses", int),
    "sticky mac addresses": ("sticky_mac_addresses", int),
    "security violation count": ("security_violation_count", int),
}

# Null MAC address indicating no source has been seen
_NULL_MAC = "0000.0000.0000"


def _parse_int_field(raw: str, label: str) -> int:
    """Parse an integer from a raw string, stripping any unit suffixes."""
    # Handle values like "1440 mins" — extract the leading integer
    numeric = raw.split()[0] if raw.split() else raw
    try:
        return int(numeric)
    except ValueError:
        msg = f"Cannot parse integer from {label!r} value: {raw!r}"
        raise ValueError(msg) from None


def _parse_last_source(line: str, result: dict[str, str | int]) -> bool:
    """Parse the 'Last Source Address:Vlan' line into result dict.

    Returns True if the line matched this field, False otherwise.
    """
    m = _LAST_SRC_RE.match(line)
    if not m:
        return False

    mac_addr = m.group(1)
    vlan_id = int(m.group(2))
    if mac_addr != _NULL_MAC:
        result["last_source_address"] = mac_addr
    if vlan_id != 0:
        result["last_source_address_vlan"] = vlan_id
    return True


def _parse_kv_line(line: str, result: dict[str, str | int]) -> None:
    """Parse a standard key-value line into result dict."""
    m = _KV_RE.match(line)
    if not m:
        return

    label = m.group(1).strip().lower()
    raw_value = m.group(2).strip()

    field = _FIELD_MAP.get(label)
    if field is None:
        return

    key, value_type = field
    if value_type is int:
        result[key] = _parse_int_field(raw_value, label)
    else:
        result[key] = raw_value


@register(OS.CISCO_IOS, r"show port-security interface (?P<interface>\S+)")
class ShowPortSecurityInterfaceParser(
    BaseParser[ShowPortSecurityInterfaceResult],
):
    """Parser for 'show port-security interface <interface>' on IOS.

    Parses port-security details for a single interface including max MAC
    addresses, violation mode, aging settings, and security violation count.
    """

    @classmethod
    def parse(cls, output: str) -> ShowPortSecurityInterfaceResult:
        """Parse 'show port-security interface <interface>' output."""
        result: dict[str, str | int] = {}

        for line in output.splitlines():
            if not line.strip():
                continue

            if _parse_last_source(line, result):
                continue

            _parse_kv_line(line, result)

        if not result:
            msg = "No port-security data found in output"
            raise ValueError(msg)

        return result  # type: ignore[return-value]
