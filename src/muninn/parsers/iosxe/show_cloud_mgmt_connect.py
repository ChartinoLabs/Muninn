"""Parser for 'show cloud-mgmt connect' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class DeviceEntry(TypedDict):
    """Schema for a single device in cloud management registration."""

    pid: str
    serial_number: str
    mac_address: str
    status: str
    timestamp_utc: str
    cloud_id: NotRequired[str]
    meraki_id: NotRequired[str]
    error: NotRequired[str]


class TunnelConfigResult(TypedDict):
    """Schema for the tunnel configuration section."""

    fetch_state: str
    last_fetch_utc: NotRequired[str]
    next_fetch_utc: NotRequired[str]
    config_server: NotRequired[str]
    primary: NotRequired[str]
    secondary: NotRequired[str]
    client_ipv6_addr: NotRequired[str]
    network_name: NotRequired[str]
    fetch_fail: NotRequired[str]


class TunnelStateResult(TypedDict):
    """Schema for the tunnel state section."""

    primary: str
    secondary: str
    primary_last_change_utc: NotRequired[str]
    secondary_last_change_utc: NotRequired[str]
    client_last_restart_utc: NotRequired[str]


class TunnelInterfaceResult(TypedDict):
    """Schema for the tunnel interface section."""

    status: str
    rx_packets: int
    tx_packets: int
    rx_errors: int
    tx_errors: int
    rx_drop_packets: int
    tx_drop_packets: int
    vrf: NotRequired[str]
    rx_packets_last_5s: NotRequired[int]
    tx_packets_last_5s: NotRequired[int]
    rx_errors_last_5s: NotRequired[int]
    tx_errors_last_5s: NotRequired[int]
    rx_drop_packets_last_5s: NotRequired[int]
    tx_drop_packets_last_5s: NotRequired[int]


class DeviceRegistrationResult(TypedDict):
    """Schema for the device registration section."""

    url: str
    devices: NotRequired[dict[str, DeviceEntry]]


class ShowCloudMgmtConnectResult(TypedDict):
    """Schema for 'show cloud-mgmt connect' parsed output."""

    service_enabled: bool
    tunnel_config: NotRequired[TunnelConfigResult]
    tunnel_state: NotRequired[TunnelStateResult]
    tunnel_interface: NotRequired[TunnelInterfaceResult]
    device_registration: NotRequired[DeviceRegistrationResult]


# Section header pattern: "Cloud-Mgmt Tunnel Config", "Cloud-Mgmt Tunnel State", etc.
_SECTION_HEADER = re.compile(r"^Cloud-Mgmt\s+(.+)$", re.IGNORECASE)

# Key-value pattern: "  Fetch State:    Config fetch succeeded"
_KEY_VALUE = re.compile(r"^\s+(.+?):\s+(.*?)\s*$")

# Service line: "Service cloud-mgmt connect: enable"
_SERVICE_LINE = re.compile(r"^Service\s+cloud-mgmt\s+connect:\s+(\S+)", re.IGNORECASE)

# Disabled line: "service cloud-mgmt connect is disabled"
_DISABLED_LINE = re.compile(
    r"^service\s+cloud-mgmt\s+connect\s+is\s+disabled$", re.IGNORECASE
)

# Separator line
_SEPARATOR = re.compile(r"^-+$")

# Map of raw key names (lowercased, spaces to underscores) to clean field names
_KEY_MAP: dict[str, str] = {
    "fetch_state": "fetch_state",
    "fetch_fail": "fetch_fail",
    "last_fetch(utc)": "last_fetch_utc",
    "next_fetch(utc)": "next_fetch_utc",
    "config_server": "config_server",
    "primary": "primary",
    "secondary": "secondary",
    "client_ipv6_addr": "client_ipv6_addr",
    "network_name": "network_name",
    "primary_last_change(utc)": "primary_last_change_utc",
    "secondary_last_change(utc)": "secondary_last_change_utc",
    "client_last_restart(utc)": "client_last_restart_utc",
    "vrf": "vrf",
    "status": "status",
    "rx_packets": "rx_packets",
    "tx_packets": "tx_packets",
    "rx_errors": "rx_errors",
    "tx_errors": "tx_errors",
    "rx_drop_packets": "rx_drop_packets",
    "tx_drop_packets": "tx_drop_packets",
    "rx_packets_(last_5s)": "rx_packets_last_5s",
    "tx_packets_(last_5s)": "tx_packets_last_5s",
    "rx_errors_(last_5s)": "rx_errors_last_5s",
    "tx_errors_(last_5s)": "tx_errors_last_5s",
    "rx_drop_packets_(last_5s)": "rx_drop_packets_last_5s",
    "tx_drop_packets_(last_5s)": "tx_drop_packets_last_5s",
    "url": "url",
    "device_number": "device_number",
    "pid": "pid",
    "serial_number": "serial_number",
    "cloud_id": "cloud_id",
    "meraki_id": "meraki_id",
    "mac_address": "mac_address",
    "timestamp(utc)": "timestamp_utc",
    "error": "error",
}

# Section name mapping from header text to result key
_SECTION_MAP: dict[str, str] = {
    "tunnel_config": "tunnel_config",
    "tunnel_state": "tunnel_state",
    "tunnel_interface": "tunnel_interface",
    "device_registration": "device_registration",
}

# Fields that should be parsed as integers
_INTEGER_FIELDS: set[str] = {
    "rx_packets",
    "tx_packets",
    "rx_errors",
    "tx_errors",
    "rx_drop_packets",
    "tx_drop_packets",
    "rx_packets_last_5s",
    "tx_packets_last_5s",
    "rx_errors_last_5s",
    "tx_errors_last_5s",
    "rx_drop_packets_last_5s",
    "tx_drop_packets_last_5s",
}


def _normalize_key(raw_key: str) -> str:
    """Normalize a raw key from CLI output to a clean field name."""
    normalized = raw_key.strip().lower().replace(" ", "_")
    return _KEY_MAP.get(normalized, normalized)


@register(OS.CISCO_IOSXE, "show cloud-mgmt connect")
class ShowCloudMgmtConnectParser(BaseParser[ShowCloudMgmtConnectResult]):
    """Parser for 'show cloud-mgmt connect' command.

    Parses the cloud management connectivity status including tunnel
    configuration, tunnel state, tunnel interface statistics, and
    device registration details.

    Example output::

        Service cloud-mgmt connect: enable

        Cloud-Mgmt Tunnel Config
        ------------------------------------
          Fetch State:                Config fetch succeeded
          Last Fetch(UTC):            2025-03-21 09:13:31
          Config Server:              cs1-2037.meraki.com
          Primary:                    usw.nt.meraki.com
          Secondary:                  use.nt.meraki.com

        Cloud-Mgmt Tunnel State
        ------------------------------------
          Primary:                    Up
          Secondary:                  Up

        Cloud-Mgmt Tunnel Interface
        ------------------------------------
          Status:                     Enable
          Rx Packets:                 53
          Tx Packets:                 63

        Cloud-Mgmt Device Registration
        ------------------------------------
          url:                        https://catalyst.meraki.com/nodes/register
          Device Number:              1
          PID:                        C9350-48U
          Serial Number:              FOC2829Y10T
          Status:                     Registered
    """

    tags: ClassVar[frozenset[str]] = frozenset({"sdwan"})

    @classmethod
    def parse(cls, output: str) -> ShowCloudMgmtConnectResult:
        """Parse 'show cloud-mgmt connect' output.

        Args:
            output: Raw CLI output from 'show cloud-mgmt connect' command.

        Returns:
            Parsed cloud management connect data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        state = _ParseState()

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or _SEPARATOR.match(stripped):
                continue

            if _parse_service_line(stripped, state):
                continue

            if _parse_section_header(stripped, state):
                continue

            _parse_key_value(line, state)

        # Save the last section
        _save_section(state)

        if not state.service_found:
            msg = "No cloud management connect information found in output"
            raise ValueError(msg)

        return ShowCloudMgmtConnectResult(**state.result)  # type: ignore[typeddict-item]


class _ParseState:
    """Mutable state container for the section-based parser."""

    def __init__(self) -> None:
        self.result: dict = {}
        self.current_section: str | None = None
        self.section_dict: dict = {}
        self.current_device: dict | None = None
        self.current_device_num: str | None = None
        self.service_found: bool = False


def _parse_service_line(stripped: str, state: _ParseState) -> bool:
    """Try to parse the service enable/disable line. Return True if matched."""
    service_match = _SERVICE_LINE.match(stripped)
    if service_match:
        state.result["service_enabled"] = service_match.group(1).lower() == "enable"
        state.service_found = True
        return True

    disabled_match = _DISABLED_LINE.match(stripped)
    if disabled_match:
        state.result["service_enabled"] = False
        state.service_found = True
        return True

    return False


def _parse_section_header(stripped: str, state: _ParseState) -> bool:
    """Try to parse a section header line. Return True if matched."""
    header_match = _SECTION_HEADER.match(stripped)
    if not header_match:
        return False

    _save_section(state)

    header_text = header_match.group(1).strip().lower().replace(" ", "_")
    section_key = _SECTION_MAP.get(header_text)
    if section_key:
        state.current_section = section_key
        state.section_dict = {}
        state.current_device = None
        state.current_device_num = None
    else:
        state.current_section = None

    return True


def _parse_key_value(line: str, state: _ParseState) -> None:
    """Parse a key-value line and add it to the current section."""
    kv_match = _KEY_VALUE.match(line)
    if not kv_match or state.current_section is None:
        return

    raw_key = kv_match.group(1)
    raw_value = kv_match.group(2).strip()
    field_name = _normalize_key(raw_key)

    if state.current_section == "device_registration":
        _handle_registration_field(field_name, raw_value, state)
        return

    if not raw_value:
        return

    if field_name in _INTEGER_FIELDS:
        state.section_dict[field_name] = int(raw_value)
    else:
        state.section_dict[field_name] = raw_value


def _handle_registration_field(
    field_name: str, raw_value: str, state: _ParseState
) -> None:
    """Handle a key-value field within the device registration section."""
    if field_name == "device_number":
        # Save any previous device before starting a new one
        if state.current_device is not None and state.current_device_num is not None:
            state.section_dict.setdefault("devices", {})[state.current_device_num] = (
                state.current_device
            )
        state.current_device_num = raw_value
        state.current_device = {}
        return

    if state.current_device is not None:
        if raw_value:
            state.current_device[field_name] = raw_value
    elif raw_value:
        state.section_dict[field_name] = raw_value


def _save_section(state: _ParseState) -> None:
    """Save the current section data into the result dict."""
    if state.current_section is None:
        return

    # Save last device if in registration section
    if (
        state.current_section == "device_registration"
        and state.current_device is not None
        and state.current_device_num is not None
    ):
        state.section_dict.setdefault("devices", {})[state.current_device_num] = (
            state.current_device
        )

    if state.section_dict:
        state.result[state.current_section] = state.section_dict
