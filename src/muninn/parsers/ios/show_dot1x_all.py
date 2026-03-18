"""Parser for 'show dot1x all' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class Dot1xClientEntry(TypedDict):
    """Schema for a single dot1x client (supplicant) entry."""

    eap_method: str
    mac_address: str
    session_id: str
    auth_sm_state: NotRequired[str]
    auth_bend_sm_state: NotRequired[str]


class Dot1xInterfaceEntry(TypedDict):
    """Schema for dot1x information on a single interface."""

    interface: str
    pae: str
    port_control: NotRequired[str]
    control_direction: NotRequired[str]
    host_mode: NotRequired[str]
    re_authentication: NotRequired[str]
    quiet_period: NotRequired[int]
    server_timeout: NotRequired[int]
    supp_timeout: NotRequired[int]
    re_auth_period: NotRequired[int]
    re_auth_period_source: NotRequired[str]
    re_auth_max: NotRequired[int]
    max_req: NotRequired[int]
    tx_period: NotRequired[int]
    rate_limit_period: NotRequired[int]
    start_period: NotRequired[int]
    auth_period: NotRequired[int]
    held_period: NotRequired[int]
    max_start: NotRequired[int]
    credentials_profile: NotRequired[str]
    eap_profile: NotRequired[str]
    clients: NotRequired[list[Dot1xClientEntry]]


class ShowDot1xAllResult(TypedDict):
    """Schema for 'show dot1x all' parsed output."""

    sysauthcontrol: NotRequired[str]
    protocol_version: NotRequired[int]
    critical_recovery_delay: NotRequired[int]
    critical_eapol: NotRequired[str]
    interfaces: dict[str, Dot1xInterfaceEntry]


# --- Global setting patterns ---
_SYSAUTHCONTROL_RE = re.compile(r"^Sysauthcontrol\s+(\S+)", re.IGNORECASE)
_PROTOCOL_VERSION_RE = re.compile(r"^Dot1x Protocol Version\s+(\d+)", re.IGNORECASE)
_CRITICAL_DELAY_RE = re.compile(r"^Critical Recovery Delay\s+(\d+)", re.IGNORECASE)
_CRITICAL_EAPOL_RE = re.compile(r"^Critical EAPOL\s+(\S+)", re.IGNORECASE)

# --- Interface header pattern ---
_INTERFACE_HEADER_RE = re.compile(r"^Dot1x Info for\s+(\S+)")

# --- Per-interface key=value patterns ---
_KV_RE = re.compile(r"^(\S+)\s+=\s+(.+)$")

# --- ReAuthPeriod with source annotation ---
_REAUTH_PERIOD_RE = re.compile(r"^(\d+)\s*\((.+)\)\s*$")

# --- Client list patterns ---
_CLIENT_LIST_HEADER_RE = re.compile(
    r"^Dot1x (Authenticator|Supplicant) Client List", re.IGNORECASE
)
_CLIENT_LIST_EMPTY_RE = re.compile(
    r"^Dot1x (Authenticator|Supplicant) Client List Empty", re.IGNORECASE
)
_EAP_METHOD_RE = re.compile(r"^EAP Method\s+=\s+(.+)$")
_SUPPLICANT_RE = re.compile(r"^Supplicant\s+=\s+(\S+)")
_SESSION_ID_RE = re.compile(r"^Session ID\s+=\s+(\S+)")
_AUTH_SM_RE = re.compile(r"^Auth SM State\s+=\s+(\S+)")
_AUTH_BEND_SM_RE = re.compile(r"^Auth BEND SM State\s+=\s+(\S+)")


def _parse_global_settings(lines: list[str]) -> dict:
    """Extract global dot1x settings from lines before any interface block."""
    settings: dict = {}
    for line in lines:
        stripped = line.strip()

        m = _SYSAUTHCONTROL_RE.match(stripped)
        if m:
            settings["sysauthcontrol"] = m.group(1)
            continue

        m = _PROTOCOL_VERSION_RE.match(stripped)
        if m:
            settings["protocol_version"] = int(m.group(1))
            continue

        m = _CRITICAL_DELAY_RE.match(stripped)
        if m:
            settings["critical_recovery_delay"] = int(m.group(1))
            continue

        m = _CRITICAL_EAPOL_RE.match(stripped)
        if m:
            settings["critical_eapol"] = m.group(1)
            continue

    return settings


def _split_interface_blocks(output: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Split output into global lines and per-interface text blocks.

    Returns:
        Tuple of (global_lines, list of (raw_interface_name, block_text)).
    """
    global_lines: list[str] = []
    blocks: list[tuple[str, str]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        m = _INTERFACE_HEADER_RE.match(stripped)
        if m:
            if current_name is not None:
                blocks.append((current_name, "\n".join(current_lines)))
            current_name = m.group(1)
            current_lines = []
        elif current_name is None:
            global_lines.append(line)
        else:
            current_lines.append(line)

    if current_name is not None:
        blocks.append((current_name, "\n".join(current_lines)))

    return global_lines, blocks


# Mapping from raw key names to typed dict field names
_KEY_MAP: dict[str, str] = {
    "pae": "pae",
    "portcontrol": "port_control",
    "controldirection": "control_direction",
    "hostmode": "host_mode",
    "reauthentication": "re_authentication",
    "quietperiod": "quiet_period",
    "servertimeout": "server_timeout",
    "supptimeout": "supp_timeout",
    "reauthperiod": "re_auth_period",
    "reauthmax": "re_auth_max",
    "maxreq": "max_req",
    "txperiod": "tx_period",
    "ratelimitperiod": "rate_limit_period",
    "startperiod": "start_period",
    "authperiod": "auth_period",
    "heldperiod": "held_period",
    "maxstart": "max_start",
}

# Fields that should be stored as integers
_INT_FIELDS: set[str] = {
    "quiet_period",
    "server_timeout",
    "supp_timeout",
    "re_auth_period",
    "re_auth_max",
    "max_req",
    "tx_period",
    "rate_limit_period",
    "start_period",
    "auth_period",
    "held_period",
    "max_start",
}


# Ordered list of (pattern, field_name) for client detail lines
_CLIENT_FIELD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_SUPPLICANT_RE, "mac_address"),
    (_SESSION_ID_RE, "session_id"),
    (_AUTH_SM_RE, "auth_sm_state"),
    (_AUTH_BEND_SM_RE, "auth_bend_sm_state"),
]


def _flush_client(clients: list[Dot1xClientEntry], current: dict | None) -> None:
    """Append the current client to the list if it has a MAC address."""
    if current is not None and "mac_address" in current:
        clients.append(current)  # type: ignore[arg-type]


def _parse_clients(lines: list[str]) -> list[Dot1xClientEntry]:
    """Parse dot1x client entries from interface block lines."""
    clients: list[Dot1xClientEntry] = []
    current: dict | None = None

    for line in lines:
        stripped = line.strip()

        m = _EAP_METHOD_RE.match(stripped)
        if m:
            _flush_client(clients, current)
            current = {"eap_method": m.group(1).strip()}
            continue

        if current is None:
            continue

        for pattern, field in _CLIENT_FIELD_PATTERNS:
            m = pattern.match(stripped)
            if m:
                current[field] = m.group(1)
                break

    _flush_client(clients, current)
    return clients


def _find_client_list_start(block_lines: list[str]) -> int | None:
    """Find the line index where the client list section begins."""
    for idx, line in enumerate(block_lines):
        stripped = line.strip()
        if _CLIENT_LIST_EMPTY_RE.match(stripped):
            return idx
        if _CLIENT_LIST_HEADER_RE.match(stripped):
            return idx
    return None


# Multi-word key patterns that _KV_RE cannot capture
_CREDENTIALS_PROFILE_RE = re.compile(r"^Credentials profile\s+=\s+(.+)$")
_EAP_PROFILE_RE = re.compile(r"^EAP profile\s+=\s+(.+)$")


def _assign_kv_field(entry: dict, field: str, raw_value: str) -> None:
    """Assign a single key-value field to the entry dict."""
    if field in _INT_FIELDS:
        # Handle values with source annotation, e.g. "3600 (Locally configured)"
        period_m = _REAUTH_PERIOD_RE.match(raw_value)
        if period_m:
            entry[field] = int(period_m.group(1))
            if field == "re_auth_period":
                entry["re_auth_period_source"] = period_m.group(2).strip()
        else:
            entry[field] = int(raw_value)
    else:
        entry[field] = raw_value


def _parse_kv_lines(kv_lines: list[str], entry: dict) -> None:
    """Parse key=value and multi-word key lines into the entry dict."""
    for line in kv_lines:
        stripped = line.strip()

        m = _KV_RE.match(stripped)
        if m:
            field = _KEY_MAP.get(m.group(1).lower())
            if field is not None:
                _assign_kv_field(entry, field, m.group(2).strip())
            continue

        cred_m = _CREDENTIALS_PROFILE_RE.match(stripped)
        if cred_m:
            entry["credentials_profile"] = cred_m.group(1).strip()
            continue

        eap_m = _EAP_PROFILE_RE.match(stripped)
        if eap_m:
            entry["eap_profile"] = eap_m.group(1).strip()


def _parse_interface_block(raw_name: str, block: str) -> Dot1xInterfaceEntry:
    """Parse a single interface block into a structured entry."""
    intf_name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)
    entry: dict = {"interface": intf_name}
    block_lines = block.splitlines()

    client_start = _find_client_list_start(block_lines)

    # Parse key=value pairs (only lines before client list)
    kv_lines = block_lines[:client_start] if client_start is not None else block_lines
    _parse_kv_lines(kv_lines, entry)

    # Parse client list if present and not empty
    if client_start is not None and not _CLIENT_LIST_EMPTY_RE.match(
        block_lines[client_start].strip()
    ):
        clients = _parse_clients(block_lines[client_start:])
        if clients:
            entry["clients"] = clients

    return entry  # type: ignore[return-value]


@register(OS.CISCO_IOS, "show dot1x all")
class ShowDot1xAllParser(BaseParser[ShowDot1xAllResult]):
    """Parser for 'show dot1x all' on IOS.

    Parses global dot1x system settings and per-interface dot1x
    configuration including PAE role, timers, and client lists.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowDot1xAllResult:
        """Parse 'show dot1x all' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed dot1x information with global settings and interfaces.

        Raises:
            ValueError: If no dot1x interface information found.
        """
        global_lines, blocks = _split_interface_blocks(output)

        if not blocks:
            msg = "No dot1x interface information found in output"
            raise ValueError(msg)

        result: ShowDot1xAllResult = {"interfaces": {}}

        # Add global settings
        settings = _parse_global_settings(global_lines)
        for key, value in settings.items():
            result[key] = value  # type: ignore[literal-required]

        # Parse each interface block
        for raw_name, block_text in blocks:
            entry = _parse_interface_block(raw_name, block_text)
            result["interfaces"][entry["interface"]] = entry

        return result
