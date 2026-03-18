"""Parser for 'show authentication sessions method details' command on IOS."""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.utils import canonical_interface_name


class MethodEntry(TypedDict):
    """Schema for a single authentication method status."""

    method: str
    state: str


class SessionEntry(TypedDict):
    """Schema for a single authentication session."""

    interface: str
    iif_id: str
    mac_address: str
    ipv4_address: str
    user_name: str
    status: str
    domain: str
    oper_host_mode: str
    oper_control_dir: str
    current_policy: str
    common_session_id: str
    acct_session_id: str
    handle: str
    methods: dict[str, MethodEntry]
    ipv6_address: NotRequired[str]
    device_type: NotRequired[str]
    device_name: NotRequired[str]
    session_timeout: NotRequired[int]
    session_timeout_remaining: NotRequired[int]
    timeout_action: NotRequired[str]
    acct_update_timeout: NotRequired[int]
    acct_update_remaining: NotRequired[int]
    server_policy_vn: NotRequired[str]
    server_policy_vlan: NotRequired[int]
    server_policy_sgt: NotRequired[int]
    server_policy_session_timeout: NotRequired[int]
    server_policy_template: NotRequired[str]
    resultant_policy_vn: NotRequired[str]
    resultant_policy_vlan: NotRequired[int]
    resultant_policy_sgt: NotRequired[int]


ShowAuthenticationSessionsMethodDetailsResult = dict[str, dict[str, SessionEntry]]


# --- Session block separator ---
_BLOCK_SEPARATOR_RE = SEPARATOR_DASH_RE

# --- Key-value field patterns ---
_INTERFACE_RE = re.compile(r"^\s*Interface:\s+(\S+)\s*$")
_IIF_ID_RE = re.compile(r"^\s*IIF-ID:\s+(\S+)\s*$")
_MAC_RE = re.compile(r"^\s*MAC Address:\s+(\S+)\s*$")
_IPV6_RE = re.compile(r"^\s*IPv6 Address:\s+(\S+)\s*$")
_IPV4_RE = re.compile(r"^\s*IPv4 Address:\s+(\S+)\s*$")
_USER_RE = re.compile(r"^\s*User-Name:\s+(.+?)\s*$")
_DEVICE_TYPE_RE = re.compile(r"^\s*Device-type:\s+(.+?)\s*$")
_DEVICE_NAME_RE = re.compile(r"^\s*Device-name:\s+(.+?)\s*$")
_STATUS_RE = re.compile(r"^\s*Status:\s+(\S+)\s*$")
_DOMAIN_RE = re.compile(r"^\s*Domain:\s+(\S+)\s*$")
_HOST_MODE_RE = re.compile(r"^\s*Oper host mode:\s+(\S+)\s*$")
_CONTROL_DIR_RE = re.compile(r"^\s*Oper control dir:\s+(\S+)\s*$")
_SESSION_TIMEOUT_RE = re.compile(
    r"^\s*Session timeout:\s+"
    r"(?:(\d+)s\s+\(\w+\),\s+Remaining:\s+(\d+)s|(\S+))\s*$"
)
_TIMEOUT_ACTION_RE = re.compile(r"^\s*Timeout action:\s+(.+?)\s*$")
_ACCT_UPDATE_RE = re.compile(
    r"^\s*Acct update timeout:\s+(\d+)s\s+\(\w+\),\s+Remaining:\s+(\d+)s\s*$"
)
_COMMON_SESSION_RE = re.compile(r"^\s*Common Session ID:\s+(\S+)\s*$")
_ACCT_SESSION_RE = re.compile(r"^\s*Acct Session ID:\s+(\S+)\s*$")
_HANDLE_RE = re.compile(r"^\s*Handle:\s+(\S+)\s*$")
_CURRENT_POLICY_RE = re.compile(r"^\s*Current Policy:\s+(\S+)\s*$")

# --- Server/Resultant policy fields ---
_VN_VALUE_RE = re.compile(r"^\s*VN Value:\s+(\S+)\s*$")
_VLAN_GROUP_RE = re.compile(r"^\s*Vlan Group:\s+Vlan:\s+(\d+)\s*$")
_SGT_VALUE_RE = re.compile(r"^\s*SGT Value:\s+(\d+)\s*$")
_SERVER_SESSION_TIMEOUT_RE = re.compile(r"^\s*Session-Timeout:\s+(\d+)\s+sec\s*$")
_INTERFACE_TEMPLATE_RE = re.compile(r"^\s*Interface Template:\s+(\S+)\s*$")

# --- Method status ---
_METHOD_RE = re.compile(r"^\s+(\S+)\s+((?:Authc|Authz)\s+\S+|Stopped|Running)\s*$")

# --- Section headers ---
_SERVER_POLICIES_RE = re.compile(r"^Server Policies:\s*$")
_RESULTANT_POLICIES_RE = re.compile(r"^Resultant Policies:\s*$")
_METHOD_STATUS_RE = re.compile(r"^Method status list:\s*$")
_METHOD_HEADER_RE = re.compile(r"^\s+Method\s+State\s*$")

_UNKNOWN_IPV6 = "Unknown"
_UNKNOWN_DEVICE_NAME = "Unknown Device"


def _store_interface(m: re.Match[str], entry: dict) -> None:
    entry["interface"] = canonical_interface_name(m.group(1), os=OS.CISCO_IOS)


def _store_ipv6(m: re.Match[str], entry: dict) -> None:
    if m.group(1) != _UNKNOWN_IPV6:
        entry["ipv6_address"] = m.group(1)


def _store_device_name(m: re.Match[str], entry: dict) -> None:
    if m.group(1) != _UNKNOWN_DEVICE_NAME:
        entry["device_name"] = m.group(1)


def _store_session_timeout(m: re.Match[str], entry: dict) -> None:
    if m.group(1) is not None:
        entry["session_timeout"] = int(m.group(1))
        entry["session_timeout_remaining"] = int(m.group(2))


def _store_acct_update(m: re.Match[str], entry: dict) -> None:
    entry["acct_update_timeout"] = int(m.group(1))
    entry["acct_update_remaining"] = int(m.group(2))


def _store_str(key: str) -> Callable[[re.Match[str], dict], None]:
    """Create a handler that stores match group 1 as a string."""

    def handler(m: re.Match[str], entry: dict) -> None:
        entry[key] = m.group(1)

    return handler


# Dispatch table: (pattern, handler) pairs for session field parsing.
# Evaluated in order; first match wins for each line.
_SESSION_FIELD_DISPATCH: list[
    tuple[re.Pattern[str], Callable[[re.Match[str], dict], None]]
] = [
    (_INTERFACE_RE, _store_interface),
    (_IIF_ID_RE, _store_str("iif_id")),
    (_MAC_RE, _store_str("mac_address")),
    (_IPV6_RE, _store_ipv6),
    (_IPV4_RE, _store_str("ipv4_address")),
    (_USER_RE, _store_str("user_name")),
    (_DEVICE_TYPE_RE, _store_str("device_type")),
    (_DEVICE_NAME_RE, _store_device_name),
    (_STATUS_RE, _store_str("status")),
    (_DOMAIN_RE, _store_str("domain")),
    (_HOST_MODE_RE, _store_str("oper_host_mode")),
    (_CONTROL_DIR_RE, _store_str("oper_control_dir")),
    (_SESSION_TIMEOUT_RE, _store_session_timeout),
    (_TIMEOUT_ACTION_RE, _store_str("timeout_action")),
    (_ACCT_UPDATE_RE, _store_acct_update),
    (_COMMON_SESSION_RE, _store_str("common_session_id")),
    (_ACCT_SESSION_RE, _store_str("acct_session_id")),
    (_HANDLE_RE, _store_str("handle")),
    (_CURRENT_POLICY_RE, _store_str("current_policy")),
]


def _split_session_blocks(output: str) -> list[list[str]]:
    """Split output into per-session blocks separated by dashed lines."""
    blocks: list[list[str]] = []
    current: list[str] = []

    for line in output.splitlines():
        if _BLOCK_SEPARATOR_RE.match(line.strip()):
            if current:
                blocks.append(current)
                current = []
            continue
        current.append(line)

    if current and any(line.strip() for line in current):
        blocks.append(current)

    return blocks


def _parse_session_fields(lines: list[str], entry: dict) -> None:
    """Parse core session key-value fields via dispatch table."""
    for line in lines:
        for pattern, handler in _SESSION_FIELD_DISPATCH:
            m = pattern.match(line)
            if m:
                handler(m, entry)
                break


def _is_section_boundary(stripped: str) -> bool:
    """Check if a stripped line marks a policy/method section boundary."""
    return bool(
        _SERVER_POLICIES_RE.match(stripped)
        or _RESULTANT_POLICIES_RE.match(stripped)
        or _METHOD_STATUS_RE.match(stripped)
    )


def _parse_policy_line(line: str, prefix: str, entry: dict) -> None:
    """Parse a single line within a policy section."""
    m = _VN_VALUE_RE.match(line)
    if m:
        entry[f"{prefix}_vn"] = m.group(1)
        return

    m = _VLAN_GROUP_RE.match(line)
    if m:
        entry[f"{prefix}_vlan"] = int(m.group(1))
        return

    m = _SGT_VALUE_RE.match(line)
    if m:
        # Take the first SGT value only (duplicates appear in output)
        if f"{prefix}_sgt" not in entry:
            entry[f"{prefix}_sgt"] = int(m.group(1))
        return

    m = _SERVER_SESSION_TIMEOUT_RE.match(line)
    if m:
        entry[f"{prefix}_session_timeout"] = int(m.group(1))
        return

    m = _INTERFACE_TEMPLATE_RE.match(line)
    if m:
        entry[f"{prefix}_template"] = m.group(1)


def _parse_policy_section(
    lines: list[str],
    start_idx: int,
    prefix: str,
    entry: dict,
) -> int:
    """Parse a Server Policies or Resultant Policies section.

    Returns the index after the last consumed line.
    """
    idx = start_idx
    while idx < len(lines):
        if _is_section_boundary(lines[idx].strip()) and idx > start_idx:
            break
        _parse_policy_line(lines[idx], prefix, entry)
        idx += 1

    return idx


def _parse_methods(lines: list[str], start_idx: int, entry: dict) -> None:
    """Parse Method status list section."""
    methods: dict[str, MethodEntry] = {}

    for line in lines[start_idx:]:
        if _METHOD_HEADER_RE.match(line):
            continue
        m = _METHOD_RE.match(line)
        if m:
            methods[m.group(1)] = MethodEntry(method=m.group(1), state=m.group(2))

    entry["methods"] = methods


def _parse_sections(lines: list[str], entry: dict) -> None:
    """Parse policy sections and method status from a block."""
    idx = 0
    while idx < len(lines):
        stripped = lines[idx].strip()

        if _SERVER_POLICIES_RE.match(stripped):
            idx = _parse_policy_section(lines, idx + 1, "server_policy", entry)
            continue

        if _RESULTANT_POLICIES_RE.match(stripped):
            idx = _parse_policy_section(lines, idx + 1, "resultant_policy", entry)
            continue

        if _METHOD_STATUS_RE.match(stripped):
            _parse_methods(lines, idx + 1, entry)
            break

        idx += 1

    if "methods" not in entry:
        entry["methods"] = {}


def _parse_block(lines: list[str]) -> tuple[str, str, SessionEntry] | None:
    """Parse a single session block.

    Returns:
        Tuple of (interface_name, session_id, entry) or None if unparseable.
    """
    if not lines or not any(line.strip() for line in lines):
        return None

    entry: dict = {}
    _parse_session_fields(lines, entry)

    if "interface" not in entry or "common_session_id" not in entry:
        return None

    _parse_sections(lines, entry)

    interface = entry["interface"]
    session_id = entry["common_session_id"]
    return interface, session_id, entry  # type: ignore[return-value]


@register(OS.CISCO_IOS, "show authentication sessions method details")
class ShowAuthenticationSessionsMethodDetailsParser(
    BaseParser[ShowAuthenticationSessionsMethodDetailsResult],
):
    """Parser for 'show authentication sessions method details' on IOS."""

    tags: ClassVar[frozenset[str]] = frozenset({"security"})

    @classmethod
    def parse(cls, output: str) -> ShowAuthenticationSessionsMethodDetailsResult:
        """Parse 'show authentication sessions method details' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed authentication session details keyed by interface name.

        Raises:
            ValueError: If no authentication session entries found in output.
        """
        blocks = _split_session_blocks(output)
        sessions: ShowAuthenticationSessionsMethodDetailsResult = {}

        for block_lines in blocks:
            result = _parse_block(block_lines)
            if result is None:
                continue
            interface, session_id, entry = result
            sessions.setdefault(interface, {})[session_id] = entry

        if not sessions:
            msg = "No authentication session entries found in output"
            raise ValueError(msg)

        return sessions
