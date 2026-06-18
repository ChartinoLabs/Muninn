"""Parser for 'show license tech support' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# --- Placeholder values that should be omitted from output ---
_PLACEHOLDERS = frozenset({"<none>", "<empty>", "none", ""})


def _is_placeholder(value: str) -> bool:
    """Return True if value is a sentinel placeholder."""
    return value.strip().lower() in _PLACEHOLDERS


# --- Section header regexes ---
_SECTION_SMART_LICENSING_STATUS_RE = re.compile(
    r"^\s*Smart\s+Licensing\s+Status\s*$", re.IGNORECASE
)
_SECTION_LICENSE_CONVERSION_RE = re.compile(
    r"^\s*License\s+Conversion\s*:\s*$", re.IGNORECASE
)
_SECTION_EXPORT_AUTH_KEY_RE = re.compile(
    r"^\s*Export\s+Authorization\s+Key\s*:\s*$", re.IGNORECASE
)
_SECTION_UTILITY_RE = re.compile(r"^\s*Utility\s*:\s*$", re.IGNORECASE)
_SECTION_SMART_LICENSING_POLICY_RE = re.compile(
    r"^\s*Smart\s+Licensing\s+Using\s+Policy\s*:\s*$", re.IGNORECASE
)
_SECTION_ACCOUNT_INFO_RE = re.compile(
    r"^\s*Account\s+Information\s*:\s*$", re.IGNORECASE
)
_SECTION_DATA_PRIVACY_RE = re.compile(r"^\s*Data\s+Privacy\s*:\s*$", re.IGNORECASE)
_SECTION_TRANSPORT_RE = re.compile(r"^\s*Transport\s*:\s*$", re.IGNORECASE)
_SECTION_MISCELLANEOUS_RE = re.compile(r"^\s*Miscellaneous\s*:\s*$", re.IGNORECASE)
_SECTION_POLICY_RE = re.compile(r"^\s*Policy\s*:\s*$", re.IGNORECASE)

# Separator line of equals signs
_SEPARATOR_EQUALS_RE = re.compile(r"^\s*={3,}\s*$")

# Smart licensing enabled/disabled line
_SMART_LICENSING_IS_RE = re.compile(
    r"^\s*Smart\s+Licensing\s+is\s+(?P<status>\S+)\s*$", re.IGNORECASE
)

# Generic key-value pattern: "  Key: Value" or "  Key: Value"
_KV_RE = re.compile(r"^\s{2,}(?P<key>[^:]+?)\s*:\s*(?P<value>.*?)\s*$")


# --- TypedDict schema ---


class LicenseConversion(TypedDict):
    """Schema for the License Conversion section."""

    automatic_conversion_enabled: NotRequired[str]
    last_data_push: NotRequired[str]
    last_file_export: NotRequired[str]


class SmartLicensingUsingPolicy(TypedDict):
    """Schema for the Smart Licensing Using Policy section."""

    status: NotRequired[str]
    reporting_mode: NotRequired[str]


class AccountInformation(TypedDict):
    """Schema for the Account Information section."""

    smart_account: NotRequired[str]
    virtual_account: NotRequired[str]


class DataPrivacy(TypedDict):
    """Schema for the Data Privacy section."""

    sending_hostname: NotRequired[str]
    callhome_hostname_privacy: NotRequired[str]
    smart_licensing_hostname_privacy: NotRequired[str]
    version_privacy: NotRequired[str]


class Transport(TypedDict):
    """Schema for the Transport section."""

    type: NotRequired[str]
    cslu_address: NotRequired[str]
    proxy_address: NotRequired[str]
    proxy_port: NotRequired[str]
    proxy_username: NotRequired[str]
    proxy_password: NotRequired[str]
    server_identity_check: NotRequired[str]
    vrf: NotRequired[str]
    ip_mode: NotRequired[str]
    trust_point: NotRequired[str]


class Miscellaneous(TypedDict):
    """Schema for the Miscellaneous section."""

    custom_id: NotRequired[str]


class ShowLicenseTechSupportResult(TypedDict):
    """Schema for 'show license tech support' parsed output."""

    smart_licensing_status: NotRequired[str]
    license_conversion: NotRequired[LicenseConversion]
    export_authorization_key: NotRequired[str]
    utility_status: NotRequired[str]
    smart_licensing_using_policy: NotRequired[SmartLicensingUsingPolicy]
    account_information: NotRequired[AccountInformation]
    data_privacy: NotRequired[DataPrivacy]
    transport: NotRequired[Transport]
    miscellaneous: NotRequired[Miscellaneous]


# --- Section parsers ---


def _parse_license_conversion(
    lines: list[str], start: int, section_headers: list[re.Pattern[str]]
) -> tuple[dict[str, str], int]:
    """Parse the License Conversion section."""
    info: dict[str, str] = {}
    idx = start
    key_map = {
        "automatic conversion enabled": "automatic_conversion_enabled",
        "last data push": "last_data_push",
        "last file export": "last_file_export",
    }
    while idx < len(lines):
        line = lines[idx]
        if _is_section_header(line, section_headers):
            break
        if match := _KV_RE.match(line):
            key_lower = match.group("key").strip().lower()
            value = match.group("value").strip()
            if key_lower in key_map and not _is_placeholder(value):
                info[key_map[key_lower]] = value
        idx += 1
    return info, idx


def _parse_smart_licensing_policy(
    lines: list[str], start: int, section_headers: list[re.Pattern[str]]
) -> tuple[dict[str, str], int]:
    """Parse the Smart Licensing Using Policy section."""
    info: dict[str, str] = {}
    idx = start
    key_map = {
        "status": "status",
        "reporting mode": "reporting_mode",
    }
    while idx < len(lines):
        line = lines[idx]
        if _is_section_header(line, section_headers):
            break
        if match := _KV_RE.match(line):
            key_lower = match.group("key").strip().lower()
            value = match.group("value").strip()
            if key_lower in key_map and not _is_placeholder(value):
                info[key_map[key_lower]] = value
        idx += 1
    return info, idx


def _parse_account_information(
    lines: list[str], start: int, section_headers: list[re.Pattern[str]]
) -> tuple[dict[str, str], int]:
    """Parse the Account Information section."""
    info: dict[str, str] = {}
    idx = start
    key_map = {
        "smart account": "smart_account",
        "virtual account": "virtual_account",
    }
    while idx < len(lines):
        line = lines[idx]
        if _is_section_header(line, section_headers):
            break
        if match := _KV_RE.match(line):
            key_lower = match.group("key").strip().lower()
            value = match.group("value").strip()
            if key_lower in key_map and not _is_placeholder(value):
                info[key_map[key_lower]] = value
        idx += 1
    return info, idx


def _parse_data_privacy(
    lines: list[str], start: int, section_headers: list[re.Pattern[str]]
) -> tuple[dict[str, str], int]:
    """Parse the Data Privacy section."""
    info: dict[str, str] = {}
    idx = start
    key_map = {
        "sending hostname": "sending_hostname",
        "callhome hostname privacy": "callhome_hostname_privacy",
        "smart licensing hostname privacy": "smart_licensing_hostname_privacy",
        "version privacy": "version_privacy",
    }
    while idx < len(lines):
        line = lines[idx]
        if _is_section_header(line, section_headers):
            break
        if match := _KV_RE.match(line):
            key_lower = match.group("key").strip().lower()
            value = match.group("value").strip()
            if key_lower in key_map and not _is_placeholder(value):
                info[key_map[key_lower]] = value
        idx += 1
    return info, idx


_PROXY_KEYS = frozenset({"address", "port", "username", "password"})

_TRANSPORT_TOP_MAP: dict[str, str] = {
    "type": "type",
    "cslu address": "cslu_address",
    "server identity check": "server_identity_check",
    "vrf": "vrf",
    "ip mode": "ip_mode",
    "trust point": "trust_point",
}


def _parse_transport(
    lines: list[str], start: int, section_headers: list[re.Pattern[str]]
) -> tuple[dict[str, str], int]:
    """Parse the Transport section."""
    info: dict[str, str] = {}
    idx = start
    in_proxy = False
    while idx < len(lines):
        line = lines[idx]
        if _is_section_header(line, section_headers):
            break
        stripped = line.strip()
        if stripped.lower() == "proxy:":
            in_proxy = True
            idx += 1
            continue
        if match := _KV_RE.match(line):
            key_lower = match.group("key").strip().lower()
            value = match.group("value").strip()
            if not _is_placeholder(value):
                _store_transport_kv(info, key_lower, value, in_proxy)
        elif stripped:
            in_proxy = False
        idx += 1
    return info, idx


def _store_transport_kv(
    info: dict[str, str], key: str, value: str, in_proxy: bool
) -> None:
    """Store a single transport key-value pair."""
    if in_proxy and key in _PROXY_KEYS:
        info[f"proxy_{key}"] = value
    elif key in _TRANSPORT_TOP_MAP:
        info[_TRANSPORT_TOP_MAP[key]] = value


def _parse_miscellaneous(
    lines: list[str], start: int, section_headers: list[re.Pattern[str]]
) -> tuple[dict[str, str], int]:
    """Parse the Miscellaneous section."""
    info: dict[str, str] = {}
    idx = start
    key_map = {"custom id": "custom_id"}
    while idx < len(lines):
        line = lines[idx]
        if _is_section_header(line, section_headers):
            break
        if match := _KV_RE.match(line):
            key_lower = match.group("key").strip().lower()
            value = match.group("value").strip()
            if key_lower in key_map and not _is_placeholder(value):
                info[key_map[key_lower]] = value
        idx += 1
    return info, idx


def _parse_utility(
    lines: list[str], start: int, section_headers: list[re.Pattern[str]]
) -> tuple[str | None, int]:
    """Parse the Utility section, extracting only the Status value."""
    idx = start
    while idx < len(lines):
        line = lines[idx]
        if _is_section_header(line, section_headers):
            break
        if match := _KV_RE.match(line):
            key_lower = match.group("key").strip().lower()
            value = match.group("value").strip()
            if key_lower == "status" and not _is_placeholder(value):
                return value, idx + 1
        idx += 1
    return None, idx


def _parse_export_auth_key(
    lines: list[str], start: int, section_headers: list[re.Pattern[str]]
) -> tuple[str | None, int]:
    r"""Parse the Export Authorization Key section.

    Extracts the 'Features Authorized' value if present and non-placeholder.
    """
    idx = start
    while idx < len(lines):
        line = lines[idx]
        if _is_section_header(line, section_headers):
            break
        if match := _KV_RE.match(line):
            key_lower = match.group("key").strip().lower()
            value = match.group("value").strip()
            if key_lower == "features authorized" and not _is_placeholder(value):
                return value, idx + 1
        idx += 1
    return None, idx


# --- Helpers ---

_ALL_SECTION_HEADERS: list[re.Pattern[str]] = [
    _SECTION_SMART_LICENSING_STATUS_RE,
    _SECTION_LICENSE_CONVERSION_RE,
    _SECTION_EXPORT_AUTH_KEY_RE,
    _SECTION_UTILITY_RE,
    _SECTION_SMART_LICENSING_POLICY_RE,
    _SECTION_ACCOUNT_INFO_RE,
    _SECTION_DATA_PRIVACY_RE,
    _SECTION_TRANSPORT_RE,
    _SECTION_MISCELLANEOUS_RE,
    _SECTION_POLICY_RE,
]


def _is_section_header(line: str, headers: list[re.Pattern[str]]) -> bool:
    """Check if a line matches any known section header."""
    return any(h.match(line) for h in headers)


def _detect_section(
    line: str,
) -> tuple[re.Pattern[str], str] | None:
    """Detect which section header a line matches.

    Returns a tuple of (pattern, result_key) or None.
    """
    section_map: list[tuple[re.Pattern[str], str]] = [
        (_SECTION_LICENSE_CONVERSION_RE, "license_conversion"),
        (_SECTION_EXPORT_AUTH_KEY_RE, "export_authorization_key"),
        (_SECTION_UTILITY_RE, "utility_status"),
        (_SECTION_SMART_LICENSING_POLICY_RE, "smart_licensing_using_policy"),
        (_SECTION_ACCOUNT_INFO_RE, "account_information"),
        (_SECTION_DATA_PRIVACY_RE, "data_privacy"),
        (_SECTION_TRANSPORT_RE, "transport"),
        (_SECTION_MISCELLANEOUS_RE, "miscellaneous"),
        (_SECTION_POLICY_RE, "_skip"),
    ]
    for pattern, key in section_map:
        if pattern.match(line):
            return pattern, key
    return None


# Type alias for section parser functions
_SectionParser = Callable[[list[str], int, list[re.Pattern[str]]], tuple[Any, int]]

# Map result keys to their section parser functions
_SECTION_PARSERS: dict[str, _SectionParser] = {
    "license_conversion": _parse_license_conversion,
    "export_authorization_key": _parse_export_auth_key,
    "utility_status": _parse_utility,
    "smart_licensing_using_policy": _parse_smart_licensing_policy,
    "account_information": _parse_account_information,
    "data_privacy": _parse_data_privacy,
    "transport": _parse_transport,
    "miscellaneous": _parse_miscellaneous,
}


def _dispatch_section(key: str, lines: list[str], idx: int, result: dict) -> int:
    """Dispatch parsing to the appropriate section handler.

    Returns the updated line index after parsing the section.
    """
    if key == "_skip":
        return idx

    parser_fn = _SECTION_PARSERS.get(key)
    if parser_fn is None:
        return idx

    parsed, idx = parser_fn(lines, idx, _ALL_SECTION_HEADERS)
    if parsed:
        result[key] = parsed
    return idx


@register(OS.CISCO_IOSXE, "show license tech support")
class ShowLicenseTechSupportParser(BaseParser["ShowLicenseTechSupportResult"]):
    """Parser for 'show license tech support' on IOS-XE.

    Parses the Smart Licensing Tech Support output which includes licensing
    status, conversion settings, transport configuration, account details,
    data privacy settings, and policy information.

    This parser extracts the key-value sections from the verbose output,
    omitting placeholder values (``<none>``, ``<empty>``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowLicenseTechSupportResult:
        """Parse 'show license tech support' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed licensing tech support data.

        Raises:
            ValueError: If no recognizable sections are found.
        """
        lines = output.splitlines()
        result: dict = {}
        idx = 0

        while idx < len(lines):
            line = lines[idx]

            # Skip separator lines
            if _SEPARATOR_EQUALS_RE.match(line):
                idx += 1
                continue

            # Smart Licensing is ENABLED/DISABLED
            if match := _SMART_LICENSING_IS_RE.match(line):
                result["smart_licensing_status"] = match.group("status")
                idx += 1
                continue

            # Check for section headers
            detected = _detect_section(line)
            if detected is not None:
                _, key = detected
                idx += 1
                idx = _dispatch_section(key, lines, idx, result)
                continue

            idx += 1

        if not result:
            msg = "No license tech support information found in output"
            raise ValueError(msg)

        return cast(ShowLicenseTechSupportResult, result)
