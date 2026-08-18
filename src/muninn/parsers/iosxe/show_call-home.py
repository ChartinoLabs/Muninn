"""Parser for 'show call-home' command on Cisco IOS and IOS-XE."""

import re
from typing import ClassVar, Literal, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_Section = Literal["settings", "alert_groups", "profiles"]


class HttpSecureSettings(TypedDict, total=False):
    """Schema for the nested ``http secure`` block."""

    server_identity_check: str


class CallHomeSettings(TypedDict, total=False):
    """Schema for the flat settings block at the top of ``show call-home``."""

    call_home_feature: str
    call_home_messages_from_address: str
    call_home_messages_reply_to_address: str
    vrf_for_call_home_messages: str
    contact_persons_email_address: str
    contact_persons_phone_number: str
    street_address: str
    customer_id: str
    contract_id: str
    site_id: str
    source_ip_address: str
    source_interface: str
    mail_server: str
    http_proxy: str
    http_secure: HttpSecureSettings
    http_resolve_hostname: str
    diagnostic_signature: str
    smart_licensing_messages: str
    aaa_authorization: str
    aaa_authorization_username: str
    data_privacy: str
    syslog_throttling: str
    rate_limit: str
    snapshot_command: str


class AlertGroup(TypedDict):
    """Schema for a single row in the alert-groups table."""

    state: Literal["enable", "disable"]
    description: str


class Profile(TypedDict):
    """Schema for a single entry in the profiles map."""

    status: NotRequired[str]


class ShowCallHomeResult(TypedDict):
    """Schema for 'show call-home' parsed output."""

    settings: CallHomeSettings
    alert_groups: dict[str, AlertGroup]
    profiles: dict[str, Profile]


_SimpleSettingsKey = Literal[
    "call_home_feature",
    "call_home_messages_from_address",
    "call_home_messages_reply_to_address",
    "vrf_for_call_home_messages",
    "contact_persons_email_address",
    "contact_persons_phone_number",
    "street_address",
    "customer_id",
    "contract_id",
    "site_id",
    "source_ip_address",
    "source_interface",
    "mail_server",
    "http_proxy",
    "http_resolve_hostname",
    "diagnostic_signature",
    "smart_licensing_messages",
    "aaa_authorization",
    "aaa_authorization_username",
    "data_privacy",
    "syslog_throttling",
    "rate_limit",
    "snapshot_command",
]

_SIMPLE_SETTINGS_KEYS: frozenset[str] = frozenset(
    {
        "call_home_feature",
        "call_home_messages_from_address",
        "call_home_messages_reply_to_address",
        "vrf_for_call_home_messages",
        "contact_persons_email_address",
        "contact_persons_phone_number",
        "street_address",
        "customer_id",
        "contract_id",
        "site_id",
        "source_ip_address",
        "source_interface",
        "mail_server",
        "http_proxy",
        "http_resolve_hostname",
        "diagnostic_signature",
        "smart_licensing_messages",
        "aaa_authorization",
        "aaa_authorization_username",
        "data_privacy",
        "syslog_throttling",
        "rate_limit",
        "snapshot_command",
    }
)

_SECTION_HEADERS = {
    "Current call home settings:": "settings",
    "Available alert groups:": "alert_groups",
    "Profiles:": "profiles",
}

_ALERT_GROUP_PATTERN = re.compile(
    r"^\s*(?P<keyword>\S+)\s+(?P<state>Enable|Disable)\s+(?P<description>.+)$"
)
_PROFILE_STATUS_PATTERN = re.compile(
    r"^(?P<name>.+?)\s*\(status:\s*(?P<status>[^)]+)\)\s*$"
)


def _normalize_key(value: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace to underscores."""
    normalized = value.strip().lower()
    normalized = normalized.replace("'", "")
    normalized = normalized.replace("-", " ")
    return "_".join(normalized.split())


def _capture_profile_status(
    stripped: str,
    profile_statuses: dict[str, str],
) -> bool:
    """Record ``Profile: <name> (status: <state>)`` lines from settings block."""
    if not stripped.startswith("Profile:"):
        return False
    name_raw = stripped.split(":", 1)[1]
    match = _PROFILE_STATUS_PATTERN.match(name_raw.strip())
    if match is None:
        return True
    profile_statuses[match.group("name").strip()] = match.group("status").strip()
    return True


def _parse_settings_line(
    *,
    line: str,
    stripped: str,
    settings: CallHomeSettings,
    nested_setting: Literal["http_secure"] | None,
) -> Literal["http_secure"] | None:
    """Parse one line from the current settings block.

    Returns the nested-section state to carry into the next line. The
    ``http secure`` header introduces an indented sub-block whose
    ``server identity check`` entry nests under ``http_secure``.
    """
    if ":" not in stripped:
        return nested_setting
    key_text, value_text = (part.strip() for part in stripped.split(":", 1))
    normalized = _normalize_key(key_text)
    indent = len(line) - len(line.lstrip())

    if indent > 4 and nested_setting == "http_secure":
        _apply_nested_http_secure(settings, normalized, value_text)
        return nested_setting
    return _apply_top_level_setting(settings, normalized, value_text)


def _apply_nested_http_secure(
    settings: CallHomeSettings,
    normalized: str,
    value: str,
) -> None:
    """Apply an indented key under the ``http secure`` sub-block."""
    if normalized != "server_identity_check":
        return
    http_secure = settings.get("http_secure") or HttpSecureSettings()
    http_secure["server_identity_check"] = value
    settings["http_secure"] = http_secure


def _apply_top_level_setting(
    settings: CallHomeSettings,
    normalized: str,
    value: str,
) -> Literal["http_secure"] | None:
    """Apply a top-level key from the settings block; return nested state."""
    if normalized == "http_secure":
        if value:
            return None
        settings["http_secure"] = HttpSecureSettings()
        return "http_secure"
    if normalized in _SIMPLE_SETTINGS_KEYS and value:
        settings[cast(_SimpleSettingsKey, normalized)] = value
    return None


def _maybe_record_profile(
    stripped: str,
    profiles: dict[str, Profile],
    profile_statuses: dict[str, str],
) -> None:
    """Record a profile entry from a ``Profile Name:`` line."""
    if not stripped.startswith("Profile Name:"):
        return
    name = stripped.split(":", 1)[1].strip()
    attrs: Profile = {}
    status = profile_statuses.get(name)
    if status is not None:
        attrs["status"] = status
    profiles[name] = attrs


@register(OS.CISCO_IOS, "show call-home")
@register(OS.CISCO_IOSXE, "show call-home")
class ShowCallHomeParser(BaseParser[ShowCallHomeResult]):
    """Parser for ``show call-home`` output.

    Parses three sections: current settings (flat key-value pairs with an
    optional nested ``http secure`` block), the alert-groups table, and
    the list of configured profiles.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowCallHomeResult:
        """Parse raw ``show call-home`` output into structured data."""
        result: ShowCallHomeResult = {
            "settings": {},
            "alert_groups": {},
            "profiles": {},
        }
        # Profile status lives in the settings block as lines like
        # ``Profile: CiscoTAC-1 (status: INACTIVE)``. The Profiles section
        # then lists configured profiles by name. Statuses are tracked
        # separately and merged as each profile is enumerated.
        profile_statuses: dict[str, str] = {}
        section: _Section | None = None
        nested_setting: Literal["http_secure"] | None = None

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()

            if not stripped or stripped.startswith("<"):
                continue

            new_section = _SECTION_HEADERS.get(stripped)
            if new_section is not None:
                section = cast(_Section, new_section)
                nested_setting = None
                continue

            nested_setting = cls._dispatch_line(
                section=section,
                line=line,
                stripped=stripped,
                result=result,
                profile_statuses=profile_statuses,
                nested_setting=nested_setting,
            )

        return result

    @classmethod
    def _dispatch_line(
        cls,
        *,
        section: _Section | None,
        line: str,
        stripped: str,
        result: ShowCallHomeResult,
        profile_statuses: dict[str, str],
        nested_setting: Literal["http_secure"] | None,
    ) -> Literal["http_secure"] | None:
        """Route a non-header line to the handler for the current section."""
        if section == "settings":
            if _capture_profile_status(stripped, profile_statuses):
                return nested_setting
            return _parse_settings_line(
                line=line,
                stripped=stripped,
                settings=result["settings"],
                nested_setting=nested_setting,
            )
        if section == "alert_groups":
            cls._parse_alert_group_line(line=line, alert_groups=result["alert_groups"])
            return None
        if section == "profiles":
            _maybe_record_profile(stripped, result["profiles"], profile_statuses)
        return None

    @classmethod
    def _parse_alert_group_line(
        cls,
        *,
        line: str,
        alert_groups: dict[str, AlertGroup],
    ) -> None:
        stripped = line.strip()
        if stripped.startswith("Keyword") or set(stripped) == {"-"}:
            return

        match = _ALERT_GROUP_PATTERN.match(line)
        if match is None:
            return

        keyword = _normalize_key(match.group("keyword"))
        state = cast(Literal["enable", "disable"], match.group("state").lower())
        alert_groups[keyword] = {
            "state": state,
            "description": match.group("description").strip(),
        }
