"""Parser for 'show ip http server status' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Prefixes that begin a fresh logical line in 'show ip http server status'
# output. Any non-blank line that does not start with one of these is treated
# as a continuation of the previous logical line. The CLI wraps long
# multi-token values (e.g. the cipher list or TLS version list) across
# multiple physical lines indented with whitespace.
_LINE_PREFIXES: tuple[str, ...] = (
    "HTTP server ",
    "HTTP secure server ",
    "HTTP File Upload ",
    "Maximum number of ",
    "Server ",
)

_KV_RE = re.compile(r"^(?P<label>[^:]+):\s*(?P<value>.*?)\s*$")

# Special non ``Label: value`` line:
#   "HTTP server auth-retry 0 time-window 0"
_AUTH_RETRY_RE = re.compile(
    r"^HTTP\s+server\s+auth-retry\s+(?P<retries>\d+)"
    r"\s+time-window\s+(?P<window>\d+)\s*$",
    re.IGNORECASE,
)

# Map of normalized label (lowercased, trimmed) -> output key + value kind.
# ``kind`` is one of:
#   "str"       – store the raw string verbatim
#   "bool"      – Enabled/Disabled/Present/Absent/yes/no -> bool
#   "int"       – integer
#   "int_secs"  – integer extracted from a value like "180 seconds"
#   "str_list"  – whitespace-separated tokens -> list[str]
#   "int_list"  – whitespace-separated tokens -> list[int]
_HTTP_FIELDS: dict[str, tuple[str, str]] = {
    "http server status": ("enabled", "bool"),
    "http server port": ("port", "int"),
    "http server active supplementary listener ports": (
        "active_supplementary_listener_ports",
        "int_list",
    ),
    "http server authentication method": ("authentication_method", "str"),
    "http server digest algorithm": ("digest_algorithm", "str"),
    "http server access class": ("access_class", "str"),
    "http server ipv4 access class": ("ipv4_access_class", "str"),
    "http server ipv6 access class": ("ipv6_access_class", "str"),
    "http server base path": ("base_path", "str"),
    "http file upload status": ("file_upload_enabled", "bool"),
    "http server upload path": ("upload_path", "str"),
    "http server help root": ("help_root", "str"),
    "maximum number of concurrent server connections allowed": (
        "max_concurrent_connections",
        "int",
    ),
    "maximum number of secondary server connections allowed": (
        "max_secondary_connections",
        "int",
    ),
    "server idle time-out": ("server_idle_timeout_seconds", "int_secs"),
    "server life time-out": ("server_life_timeout_seconds", "int_secs"),
    "server session idle time-out": (
        "server_session_idle_timeout_seconds",
        "int_secs",
    ),
    "maximum number of requests allowed on a connection": (
        "max_requests_per_connection",
        "int",
    ),
    "server linger time": ("server_linger_time_seconds", "int_secs"),
    "http server active session modules": ("active_session_modules", "str"),
}

_HTTPS_FIELDS: dict[str, tuple[str, str]] = {
    "http secure server capability": ("capability_present", "bool"),
    "http secure server status": ("enabled", "bool"),
    "http secure server port": ("port", "int"),
    "http secure server ciphersuite": ("ciphersuite", "str_list"),
    "http secure server tls version": ("tls_versions", "str_list"),
    "http secure server client authentication": (
        "client_authentication_enabled",
        "bool",
    ),
    "http secure server piv authentication": (
        "piv_authentication_enabled",
        "bool",
    ),
    "http secure server piv authorization only": (
        "piv_authorization_only_enabled",
        "bool",
    ),
    "http secure server trustpoint": ("trustpoint", "str"),
    "http secure server peer validation trustpoint": (
        "peer_validation_trustpoint",
        "str",
    ),
    "http secure server ecdhe curve": ("ecdhe_curve", "str"),
    "http secure server active session modules": ("active_session_modules", "str"),
}


class HttpServerStatus(TypedDict):
    """Schema for the plaintext HTTP server section."""

    enabled: bool
    port: NotRequired[int]
    active_supplementary_listener_ports: NotRequired[list[int]]
    authentication_method: NotRequired[str]
    auth_retry_count: NotRequired[int]
    auth_retry_time_window_minutes: NotRequired[int]
    digest_algorithm: NotRequired[str]
    access_class: NotRequired[str]
    ipv4_access_class: NotRequired[str]
    ipv6_access_class: NotRequired[str]
    base_path: NotRequired[str]
    file_upload_enabled: NotRequired[bool]
    upload_path: NotRequired[str]
    help_root: NotRequired[str]
    max_concurrent_connections: NotRequired[int]
    max_secondary_connections: NotRequired[int]
    server_idle_timeout_seconds: NotRequired[int]
    server_life_timeout_seconds: NotRequired[int]
    server_session_idle_timeout_seconds: NotRequired[int]
    max_requests_per_connection: NotRequired[int]
    server_linger_time_seconds: NotRequired[int]
    active_session_modules: NotRequired[str]


class HttpSecureServerStatus(TypedDict):
    """Schema for the HTTPS (HTTP secure) server section."""

    enabled: bool
    capability_present: NotRequired[bool]
    port: NotRequired[int]
    ciphersuite: NotRequired[list[str]]
    tls_versions: NotRequired[list[str]]
    client_authentication_enabled: NotRequired[bool]
    piv_authentication_enabled: NotRequired[bool]
    piv_authorization_only_enabled: NotRequired[bool]
    trustpoint: NotRequired[str]
    peer_validation_trustpoint: NotRequired[str]
    ecdhe_curve: NotRequired[str]
    active_session_modules: NotRequired[str]


class ShowIpHttpServerStatusResult(TypedDict):
    """Schema for 'show ip http server status' parsed output."""

    http_server: HttpServerStatus
    http_secure_server: HttpSecureServerStatus


_PLACEHOLDERS = {"none", "n/a", "-", ""}


def _is_line_start(line: str) -> bool:
    """Return True if the line begins a new logical record."""
    return any(line.startswith(prefix) for prefix in _LINE_PREFIXES)


def _unwrap_lines(output: str) -> list[str]:
    """Join terminal-wrapped continuation lines onto their logical line."""
    logical: list[str] = []
    for raw in output.splitlines():
        if not raw.strip():
            continue
        if not logical or _is_line_start(raw):
            logical.append(raw.rstrip())
            continue
        # Continuation line: join with a single space, dropping leading
        # whitespace from the continuation but preserving a separator so the
        # tokens of multi-value lists remain distinct.
        logical[-1] = logical[-1] + " " + raw.strip()
    return logical


def _to_bool(value: str) -> bool | None:
    """Translate an Enabled/Disabled/Present/Absent token to a bool."""
    lowered = value.strip().lower()
    if lowered in {"enabled", "present", "yes", "true", "active"}:
        return True
    if lowered in {"disabled", "absent", "no", "false", "inactive"}:
        return False
    return None


def _is_placeholder(value: str) -> bool:
    """Return True if the value should be omitted (None/empty/placeholder)."""
    return value.strip().lower() in _PLACEHOLDERS


def _coerce_int(value: str) -> int | None:
    """Coerce ``value`` to an int, returning None on failure."""
    try:
        return int(value)
    except ValueError:
        return None


def _coerce_int_secs(value: str) -> int | None:
    """Extract a leading integer (number of seconds) from ``value``."""
    match = re.match(r"^(\d+)", value)
    return int(match.group(1)) if match else None


def _coerce_int_list(value: str) -> list[int] | None:
    """Coerce ``value`` to a list[int]; return None on any non-integer token."""
    try:
        return [int(tok) for tok in value.split()]
    except ValueError:
        return None


def _coerce_str_list(value: str) -> list[str] | None:
    """Coerce ``value`` to a list[str]; return None on empty input."""
    tokens = value.split()
    return tokens or None


_KIND_DISPATCH: dict[str, Callable[[str], object | None]] = {
    "bool": _to_bool,
    "int": _coerce_int,
    "int_secs": _coerce_int_secs,
    "str_list": _coerce_str_list,
    "int_list": _coerce_int_list,
}


def _coerce_value(value: str, kind: str) -> object | None:
    """Coerce a raw value string into the type indicated by ``kind``.

    Returns ``None`` if the value should be omitted (placeholder or empty).
    """
    stripped = value.strip()
    if _is_placeholder(stripped):
        return None
    handler = _KIND_DISPATCH.get(kind)
    if handler is None:
        return stripped
    return handler(stripped)


def _store_field(target: dict, key: str, kind: str, raw_value: str) -> None:
    """Coerce and store a field if the value is meaningful."""
    coerced = _coerce_value(raw_value, kind)
    if coerced is None:
        return
    if isinstance(coerced, list) and not coerced:
        return
    target[key] = coerced


def _try_auth_retry(line: str, http_server: dict) -> bool:
    """Handle the special 'auth-retry N time-window M' line."""
    match = _AUTH_RETRY_RE.match(line)
    if not match:
        return False
    http_server["auth_retry_count"] = int(match.group("retries"))
    http_server["auth_retry_time_window_minutes"] = int(match.group("window"))
    return True


def _try_field(
    label: str,
    value: str,
    field_map: dict[str, tuple[str, str]],
    target: dict,
) -> bool:
    """Match ``label`` against ``field_map`` and store the value if matched."""
    entry = field_map.get(label)
    if entry is None:
        return False
    key, kind = entry
    _store_field(target, key, kind, value)
    return True


@register(OS.CISCO_IOSXE, "show ip http server status")
class ShowIpHttpServerStatusParser(BaseParser[ShowIpHttpServerStatusResult]):
    """Parser for 'show ip http server status' on Cisco IOS-XE.

    Parses the HTTP and HTTPS server configuration and runtime status into
    two grouped sub-dictionaries: ``http_server`` (plain HTTP) and
    ``http_secure_server`` (HTTPS). Boolean fields capture Enabled/Disabled
    and Present/Absent states; numeric timeouts are stored as integers with
    their unit reflected in the key name (e.g. ``server_idle_timeout_seconds``).
    Placeholder values such as ``None``/empty paths are omitted rather than
    stored.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.SYSTEM},
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpHttpServerStatusResult:
        """Parse 'show ip http server status' output into structured data.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed HTTP/HTTPS server status grouped by service.

        Raises:
            ValueError: If neither the HTTP nor the HTTPS server status header
                is present in the output (indicating the input is not from
                this command).
        """
        http_server: dict = {}
        http_secure_server: dict = {}

        for line in _unwrap_lines(output):
            if _try_auth_retry(line, http_server):
                continue

            match = _KV_RE.match(line)
            if not match:
                continue

            label = match.group("label").strip().lower()
            value = match.group("value")

            if _try_field(label, value, _HTTPS_FIELDS, http_secure_server):
                continue
            _try_field(label, value, _HTTP_FIELDS, http_server)

        if "enabled" not in http_server and "enabled" not in http_secure_server:
            msg = (
                "Missing required 'HTTP server status' or "
                "'HTTP secure server status' line in output"
            )
            raise ValueError(msg)

        # Both sub-sections must report an `enabled` field so that the
        # Required marker on the TypedDict holds. If the device omitted one
        # (rare on modern IOS-XE), default to False so consumers always have
        # a known boolean.
        http_server.setdefault("enabled", False)
        http_secure_server.setdefault("enabled", False)

        result: dict = {
            "http_server": http_server,
            "http_secure_server": http_secure_server,
        }
        return cast(ShowIpHttpServerStatusResult, result)
