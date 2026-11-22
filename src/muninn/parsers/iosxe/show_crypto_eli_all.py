"""Parser for 'show crypto eli all' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Hardware Encryption : INACTIVE
_HW_ENCRYPTION_RE = re.compile(
    r"^\s*Hardware\s+Encryption\s*:\s*(?P<state>\S+)\s*$", re.IGNORECASE
)

# Number of crypto engines = 2
_NUM_ENGINES_RE = re.compile(
    r"^\s*Number\s+of\s+crypto\s+engines\s*=\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)

# CryptoEngine Software Crypto Engine details: state = Active
_ENGINE_HEADER_RE = re.compile(
    r"^\s*CryptoEngine\s+(?P<name>.+?)\s+details\s*:\s*"
    r"state\s*=\s*(?P<state>\S+)\s*$",
    re.IGNORECASE,
)

# Capability    : IPPCP, DES, 3DES, ...
_CAPABILITY_RE = re.compile(r"^\s*Capability\s*:\s*(?P<caps>.+)$", re.IGNORECASE)

# IKE-Session   :     0 active,   100 max, 0 failed, 0 created
_SESSION_RE = re.compile(
    r"^\s*(?P<type>IKE-Session|IKEv2-Session|IPSec-Session)"
    r"\s*:\s*(?P<active>\d+)\s+active\s*,\s*(?P<max>\d+)\s+max\s*,"
    r"\s*(?P<failed>\d+)\s+failed\s*,\s*(?P<created>\d+)\s+created\s*$",
    re.IGNORECASE,
)

# DH            :     3 active(3/0),    50 max, 0 failed, 3 created
_DH_SESSION_RE = re.compile(
    r"^\s*DH\s*:\s*(?P<active>\d+)\s+active"
    r"\((?P<phase1>\d+)/(?P<phase2>\d+)\)\s*,"
    r"\s*(?P<max>\d+)\s+max\s*,"
    r"\s*(?P<failed>\d+)\s+failed\s*,"
    r"\s*(?P<created>\d+)\s+created\s*$",
    re.IGNORECASE,
)

# SSL support   : Yes
_SSL_SUPPORT_RE = re.compile(
    r"^\s*SSL\s+support\s*:\s*(?P<value>\S+)\s*$", re.IGNORECASE
)

# SSL versions  : SSLv3.0, TLSv1.0, DTLSv1.0, ...
_SSL_VERSIONS_RE = re.compile(
    r"^\s*SSL\s+versions\s*:\s*(?P<versions>.+)$", re.IGNORECASE
)

# Max SSL connec: 1000
_MAX_SSL_RE = re.compile(
    r"^\s*Max\s+SSL\s+connec\s*:\s*(?P<value>\d+)\s*$", re.IGNORECASE
)

# SSL namespace : 1
_SSL_NAMESPACE_RE = re.compile(
    r"^\s*SSL\s+namespace\s*:\s*(?P<value>\d+)\s*$", re.IGNORECASE
)

# Number of DH's pregenerated = 4
_DH_PREGEN_RE = re.compile(
    r"^\s*Number\s+of\s+DH's\s+pregenerated\s*=\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)

# DH lifetime = 86400 seconds
_DH_LIFETIME_RE = re.compile(
    r"^\s*DH\s+lifetime\s*=\s*(?P<seconds>\d+)\s+seconds\s*$",
    re.IGNORECASE,
)

# DH calculations: P1 3, SS 0
_DH_CALCS_RE = re.compile(
    r"^\s*DH\s+calculations\s*:\s*P1\s+(?P<p1>\d+)\s*,"
    r"\s*SS\s+(?P<ss>\d+)\s*$",
    re.IGNORECASE,
)

# crypto engine 1:Software Crypto Engine
_CRYPTO_ENGINE_SUMMARY_RE = re.compile(
    r"^\s*crypto\s+engine\s+\d+\s*:\s*(?P<name>.+?)\s*$",
    re.IGNORECASE,
)

# DH in use/freeing/free - 3/0/47
_DH_USAGE_RE = re.compile(
    r"^\s*DH\s+in\s+use/freeing/free\s*-\s*"
    r"(?P<in_use>\d+)/(?P<freeing>\d+)/(?P<free>\d+)\s*$",
    re.IGNORECASE,
)

# SSLv3.0 suites:  /  TLSv1.0 suites:  /  DTLSv1.0 suite:
_SUITE_HEADER_RE = re.compile(r"^\s*(?P<version>\S+)\s+suites?\s*:\s*$", re.IGNORECASE)

# Cipher suite line (indented):  TLS_RSA_WITH_3DES_EDE_CBC_SHA
_SUITE_LINE_RE = re.compile(r"^\s{10,}(?P<suite>TLS_\S+)\s*$")

# Known structural line patterns for disambiguation
_KNOWN_PATTERNS: tuple[re.Pattern[str], ...] = (
    _SESSION_RE,
    _DH_SESSION_RE,
    _SSL_SUPPORT_RE,
    _SSL_VERSIONS_RE,
    _MAX_SSL_RE,
    _SSL_NAMESPACE_RE,
    _SUITE_HEADER_RE,
    _DH_PREGEN_RE,
    _DH_LIFETIME_RE,
    _DH_CALCS_RE,
    _CRYPTO_ENGINE_SUMMARY_RE,
    _DH_USAGE_RE,
    _ENGINE_HEADER_RE,
    _HW_ENCRYPTION_RE,
    _NUM_ENGINES_RE,
)


class SessionCounters(TypedDict):
    """Session counter block for IKE/IKEv2/IPSec sessions."""

    active: int
    max: int
    failed: int
    created: int


class DHSessionCounters(TypedDict):
    """DH-specific session counters with phase breakdown."""

    active: int
    active_phase1: int
    active_phase2: int
    max: int
    failed: int
    created: int


class DHUsage(TypedDict):
    """DH buffer usage statistics for a crypto engine."""

    in_use: int
    freeing: int
    free: int


class DHCalculations(TypedDict):
    """DH calculation counters."""

    p1: int
    ss: int


class CryptoEngineEntry(TypedDict):
    """Details of a single crypto engine."""

    state: str
    capabilities: NotRequired[list[str]]
    ike_sessions: NotRequired[SessionCounters]
    ikev2_sessions: NotRequired[SessionCounters]
    ipsec_sessions: NotRequired[SessionCounters]
    dh_sessions: NotRequired[DHSessionCounters]
    ssl_support: NotRequired[bool]
    ssl_versions: NotRequired[list[str]]
    max_ssl_connections: NotRequired[int]
    ssl_namespace: NotRequired[int]
    cipher_suites: NotRequired[dict[str, list[str]]]
    dh_usage: NotRequired[DHUsage]


class DHPregeneration(TypedDict):
    """DH pregeneration summary."""

    count: int
    lifetime_seconds: int
    calculations: NotRequired[DHCalculations]


class ShowCryptoEliAllResult(TypedDict):
    """Schema for 'show crypto eli all' parsed output."""

    hardware_encryption: str
    number_of_crypto_engines: int
    engines: dict[str, CryptoEngineEntry]
    dh_pregeneration: NotRequired[DHPregeneration]


def _split_csv(text: str) -> list[str]:
    """Split comma-separated text, stripping whitespace and empties."""
    return [t.strip() for t in text.rstrip(",").split(",") if t.strip()]


def _is_known_pattern(line: str) -> bool:
    """Return True if line matches any known structural pattern."""
    return any(p.match(line) for p in _KNOWN_PATTERNS)


def _try_global_section(
    line: str,
    dh_pregen: dict[str, object],
) -> bool:
    """Try to parse DH pregeneration global lines.

    Returns True if the line was consumed.
    """
    m = _DH_PREGEN_RE.match(line)
    if m:
        dh_pregen["count"] = int(m.group("count"))
        return True

    m = _DH_LIFETIME_RE.match(line)
    if m:
        dh_pregen["lifetime_seconds"] = int(m.group("seconds"))
        return True

    m = _DH_CALCS_RE.match(line)
    if m:
        dh_pregen["calculations"] = cast(
            DHCalculations,
            {"p1": int(m.group("p1")), "ss": int(m.group("ss"))},
        )
        return True

    return False


def _try_session_counters(
    line: str,
    engine: dict[str, object],
) -> bool:
    """Try to parse session counter lines (IKE, IKEv2, DH, IPSec).

    Returns True if the line was consumed.
    """
    m = _SESSION_RE.match(line)
    if m:
        counters = cast(
            SessionCounters,
            {
                "active": int(m.group("active")),
                "max": int(m.group("max")),
                "failed": int(m.group("failed")),
                "created": int(m.group("created")),
            },
        )
        session_type = m.group("type").lower()
        if "ikev2" in session_type:
            engine["ikev2_sessions"] = counters
        elif "ike" in session_type:
            engine["ike_sessions"] = counters
        elif "ipsec" in session_type:
            engine["ipsec_sessions"] = counters
        return True

    m = _DH_SESSION_RE.match(line)
    if m:
        engine["dh_sessions"] = cast(
            DHSessionCounters,
            {
                "active": int(m.group("active")),
                "active_phase1": int(m.group("phase1")),
                "active_phase2": int(m.group("phase2")),
                "max": int(m.group("max")),
                "failed": int(m.group("failed")),
                "created": int(m.group("created")),
            },
        )
        return True

    return False


def _try_ssl_fields(
    line: str,
    engine: dict[str, object],
) -> bool:
    """Try to parse SSL scalar fields (support, max, namespace).

    Returns True if the line was consumed.
    """
    m = _SSL_SUPPORT_RE.match(line)
    if m:
        engine["ssl_support"] = m.group("value").lower() == "yes"
        return True

    m = _MAX_SSL_RE.match(line)
    if m:
        engine["max_ssl_connections"] = int(m.group("value"))
        return True

    m = _SSL_NAMESPACE_RE.match(line)
    if m:
        engine["ssl_namespace"] = int(m.group("value"))
        return True

    return False


def _try_cipher_suites(
    line: str,
    engine: dict[str, object],
    current_suite_version: str,
) -> tuple[bool, str]:
    """Try to parse cipher suite header or entry lines.

    Returns (consumed, updated_suite_version).
    """
    m = _SUITE_HEADER_RE.match(line)
    if m:
        version = m.group("version")
        if "cipher_suites" not in engine:
            engine["cipher_suites"] = {}
        suites = cast(dict[str, list[str]], engine["cipher_suites"])
        suites[version] = []
        return True, version

    m = _SUITE_LINE_RE.match(line)
    if m and current_suite_version:
        suites = cast(dict[str, list[str]], engine["cipher_suites"])
        suites[current_suite_version].append(m.group("suite"))
        return True, current_suite_version

    return False, current_suite_version


class _ParseState:
    """Mutable state container for the engine parsing loop."""

    def __init__(self) -> None:
        self.engines: dict[str, dict[str, object]] = {}
        self.dh_pregen: dict[str, object] = {}
        self.current_engine: dict[str, object] | None = None
        self.suite_version: str = ""
        self.continuation: str = ""

    def reset_continuation(self) -> None:
        """Clear continuation and suite state."""
        self.continuation = ""
        self.suite_version = ""


def _handle_engine_header(state: _ParseState, line: str) -> bool:
    """Handle CryptoEngine header line. Returns True if consumed."""
    m = _ENGINE_HEADER_RE.match(line)
    if not m:
        return False
    state.current_engine = {"state": m.group("state")}
    state.engines[m.group("name")] = state.current_engine
    state.reset_continuation()
    return True


def _handle_engine_summary(state: _ParseState, line: str) -> bool:
    """Handle 'crypto engine N:Name' summary line. Returns True if consumed."""
    m = _CRYPTO_ENGINE_SUMMARY_RE.match(line)
    if not m:
        return False
    summary_name = m.group("name")
    for ename in state.engines:
        if ename in summary_name or summary_name in ename:
            state.current_engine = state.engines[ename]
            break
    else:
        state.current_engine = state.engines.get(summary_name)
        if state.current_engine is None:
            state.current_engine = {"state": "Active"}
            state.engines[summary_name] = state.current_engine
    state.reset_continuation()
    return True


def _continue_capability(state: _ParseState, stripped: str) -> bool:
    """Append continuation tokens to the current engine's capabilities."""
    target = state.current_engine
    if target is None:
        for eng in reversed(list(state.engines.values())):
            if "capabilities" in eng:
                target = eng
                break
    if target is None or "capabilities" not in target:
        state.continuation = ""
        return False
    caps = cast(list[str], target["capabilities"])
    caps.extend(_split_csv(stripped))
    if not stripped.endswith(","):
        state.continuation = ""
    return True


def _continue_ssl_versions(state: _ParseState, stripped: str) -> bool:
    """Append continuation tokens to the current engine's SSL versions."""
    if state.current_engine is None:
        state.continuation = ""
        return False
    versions = cast(list[str], state.current_engine["ssl_versions"])
    versions.extend(_split_csv(stripped))
    if not stripped.endswith(","):
        state.continuation = ""
    return True


def _handle_continuation(state: _ParseState, line: str) -> bool:
    """Handle capability or SSL version continuation lines.

    Returns True if the line was consumed as a continuation.
    """
    if not state.continuation:
        return False

    stripped = line.strip()
    if not stripped or _is_known_pattern(line):
        state.continuation = ""
        return False

    if state.continuation == "capability":
        return _continue_capability(state, stripped)

    if state.continuation == "ssl_versions":
        return _continue_ssl_versions(state, stripped)

    state.continuation = ""
    return False


def _try_dh_usage(state: _ParseState, line: str) -> bool:
    """Try to parse DH usage line. Returns True if consumed."""
    m = _DH_USAGE_RE.match(line)
    if not m or state.current_engine is None:
        return False
    state.current_engine["dh_usage"] = cast(
        DHUsage,
        {
            "in_use": int(m.group("in_use")),
            "freeing": int(m.group("freeing")),
            "free": int(m.group("free")),
        },
    )
    state.reset_continuation()
    return True


def _try_engine_content(state: _ParseState, line: str) -> bool:
    """Try to parse content lines within a crypto engine block.

    Returns True if the line was consumed.
    """
    engine = state.current_engine
    if engine is None:
        return False

    # Capability line
    m = _CAPABILITY_RE.match(line)
    if m:
        caps_text = m.group("caps")
        engine["capabilities"] = _split_csv(caps_text)
        state.continuation = "capability" if caps_text.rstrip().endswith(",") else ""
        state.suite_version = ""
        return True

    # Session counters (IKE, IKEv2, DH, IPSec)
    if _try_session_counters(line, engine):
        state.reset_continuation()
        return True

    # SSL scalar fields
    if _try_ssl_fields(line, engine):
        state.reset_continuation()
        return True

    # SSL versions (may have continuation)
    m = _SSL_VERSIONS_RE.match(line)
    if m:
        versions_text = m.group("versions")
        engine["ssl_versions"] = _split_csv(versions_text)
        state.continuation = (
            "ssl_versions" if versions_text.rstrip().endswith(",") else ""
        )
        state.suite_version = ""
        return True

    # Cipher suites
    consumed, state.suite_version = _try_cipher_suites(
        line, engine, state.suite_version
    )
    if consumed:
        state.continuation = ""
        return True

    return False


def _parse_engines(
    lines: list[str],
) -> tuple[dict[str, CryptoEngineEntry], DHPregeneration | None]:
    """Parse all crypto engine blocks and DH pregeneration info."""
    state = _ParseState()

    for line in lines:
        if _handle_engine_header(state, line):
            continue

        if _try_global_section(line, state.dh_pregen):
            state.current_engine = None
            state.reset_continuation()
            continue

        if _handle_engine_summary(state, line):
            continue

        if _try_dh_usage(state, line):
            continue

        if _handle_continuation(state, line):
            continue

        if state.current_engine is None:
            state.continuation = ""
            continue

        _try_engine_content(state, line)

    dh_result: DHPregeneration | None = None
    if "count" in state.dh_pregen and "lifetime_seconds" in state.dh_pregen:
        dh_result = cast(DHPregeneration, state.dh_pregen)

    return cast(dict[str, CryptoEngineEntry], state.engines), dh_result


@register(OS.CISCO_IOSXE, "show crypto eli all")
class ShowCryptoEliAllParser(BaseParser[ShowCryptoEliAllResult]):
    """Parser for 'show crypto eli all' on IOS-XE.

    Extracts hardware encryption status, crypto engine details
    (capabilities, session counters, SSL configuration, cipher
    suites), and DH pregeneration information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoEliAllResult:
        """Parse 'show crypto eli all' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Structured crypto engine and encryption data.

        Raises:
            ValueError: If required fields are not found.
        """
        result: dict[str, object] = {}
        lines = output.splitlines()

        for line in lines:
            m = _HW_ENCRYPTION_RE.match(line)
            if m:
                result["hardware_encryption"] = m.group("state")
                continue

            m = _NUM_ENGINES_RE.match(line)
            if m:
                result["number_of_crypto_engines"] = int(m.group("count"))
                continue

        for required in ("hardware_encryption", "number_of_crypto_engines"):
            if required not in result:
                msg = f"Missing required field: {required}"
                raise ValueError(msg)

        engines, dh_pregen = _parse_engines(lines)
        result["engines"] = engines

        if dh_pregen is not None:
            result["dh_pregeneration"] = dh_pregen

        return cast(ShowCryptoEliAllResult, result)
