"""Parser for 'show macsec mka statistics interface' command on Cisco IOS-XR."""

import re
from collections.abc import Callable
from typing import Any, ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class SessionStatistics(TypedDict):
    """Session-level statistics."""

    link_secured_uptime: str
    session_uptime: str
    sak_rekey_count_ha: int
    sak_rekey_count: int
    last_sak_an: int
    last_sak_install_time: str


class CaStatistics(TypedDict):
    """CA (Connectivity Association) statistics."""

    pairwise_caks_derived: int
    pairwise_cak_rekeys: int
    group_caks_generated: int
    group_caks_received: int


class SaStatistics(TypedDict):
    """SA (Security Association) statistics."""

    saks_generated: int
    saks_rekeyed: int
    saks_received: int
    sak_responses_received: int
    ppk_tuple_generated: int
    ppk_retrieved: int


class MkpduTransmitted(TypedDict):
    """MKPDU transmitted counters."""

    total: int
    distributed_sak: int
    distributed_cak: int
    distributed_ppk: int
    ppk_capable: int


class MkpduReceived(TypedDict):
    """MKPDU validated and received counters."""

    total: int
    distributed_sak: int
    distributed_cak: int
    distributed_ppk: int
    ppk_capable: int


class MkpduStatistics(TypedDict):
    """MKPDU statistics."""

    transmitted: MkpduTransmitted
    received: MkpduReceived


class CaMkpduFailures(TypedDict):
    """CA MKPDU failure counters."""

    rx_validation_icv: int
    rx_packet_validation: int
    rx_bad_peer_mn: int
    rx_non_recent_peerlist_mn: int
    rx_drop_sakuse_kn_mismatch: int
    rx_drop_sakuse_rx_not_set: int
    rx_drop_sakuse_key_mi_mismatch: int
    rx_drop_sakuse_an_not_in_use: int
    rx_drop_sakuse_ks_rx_tx_not_set: int


class CaPpkFailures(TypedDict):
    """CA PPK failure counters."""

    ppk_id_nak: int
    ppk_id_null: int
    ppk_id_mismatched: int
    ppk_request_timeout: int
    ppk_tuple_failure: int
    ppk_retrieval_failure: int
    ppk_retry_failure: int
    ppk_tid_mismatch: int
    ppk_identity_not_found: int
    ppk_aipc_conn_down_fail: int


class MkaIdbStatistics(TypedDict):
    """MKA IDB statistics."""

    mkpdus_tx_success: int
    mkpdus_tx_fail: int
    mkpdus_tx_pkt_build_fail: int
    mkpdus_no_tx_on_intf_down: int
    mkpdus_no_rx_on_intf_down: int
    mkpdus_rx_ca_not_found: int
    mkpdus_rx_error: int
    mkpdus_rx_success: int
    mkpdus_rx_invalid_length: int
    mkpdus_rx_invalid_ckn: int
    mkpdus_rx_force_suspended: int
    mkpdus_tx_force_suspended: int


class MkpduFailures(TypedDict):
    """MKPDU failure counters."""

    rx_validation_icv: int
    rx_packet_validation: int
    rx_bad_peer_mn: int
    rx_non_recent_peerlist_mn: int
    rx_drop_sakuse_kn_mismatch: int
    rx_drop_sakuse_rx_not_set: int
    rx_drop_sakuse_key_mi_mismatch: int
    rx_drop_sakuse_an_not_in_use: int
    rx_drop_sakuse_ks_rx_tx_not_set: int
    rx_drop_packet_ethertype_mismatch: int
    rx_drop_packet_source_mac_null: int
    rx_drop_packet_destination_mac_null: int
    rx_drop_packet_payload_null: int


class SakFailures(TypedDict):
    """SAK failure counters."""

    sak_generation: int
    hash_key_generation: int
    sak_encryption_wrap: int
    sak_decryption_unwrap: int


class PpkFailures(TypedDict):
    """PPK failure counters."""

    ppk_id_nak: int
    ppk_id_null_received: int
    ppk_id_mismatched: int
    ppk_request_timeout: int
    ppk_tuple_failure: int
    ppk_retrieval_failure: int
    ppk_retry_failure: int
    ppk_tid_mismatch: int
    ppk_identity_not_found: int
    ppk_hash_key_generation: int
    ppk_id_encryption_wrap: int
    ppk_id_decryption_unwrap: int
    ppk_aipc_conn_down_fail: int


class CaFailures(TypedDict):
    """CA failure counters."""

    ick_derivation: int
    kek_derivation: int
    invalid_peer_macsec_capability: int


class MacsecFailures(TypedDict):
    """MACsec failure counters."""

    rx_sc_creation: int
    tx_sc_creation: int
    rx_sa_installation: int
    tx_sa_installation: int


class MacsecMkaStatisticsResult(TypedDict):
    """Schema for 'show macsec mka statistics interface' parsed output."""

    interface: str
    reauthentication_attempts: int
    session_statistics: SessionStatistics
    ca_statistics: CaStatistics
    sa_statistics: SaStatistics
    mkpdu_statistics: MkpduStatistics
    ca_mkpdu_failures: CaMkpduFailures
    ca_ppk_failures: CaPpkFailures
    mka_idb_statistics: MkaIdbStatistics
    mkpdu_failures: MkpduFailures
    sak_failures: SakFailures
    ppk_failures: PpkFailures
    ca_failures: CaFailures
    macsec_failures: MacsecFailures


# Interface line in header
_INTERFACE_PATTERN = re.compile(
    r"^MKA Statistics for Session on interface\s+\((?P<interface>\S+)\)\s*$"
)

# Generic key-value pattern: "Key Name.... value" or "Key Name... value"
_KV_PATTERN = re.compile(r'^\s*"?(?P<key>[^."\n]+?)"?\s*\.{2,}\s*(?P<value>\S+.*?)\s*$')

# Reauthentication attempts line
_REAUTH_PATTERN = re.compile(r"^Reauthentication Attempts\.\.\s*(?P<value>\d+)\s*$")


def _parse_int(value: str) -> int:
    """Parse an integer value, stripping any trailing whitespace."""
    return int(value.strip())


def _normalize_key(key: str) -> str:
    """Normalize a key string for matching.

    Strips quotes, lowercases, replaces spaces/hyphens/parens with underscores.
    """
    normalized = key.strip().strip('"').lower()
    normalized = re.sub(r"[/\s()\-]+", "_", normalized)
    normalized = re.sub(r"_+", "_", normalized)
    return normalized.strip("_")


_SECTION_HEADERS = frozenset(
    {
        "session statistics",
        "ca statistics",
        "sa statistics",
        "mkpdu statistics",
        "ca failures",
        "ca mkpdu failures",
        "ca ppk failures",
        "mka idb statistics",
        "mkpdu failures",
        "sak failures",
        "ppk failures",
        "macsec failures",
    }
)


def _identify_section(line: str) -> str | None:
    """Identify a section header from a line, returning normalized name."""
    lower = line.strip().lower()
    for header in _SECTION_HEADERS:
        if lower == header:
            return header
    return None


# Mapping tables for substring-based dispatch.
# Each entry is (substring_to_match, target_dict_key).
# Order matters: more specific matches must come first.

_CA_MKPDU_FAILURES_MAP: list[tuple[str, str]] = [
    ("rx_validation", "rx_validation_icv"),  # also requires "icv" check
    ("rx_packet_validation", "rx_packet_validation"),
    ("bad_peer_mn", "rx_bad_peer_mn"),
    ("non_recent_peerlist", "rx_non_recent_peerlist_mn"),
    ("kn_mismatch", "rx_drop_sakuse_kn_mismatch"),
    ("rx_not_set", "rx_drop_sakuse_rx_not_set"),
    ("key_mi_mismatch", "rx_drop_sakuse_key_mi_mismatch"),
    ("an_not_in_use", "rx_drop_sakuse_an_not_in_use"),
    ("ks_rx_tx_not_set", "rx_drop_sakuse_ks_rx_tx_not_set"),
]

_PPK_FAILURES_MAP: list[tuple[str, str]] = [
    ("ppk_id_nak", "ppk_id_nak"),
    ("ppk_id_null", "ppk_id_null"),
    ("ppk_id_mismatch", "ppk_id_mismatched"),
    ("request_timeout", "ppk_request_timeout"),
    ("tuple_failure", "ppk_tuple_failure"),
    ("retrieval_failure", "ppk_retrieval_failure"),
    ("retry_failure", "ppk_retry_failure"),
    ("tid_mismatch", "ppk_tid_mismatch"),
    ("identity_not_found", "ppk_identity_not_found"),
    ("aipc_conn_down", "ppk_aipc_conn_down_fail"),
]

_MKA_IDB_MAP: list[tuple[str, str]] = [
    ("tx_pkt_build_fail", "mkpdus_tx_pkt_build_fail"),
    ("no_tx_on_intf_down", "mkpdus_no_tx_on_intf_down"),
    ("no_rx_on_intf_down", "mkpdus_no_rx_on_intf_down"),
    ("rx_ca_not_found", "mkpdus_rx_ca_not_found"),
    ("rx_invalid_length", "mkpdus_rx_invalid_length"),
    ("rx_invalid_ckn", "mkpdus_rx_invalid_ckn"),
    ("rx_force_suspended", "mkpdus_rx_force_suspended"),
    ("tx_force_suspended", "mkpdus_tx_force_suspended"),
]

_MKA_IDB_EXACT_MAP: dict[str, str] = {
    "mkpdus_tx_success": "mkpdus_tx_success",
    "mkpdus_tx_fail": "mkpdus_tx_fail",
    "mkpdus_rx_error": "mkpdus_rx_error",
    "mkpdus_rx_success": "mkpdus_rx_success",
}

_MKPDU_FAILURES_MAP: list[tuple[str, str]] = [
    ("rx_packet_validation", "rx_packet_validation"),
    ("bad_peer_mn", "rx_bad_peer_mn"),
    ("non_recent_peerlist", "rx_non_recent_peerlist_mn"),
    ("kn_mismatch", "rx_drop_sakuse_kn_mismatch"),
    ("rx_not_set", "rx_drop_sakuse_rx_not_set"),
    ("key_mi_mismatch", "rx_drop_sakuse_key_mi_mismatch"),
    ("an_not_in_use", "rx_drop_sakuse_an_not_in_use"),
    ("ks_rx_tx_not_set", "rx_drop_sakuse_ks_rx_tx_not_set"),
    ("ethertype_mismatch", "rx_drop_packet_ethertype_mismatch"),
    ("source_mac_null", "rx_drop_packet_source_mac_null"),
    ("destination_mac_null", "rx_drop_packet_destination_mac_null"),
    ("payload_null", "rx_drop_packet_payload_null"),
]


def _dispatch_substring(
    norm: str,
    target: Any,  # noqa: ANN401
    value: int,
    mapping: list[tuple[str, str]],
) -> bool:
    """Apply first matching substring mapping to target dict.

    Returns True if matched.
    """
    for substring, field in mapping:
        if substring in norm:
            target[field] = value
            return True
    return False


class _ParseState:
    """Mutable state accumulator for the parse loop."""

    def __init__(self) -> None:
        self.current_section: str | None = None
        self.mkpdu_sub: str | None = None
        self.uptime_key: str | None = None
        self.uptime_accum: str = ""
        self.reauth_attempts: int = 0

        self.session_stats = SessionStatistics(
            link_secured_uptime="",
            session_uptime="",
            sak_rekey_count_ha=0,
            sak_rekey_count=0,
            last_sak_an=0,
            last_sak_install_time="",
        )
        self.ca_stats = CaStatistics(
            pairwise_caks_derived=0,
            pairwise_cak_rekeys=0,
            group_caks_generated=0,
            group_caks_received=0,
        )
        self.sa_stats = SaStatistics(
            saks_generated=0,
            saks_rekeyed=0,
            saks_received=0,
            sak_responses_received=0,
            ppk_tuple_generated=0,
            ppk_retrieved=0,
        )
        self.mkpdu_tx = MkpduTransmitted(
            total=0,
            distributed_sak=0,
            distributed_cak=0,
            distributed_ppk=0,
            ppk_capable=0,
        )
        self.mkpdu_rx = MkpduReceived(
            total=0,
            distributed_sak=0,
            distributed_cak=0,
            distributed_ppk=0,
            ppk_capable=0,
        )
        self.ca_mkpdu_fail = CaMkpduFailures(
            rx_validation_icv=0,
            rx_packet_validation=0,
            rx_bad_peer_mn=0,
            rx_non_recent_peerlist_mn=0,
            rx_drop_sakuse_kn_mismatch=0,
            rx_drop_sakuse_rx_not_set=0,
            rx_drop_sakuse_key_mi_mismatch=0,
            rx_drop_sakuse_an_not_in_use=0,
            rx_drop_sakuse_ks_rx_tx_not_set=0,
        )
        self.ca_ppk_fail = CaPpkFailures(
            ppk_id_nak=0,
            ppk_id_null=0,
            ppk_id_mismatched=0,
            ppk_request_timeout=0,
            ppk_tuple_failure=0,
            ppk_retrieval_failure=0,
            ppk_retry_failure=0,
            ppk_tid_mismatch=0,
            ppk_identity_not_found=0,
            ppk_aipc_conn_down_fail=0,
        )
        self.mka_idb = MkaIdbStatistics(
            mkpdus_tx_success=0,
            mkpdus_tx_fail=0,
            mkpdus_tx_pkt_build_fail=0,
            mkpdus_no_tx_on_intf_down=0,
            mkpdus_no_rx_on_intf_down=0,
            mkpdus_rx_ca_not_found=0,
            mkpdus_rx_error=0,
            mkpdus_rx_success=0,
            mkpdus_rx_invalid_length=0,
            mkpdus_rx_invalid_ckn=0,
            mkpdus_rx_force_suspended=0,
            mkpdus_tx_force_suspended=0,
        )
        self.mkpdu_fail = MkpduFailures(
            rx_validation_icv=0,
            rx_packet_validation=0,
            rx_bad_peer_mn=0,
            rx_non_recent_peerlist_mn=0,
            rx_drop_sakuse_kn_mismatch=0,
            rx_drop_sakuse_rx_not_set=0,
            rx_drop_sakuse_key_mi_mismatch=0,
            rx_drop_sakuse_an_not_in_use=0,
            rx_drop_sakuse_ks_rx_tx_not_set=0,
            rx_drop_packet_ethertype_mismatch=0,
            rx_drop_packet_source_mac_null=0,
            rx_drop_packet_destination_mac_null=0,
            rx_drop_packet_payload_null=0,
        )
        self.sak_fail = SakFailures(
            sak_generation=0,
            hash_key_generation=0,
            sak_encryption_wrap=0,
            sak_decryption_unwrap=0,
        )
        self.ppk_fail = PpkFailures(
            ppk_id_nak=0,
            ppk_id_null_received=0,
            ppk_id_mismatched=0,
            ppk_request_timeout=0,
            ppk_tuple_failure=0,
            ppk_retrieval_failure=0,
            ppk_retry_failure=0,
            ppk_tid_mismatch=0,
            ppk_identity_not_found=0,
            ppk_hash_key_generation=0,
            ppk_id_encryption_wrap=0,
            ppk_id_decryption_unwrap=0,
            ppk_aipc_conn_down_fail=0,
        )
        self.ca_fail = CaFailures(
            ick_derivation=0,
            kek_derivation=0,
            invalid_peer_macsec_capability=0,
        )
        self.macsec_fail = MacsecFailures(
            rx_sc_creation=0,
            tx_sc_creation=0,
            rx_sa_installation=0,
            tx_sa_installation=0,
        )

    def flush_uptime(self) -> None:
        """Flush any pending uptime accumulator to session stats."""
        if self.uptime_key is not None:
            normalized = re.sub(r"\s+", " ", self.uptime_accum).strip()
            if self.uptime_key == "link_secured_uptime":
                self.session_stats["link_secured_uptime"] = normalized
            elif self.uptime_key == "session_uptime":
                self.session_stats["session_uptime"] = normalized
            self.uptime_key = None
            self.uptime_accum = ""


_QUOTED_MKPDU_PATTERN = re.compile(
    r'^\s*"(?P<key>[^"]+)"\s*\.{2,}\s*(?P<value>\d+)\s*$'
)


def _handle_mkpdu_quoted(line: str, state: "_ParseState") -> None:
    """Handle quoted MKPDU sub-counter lines."""
    if state.current_section != "mkpdu statistics" or not state.mkpdu_sub:
        return
    quoted_match = _QUOTED_MKPDU_PATTERN.match(line)
    if quoted_match:
        qkey = _normalize_key(quoted_match.group("key"))
        qval = _parse_int(quoted_match.group("value"))
        target = state.mkpdu_tx if state.mkpdu_sub == "tx" else state.mkpdu_rx
        _apply_mkpdu_sub_counter(target, qkey, qval)


def _get_section_handler(
    section: str | None, state: "_ParseState"
) -> Callable[[str, str], None] | None:
    """Return a bound handler function for the given section, or None."""
    if section is None:
        return None
    handlers: dict[str, Callable[[str, str], None]] = {
        "session statistics": lambda k, v: _parse_session_stats_line(
            k, v, state.session_stats
        ),
        "ca statistics": lambda k, v: _parse_ca_stats_line(k, v, state.ca_stats),
        "sa statistics": lambda k, v: _parse_sa_stats_line(k, v, state.sa_stats),
        "ca mkpdu failures": lambda k, v: _parse_sakuse_failures_line(
            k, v, state.ca_mkpdu_fail
        ),
        "ca ppk failures": lambda k, v: _parse_ppk_common_line(k, v, state.ca_ppk_fail),
        "mka idb statistics": lambda k, v: _parse_mka_idb_line(k, v, state.mka_idb),
        "mkpdu failures": lambda k, v: _parse_mkpdu_failures_line(
            k, v, state.mkpdu_fail
        ),
        "sak failures": lambda k, v: _parse_sak_failures_line(k, v, state.sak_fail),
        "ppk failures": lambda k, v: _parse_ppk_full_failures_line(
            k, v, state.ppk_fail
        ),
        "ca failures": lambda k, v: _parse_ca_failures_line(k, v, state.ca_fail),
        "macsec failures": lambda k, v: _parse_macsec_failures_line(
            k, v, state.macsec_fail
        ),
    }
    return handlers.get(section)


@register(
    OS.CISCO_IOSXR,
    r"show macsec mka statistics interface (?P<interface>\S+)",
)
class ShowMacsecMkaStatisticsInterfaceParser(
    BaseParser["MacsecMkaStatisticsResult"],
):
    """Parser for 'show macsec mka statistics interface' on IOS-XR.

    Parses MKA session statistics for a specific interface, including
    session statistics, CA/SA statistics, MKPDU counters, and various
    failure categories.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MACSEC,
            ParserTag.SECURITY,
        }
    )

    @classmethod
    def parse(cls, output: str) -> MacsecMkaStatisticsResult:
        """Parse 'show macsec mka statistics interface' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MACsec MKA statistics data.

        Raises:
            ValueError: If interface header not found in output.
        """
        lines = output.splitlines()
        interface = cls._extract_interface(lines)
        state = _ParseState()

        i = 0
        while i < len(lines):
            i = cls._process_line(lines, i, state)

        state.flush_uptime()

        return MacsecMkaStatisticsResult(
            interface=interface,
            reauthentication_attempts=state.reauth_attempts,
            session_statistics=state.session_stats,
            ca_statistics=state.ca_stats,
            sa_statistics=state.sa_stats,
            mkpdu_statistics=MkpduStatistics(
                transmitted=state.mkpdu_tx,
                received=state.mkpdu_rx,
            ),
            ca_mkpdu_failures=state.ca_mkpdu_fail,
            ca_ppk_failures=state.ca_ppk_fail,
            mka_idb_statistics=state.mka_idb,
            mkpdu_failures=state.mkpdu_fail,
            sak_failures=state.sak_fail,
            ppk_failures=state.ppk_fail,
            ca_failures=state.ca_fail,
            macsec_failures=state.macsec_fail,
        )

    @classmethod
    def _process_line(cls, lines: list[str], i: int, state: _ParseState) -> int:
        """Process a single line and return next line index."""
        line = lines[i]
        stripped = line.strip()

        if not stripped or stripped.startswith("="):
            return i + 1

        if cls._handle_header_lines(stripped, state):
            return i + 1

        kv_match = _KV_PATTERN.match(line)
        if kv_match:
            cls._handle_kv_match(kv_match, state)
            return i + 1

        # Continuation lines for uptime values
        if state.uptime_key is not None and stripped:
            state.uptime_accum += " " + stripped
            if _is_complete_uptime(state.uptime_accum):
                state.flush_uptime()
            return i + 1

        # Quoted MKPDU sub-counter lines
        _handle_mkpdu_quoted(line, state)
        return i + 1

    @classmethod
    def _handle_header_lines(cls, stripped: str, state: _ParseState) -> bool:
        """Handle section headers and metadata lines. Returns True if consumed."""
        section = _identify_section(stripped)
        if section is not None:
            state.flush_uptime()
            state.current_section = section
            state.mkpdu_sub = None
            return True

        if _INTERFACE_PATTERN.match(stripped):
            return True

        reauth_match = _REAUTH_PATTERN.match(stripped)
        if reauth_match:
            state.reauth_attempts = _parse_int(reauth_match.group("value"))
            return True

        if stripped.lower().startswith("last sak data"):
            return True

        return False

    @classmethod
    def _handle_kv_match(cls, kv_match: re.Match[str], state: _ParseState) -> None:
        """Process a key-value regex match."""
        state.flush_uptime()
        raw_key = kv_match.group("key")
        value = kv_match.group("value")
        cls._dispatch_kv(raw_key, value, state)
        # Check if uptime wraps to next line
        norm = _normalize_key(raw_key)
        if (
            state.current_section == "session statistics"
            and norm in ("link_secured_uptime", "session_uptime")
            and not _is_complete_uptime(value)
        ):
            state.uptime_key = norm
            state.uptime_accum = value

    @classmethod
    def _dispatch_kv(cls, raw_key: str, value: str, state: _ParseState) -> None:
        """Dispatch a key-value pair to the correct section handler."""
        section = state.current_section
        if section == "mkpdu statistics":
            _parse_mkpdu_line(raw_key, value, state)
            return
        handler = _get_section_handler(section, state)
        if handler is not None:
            handler(raw_key, value)

    @classmethod
    def _extract_interface(cls, lines: list[str]) -> str:
        """Extract interface name from the header line."""
        for line in lines:
            match = _INTERFACE_PATTERN.match(line.strip())
            if match:
                return canonical_interface_name(
                    match.group("interface"), os=OS.CISCO_IOSXR
                )
        msg = "No MKA statistics interface header found in output"
        raise ValueError(msg)


def _is_complete_uptime(value: str) -> bool:
    """Check if an uptime value string is complete (ends with seconds)."""
    return "second" in value.lower()


def _parse_session_stats_line(
    raw_key: str, value: str, stats: SessionStatistics
) -> None:
    """Parse a session statistics key-value line."""
    norm = _normalize_key(raw_key)
    if norm == "link_secured_uptime":
        if _is_complete_uptime(value):
            stats["link_secured_uptime"] = re.sub(r"\s+", " ", value).strip()
    elif norm == "session_uptime":
        if _is_complete_uptime(value):
            stats["session_uptime"] = re.sub(r"\s+", " ", value).strip()
    elif norm == "sak_rekey_count_ha":
        stats["sak_rekey_count_ha"] = _parse_int(value)
    elif norm == "sak_rekey_count":
        stats["sak_rekey_count"] = _parse_int(value)
    elif norm == "an":
        stats["last_sak_an"] = _parse_int(value)
    elif norm == "sa_install_time":
        stats["last_sak_install_time"] = value.strip()


def _parse_ca_stats_line(raw_key: str, value: str, stats: CaStatistics) -> None:
    """Parse a CA statistics key-value line."""
    norm = _normalize_key(raw_key)
    field_map: dict[str, str] = {
        "pairwise_caks_derived": "pairwise_caks_derived",
        "pairwise_cak_rekeys": "pairwise_cak_rekeys",
        "group_caks_generated": "group_caks_generated",
        "group_caks_received": "group_caks_received",
    }
    if norm in field_map:
        stats[field_map[norm]] = _parse_int(value)  # type: ignore[literal-required]  # ty: ignore[invalid-key]


def _parse_sa_stats_line(raw_key: str, value: str, stats: SaStatistics) -> None:
    """Parse an SA statistics key-value line."""
    norm = _normalize_key(raw_key)
    field_map: dict[str, str] = {
        "saks_generated": "saks_generated",
        "saks_rekeyed": "saks_rekeyed",
        "saks_received": "saks_received",
        "sak_responses_received": "sak_responses_received",
        "ppk_tuple_generated": "ppk_tuple_generated",
        "ppk_retrieved": "ppk_retrieved",
    }
    if norm in field_map:
        stats[field_map[norm]] = _parse_int(value)  # type: ignore[literal-required]  # ty: ignore[invalid-key]


def _parse_mkpdu_line(raw_key: str, value: str, state: _ParseState) -> None:
    """Parse MKPDU statistics line and manage tx/rx sub-section state."""
    norm = _normalize_key(raw_key)
    if norm in ("mkpdus_transmitted", "mkpdus_tx"):
        state.mkpdu_tx["total"] = _parse_int(value)
        state.mkpdu_sub = "tx"
    elif norm in ("mkpdus_validated_&_rx", "mkpdus_validated_rx"):
        state.mkpdu_rx["total"] = _parse_int(value)
        state.mkpdu_sub = "rx"
    elif state.mkpdu_sub is not None:
        target = state.mkpdu_tx if state.mkpdu_sub == "tx" else state.mkpdu_rx
        _apply_mkpdu_sub_counter(target, norm, _parse_int(value))


def _apply_mkpdu_sub_counter(
    target: MkpduTransmitted | MkpduReceived, norm_key: str, value: int
) -> None:
    """Apply a sub-counter to MKPDU transmitted or received dict."""
    sub_map: dict[str, str] = {
        "distributed_sak": "distributed_sak",
        "distributed_cak": "distributed_cak",
        "distributed_ppk": "distributed_ppk",
        "ppk_capable": "ppk_capable",
    }
    if norm_key in sub_map:
        target[sub_map[norm_key]] = value  # type: ignore[literal-required]  # ty: ignore[invalid-key]


def _parse_sakuse_failures_line(
    raw_key: str, value: str, failures: CaMkpduFailures
) -> None:
    """Parse CA MKPDU failures (SAKUSE pattern lines)."""
    norm = _normalize_key(raw_key)
    # Special case: rx_validation requires "icv" in the key
    if "rx_validation" in norm and "icv" in norm:
        failures["rx_validation_icv"] = _parse_int(value)
        return
    _dispatch_substring(norm, failures, _parse_int(value), _CA_MKPDU_FAILURES_MAP[1:])


def _parse_ppk_common_line(raw_key: str, value: str, failures: CaPpkFailures) -> None:
    """Parse CA PPK failures lines."""
    norm = _normalize_key(raw_key)
    _dispatch_substring(norm, failures, _parse_int(value), _PPK_FAILURES_MAP)


def _parse_mka_idb_line(raw_key: str, value: str, stats: MkaIdbStatistics) -> None:
    """Parse MKA IDB statistics line."""
    norm = _normalize_key(raw_key)
    # Try exact match first
    if norm in _MKA_IDB_EXACT_MAP:
        stats[_MKA_IDB_EXACT_MAP[norm]] = _parse_int(value)  # type: ignore[literal-required]  # ty: ignore[invalid-key]
        return
    _dispatch_substring(norm, stats, _parse_int(value), _MKA_IDB_MAP)


def _parse_mkpdu_failures_line(
    raw_key: str, value: str, failures: MkpduFailures
) -> None:
    """Parse MKPDU failures lines."""
    norm = _normalize_key(raw_key)
    # Special case: rx_validation requires "icv"
    if "rx_validation" in norm and "icv" in norm:
        failures["rx_validation_icv"] = _parse_int(value)
        return
    _dispatch_substring(norm, failures, _parse_int(value), _MKPDU_FAILURES_MAP)


def _parse_sak_failures_line(raw_key: str, value: str, failures: SakFailures) -> None:
    """Parse SAK failures lines."""
    norm = _normalize_key(raw_key)
    if "sak_generation" in norm:
        failures["sak_generation"] = _parse_int(value)
    elif "hash_key_generation" in norm:
        failures["hash_key_generation"] = _parse_int(value)
    elif "decryption" in norm or "unwrap" in norm:
        failures["sak_decryption_unwrap"] = _parse_int(value)
    elif "encryption" in norm or "wrap" in norm:
        failures["sak_encryption_wrap"] = _parse_int(value)


_PPK_FULL_FAILURES_MAP: list[tuple[str, str]] = [
    ("ppk_id_nak", "ppk_id_nak"),
    ("ppk_id_null", "ppk_id_null_received"),
    ("ppk_id_mismatch", "ppk_id_mismatched"),
    ("hash_key", "ppk_hash_key_generation"),
    ("id_decryption", "ppk_id_decryption_unwrap"),
    ("id_unwrap", "ppk_id_decryption_unwrap"),
    ("id_encryption", "ppk_id_encryption_wrap"),
    ("id_wrap", "ppk_id_encryption_wrap"),
    ("aipc_conn_down", "ppk_aipc_conn_down_fail"),
    ("request_timeout", "ppk_request_timeout"),
    ("tuple_failure", "ppk_tuple_failure"),
    ("retrieval_failure", "ppk_retrieval_failure"),
    ("retry_failure", "ppk_retry_failure"),
    ("tid_mismatch", "ppk_tid_mismatch"),
    ("identity_not_found", "ppk_identity_not_found"),
]


def _parse_ppk_full_failures_line(
    raw_key: str, value: str, failures: PpkFailures
) -> None:
    """Parse PPK failures section (full set including hash/encryption)."""
    norm = _normalize_key(raw_key)
    _dispatch_substring(norm, failures, _parse_int(value), _PPK_FULL_FAILURES_MAP)


def _parse_ca_failures_line(raw_key: str, value: str, failures: CaFailures) -> None:
    """Parse CA failures lines."""
    norm = _normalize_key(raw_key)
    if "ick_derivation" in norm:
        failures["ick_derivation"] = _parse_int(value)
    elif "kek_derivation" in norm:
        failures["kek_derivation"] = _parse_int(value)
    elif "invalid_peer_macsec" in norm:
        failures["invalid_peer_macsec_capability"] = _parse_int(value)


def _parse_macsec_failures_line(
    raw_key: str, value: str, failures: MacsecFailures
) -> None:
    """Parse MACsec failures lines."""
    norm = _normalize_key(raw_key)
    if "rx_sc_creation" in norm:
        failures["rx_sc_creation"] = _parse_int(value)
    elif "tx_sc_creation" in norm:
        failures["tx_sc_creation"] = _parse_int(value)
    elif "rx_sa_installation" in norm:
        failures["rx_sa_installation"] = _parse_int(value)
    elif "tx_sa_installation" in norm:
        failures["tx_sa_installation"] = _parse_int(value)
