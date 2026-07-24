"""Parser for 'show macsec mka statistics location' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MkaSessionTotals(TypedDict):
    """MKA session total counters."""

    secured: int
    reauthentication_attempts: int
    deleted_secured: int
    keepalive_timeouts: int


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


class MkpduRxStatistics(TypedDict):
    """MKPDU receive sub-statistics."""

    distributed_sak: int
    distributed_cak: int
    distributed_ppk: int
    ppk_capable: int


class MkpduTxStatistics(TypedDict):
    """MKPDU transmit sub-statistics."""

    distributed_sak: int
    distributed_cak: int
    distributed_ppk: int
    ppk_capable: int


class MkpduStatistics(TypedDict):
    """MKPDU statistics."""

    validated_and_rx: int
    rx: MkpduRxStatistics
    transmitted: int
    tx: MkpduTxStatistics


class SessionFailures(TypedDict):
    """Session failure counters."""

    bring_up_failures: int
    reauthentication_failures: int
    duplicate_auth_mgr_handle: int


class SakFailures(TypedDict):
    """SAK failure counters."""

    sak_generation: int
    hash_key_generation: int
    sak_encryption_wrap: int
    sak_decryption_unwrap: int
    sak_cipher_mismatch: int


class PpkFailures(TypedDict):
    """PPK failure counters."""

    ppk_id_nak: int
    ppk_id_expired: int
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

    group_cak_generation: int
    group_cak_encryption_wrap: int
    group_cak_decryption_unwrap: int
    pairwise_cak_derivation: int
    ckn_derivation: int
    ick_derivation: int
    kek_derivation: int
    invalid_peer_macsec_capability: int


class MacsecFailures(TypedDict):
    """MACsec failure counters."""

    rx_sc_creation: int
    tx_sc_creation: int
    rx_sa_installation: int
    tx_sa_installation: int


class MkpduFailures(TypedDict):
    """MKPDU failure counters."""

    mkpdu_tx: int
    mkpdu_rx_icv_validation: int
    mkpdu_rx_packet_validation: int
    mkpdu_rx_bad_peer_mn: int
    mkpdu_rx_non_recent_peerlist_mn: int
    mkpdu_rx_drop_sakuse_kn_mismatch: int
    mkpdu_rx_drop_sakuse_rx_not_set: int
    mkpdu_rx_drop_sakuse_key_mi_mismatch: int
    mkpdu_rx_drop_sakuse_an_not_in_use: int
    mkpdu_rx_drop_sakuse_ks_rx_tx_not_set: int


class IoxGlobalStatistics(TypedDict):
    """IOX global statistics."""

    mkpdus_rx_idb_not_found: int
    mkpdus_rx_invalid_ckn: int
    mkpdus_tx_invalid_idb: int
    mkpdus_tx_pkt_build_fail: int


class MkaGlobalStatistics(TypedDict):
    """Top-level MKA global statistics structure."""

    session_totals: MkaSessionTotals
    ca_statistics: CaStatistics
    sa_statistics: SaStatistics
    mkpdu_statistics: MkpduStatistics


class MkaErrorCounters(TypedDict):
    """Top-level MKA error counters structure."""

    session_failures: SessionFailures
    sak_failures: SakFailures
    ppk_failures: PpkFailures
    ca_failures: CaFailures
    macsec_failures: MacsecFailures
    mkpdu_failures: MkpduFailures


class ShowMacsecMkaStatisticsLocationResult(TypedDict):
    """Schema for 'show macsec mka statistics location' parsed output."""

    mka_global_statistics: MkaGlobalStatistics
    mka_error_counters: MkaErrorCounters
    iox_global_statistics: IoxGlobalStatistics


# Regex patterns for extracting counter values
_COUNTER_RE = re.compile(r"\.{2,}\s*(?P<value>\d+)\s*$")
_QUOTED_COUNTER_RE = re.compile(r'^\s*"(?P<label>[^"]+)"\.{2,}\s*(?P<value>\d+)\s*$')

# MKPDU quoted-label to key mapping
_MKPDU_QUOTED_KEYS: dict[str, str] = {
    "distributed sak": "distributed_sak",
    "distributed cak": "distributed_cak",
    "distributed ppk": "distributed_ppk",
    "ppk capable": "ppk_capable",
}


def _extract_value(line: str) -> int | None:
    """Extract a numeric value from a counter line using dot separators."""
    match = _COUNTER_RE.search(line)
    if match:
        return int(match.group("value"))
    return None


def _scan_to_section(lines: list[str], idx: int, marker: str) -> int:
    """Advance index until a line containing marker (case-insensitive)."""
    while idx < len(lines):
        if marker in lines[idx].lower():
            return idx + 1
        idx += 1
    return idx


def _skip_separators(lines: list[str], idx: int) -> int:
    """Skip lines that are purely separator characters (=)."""
    while idx < len(lines) and lines[idx].strip().startswith("="):
        idx += 1
    return idx


def _parse_counter_section(
    lines: list[str],
    idx: int,
    mapping: dict[str, str],
    stop_markers: list[str],
) -> tuple[dict[str, int], int]:
    """Parse a section of counter lines into a dict using mapping.

    Stops at an empty line or when a stop_marker is encountered.

    Returns:
        Tuple of (parsed values dict, new index).
    """
    values: dict[str, int] = {}
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip().lower()
        if not stripped or any(stripped.startswith(m) for m in stop_markers):
            break
        val = _extract_value(line)
        if val is not None:
            for key, attr in mapping.items():
                if key in stripped:
                    values[attr] = val
                    break
        idx += 1
    return values, idx


def _parse_mkpdu_statistics(lines: list[str], idx: int) -> tuple[MkpduStatistics, int]:
    """Parse MKPDU Statistics section."""
    rx_stats = MkpduRxStatistics(
        distributed_sak=0,
        distributed_cak=0,
        distributed_ppk=0,
        ppk_capable=0,
    )
    tx_stats = MkpduTxStatistics(
        distributed_sak=0,
        distributed_cak=0,
        distributed_ppk=0,
        ppk_capable=0,
    )
    validated_and_rx = 0
    transmitted = 0
    current_target: MkpduRxStatistics | MkpduTxStatistics | None = None

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip().lower()
        if not stripped or stripped.startswith("mka error counter"):
            break

        val = _extract_value(line)
        if val is not None:
            if "validated" in stripped and "rx" in stripped:
                validated_and_rx = val
                current_target = rx_stats
            elif "transmitted" in stripped:
                transmitted = val
                current_target = tx_stats
            elif current_target is not None:
                _apply_quoted_mkpdu(line, current_target)
        idx += 1

    result = MkpduStatistics(
        validated_and_rx=validated_and_rx,
        rx=rx_stats,
        transmitted=transmitted,
        tx=tx_stats,
    )
    return result, idx


def _apply_quoted_mkpdu(
    line: str,
    target: MkpduRxStatistics | MkpduTxStatistics,
) -> None:
    """Apply a quoted MKPDU sub-counter line to the target dict."""
    quoted = _QUOTED_COUNTER_RE.match(line.strip())
    if not quoted:
        return
    label = quoted.group("label").lower()
    qval = int(quoted.group("value"))
    for pattern, attr in _MKPDU_QUOTED_KEYS.items():
        if pattern in label:
            target[attr] = qval  # type: ignore[literal-required]
            break


def _build_global_statistics(
    lines: list[str], idx: int
) -> tuple[MkaGlobalStatistics, int]:
    """Parse the entire MKA Global Statistics block."""
    # Session Totals
    idx = _scan_to_section(lines, idx, "mka session totals")
    session_mapping = {
        "secured": "secured",
        "reauthentication attempts": "reauthentication_attempts",
        "deleted (secured)": "deleted_secured",
        "keepalive timeouts": "keepalive_timeouts",
    }
    values, idx = _parse_counter_section(lines, idx, session_mapping, ["ca statistics"])
    session_totals = MkaSessionTotals(
        secured=values.get("secured", 0),
        reauthentication_attempts=values.get("reauthentication_attempts", 0),
        deleted_secured=values.get("deleted_secured", 0),
        keepalive_timeouts=values.get("keepalive_timeouts", 0),
    )

    # CA Statistics
    idx = _scan_to_section(lines, idx, "ca statistics")
    ca_mapping = {
        "pairwise caks derived": "pairwise_caks_derived",
        "pairwise cak rekeys": "pairwise_cak_rekeys",
        "group caks generated": "group_caks_generated",
        "group caks received": "group_caks_received",
    }
    values, idx = _parse_counter_section(lines, idx, ca_mapping, ["sa statistics"])
    ca_stats = CaStatistics(
        pairwise_caks_derived=values.get("pairwise_caks_derived", 0),
        pairwise_cak_rekeys=values.get("pairwise_cak_rekeys", 0),
        group_caks_generated=values.get("group_caks_generated", 0),
        group_caks_received=values.get("group_caks_received", 0),
    )

    # SA Statistics
    idx = _scan_to_section(lines, idx, "sa statistics")
    sa_mapping = {
        "saks generated": "saks_generated",
        "saks rekeyed": "saks_rekeyed",
        "saks received": "saks_received",
        "sak responses received": "sak_responses_received",
        "ppk tuple generated": "ppk_tuple_generated",
        "ppk retrieved": "ppk_retrieved",
    }
    values, idx = _parse_counter_section(lines, idx, sa_mapping, ["mkpdu statistics"])
    sa_stats = SaStatistics(
        saks_generated=values.get("saks_generated", 0),
        saks_rekeyed=values.get("saks_rekeyed", 0),
        saks_received=values.get("saks_received", 0),
        sak_responses_received=values.get("sak_responses_received", 0),
        ppk_tuple_generated=values.get("ppk_tuple_generated", 0),
        ppk_retrieved=values.get("ppk_retrieved", 0),
    )

    # MKPDU Statistics
    idx = _scan_to_section(lines, idx, "mkpdu statistics")
    mkpdu_stats, idx = _parse_mkpdu_statistics(lines, idx)

    return (
        MkaGlobalStatistics(
            session_totals=session_totals,
            ca_statistics=ca_stats,
            sa_statistics=sa_stats,
            mkpdu_statistics=mkpdu_stats,
        ),
        idx,
    )


def _build_error_counters(lines: list[str], idx: int) -> tuple[MkaErrorCounters, int]:
    """Parse the entire MKA Error Counter Totals block."""
    idx = _skip_separators(lines, idx)

    # Session Failures
    idx = _scan_to_section(lines, idx, "session failures")
    sf_mapping = {
        "bring-up failures": "bring_up_failures",
        "reauthentication failures": "reauthentication_failures",
        "duplicate auth-mgr handle": "duplicate_auth_mgr_handle",
    }
    values, idx = _parse_counter_section(lines, idx, sf_mapping, ["sak failures"])
    session_failures = SessionFailures(
        bring_up_failures=values.get("bring_up_failures", 0),
        reauthentication_failures=values.get("reauthentication_failures", 0),
        duplicate_auth_mgr_handle=values.get("duplicate_auth_mgr_handle", 0),
    )

    # SAK Failures
    idx = _scan_to_section(lines, idx, "sak failures")
    sak_mapping = {
        "sak generation": "sak_generation",
        "hash key generation": "hash_key_generation",
        "sak encryption/wrap": "sak_encryption_wrap",
        "sak decryption/unwrap": "sak_decryption_unwrap",
        "sak cipher mismatch": "sak_cipher_mismatch",
    }
    values, idx = _parse_counter_section(lines, idx, sak_mapping, ["ppk failures"])
    sak_failures = SakFailures(
        sak_generation=values.get("sak_generation", 0),
        hash_key_generation=values.get("hash_key_generation", 0),
        sak_encryption_wrap=values.get("sak_encryption_wrap", 0),
        sak_decryption_unwrap=values.get("sak_decryption_unwrap", 0),
        sak_cipher_mismatch=values.get("sak_cipher_mismatch", 0),
    )

    # PPK Failures
    idx = _scan_to_section(lines, idx, "ppk failures")
    ppk_mapping = {
        "ppk id nak": "ppk_id_nak",
        "ppk id expired": "ppk_id_expired",
        "ppk id null received": "ppk_id_null_received",
        "ppk id mismatched": "ppk_id_mismatched",
        "ppk request timeout": "ppk_request_timeout",
        "ppk tuple failure": "ppk_tuple_failure",
        "ppk retrieval failure": "ppk_retrieval_failure",
        "ppk retry failure": "ppk_retry_failure",
        "ppk tid mismatch": "ppk_tid_mismatch",
        "ppk identity not found": "ppk_identity_not_found",
        "ppk hash key generation": "ppk_hash_key_generation",
        "ppk id encryption/wrap": "ppk_id_encryption_wrap",
        "ppk id decryption/unwrap": "ppk_id_decryption_unwrap",
        "ppk aipc conn down fail": "ppk_aipc_conn_down_fail",
    }
    values, idx = _parse_counter_section(lines, idx, ppk_mapping, ["ca failures"])
    ppk_failures = PpkFailures(
        ppk_id_nak=values.get("ppk_id_nak", 0),
        ppk_id_expired=values.get("ppk_id_expired", 0),
        ppk_id_null_received=values.get("ppk_id_null_received", 0),
        ppk_id_mismatched=values.get("ppk_id_mismatched", 0),
        ppk_request_timeout=values.get("ppk_request_timeout", 0),
        ppk_tuple_failure=values.get("ppk_tuple_failure", 0),
        ppk_retrieval_failure=values.get("ppk_retrieval_failure", 0),
        ppk_retry_failure=values.get("ppk_retry_failure", 0),
        ppk_tid_mismatch=values.get("ppk_tid_mismatch", 0),
        ppk_identity_not_found=values.get("ppk_identity_not_found", 0),
        ppk_hash_key_generation=values.get("ppk_hash_key_generation", 0),
        ppk_id_encryption_wrap=values.get("ppk_id_encryption_wrap", 0),
        ppk_id_decryption_unwrap=values.get("ppk_id_decryption_unwrap", 0),
        ppk_aipc_conn_down_fail=values.get("ppk_aipc_conn_down_fail", 0),
    )

    # CA Failures
    idx = _scan_to_section(lines, idx, "ca failures")
    ca_mapping = {
        "group cak generation": "group_cak_generation",
        "group cak encryption/wrap": "group_cak_encryption_wrap",
        "group cak decryption/unwrap": "group_cak_decryption_unwrap",
        "pairwise cak derivation": "pairwise_cak_derivation",
        "ckn derivation": "ckn_derivation",
        "ick derivation": "ick_derivation",
        "kek derivation": "kek_derivation",
        "invalid peer macsec capability": "invalid_peer_macsec_capability",
    }
    values, idx = _parse_counter_section(lines, idx, ca_mapping, ["macsec failures"])
    ca_failures = CaFailures(
        group_cak_generation=values.get("group_cak_generation", 0),
        group_cak_encryption_wrap=values.get("group_cak_encryption_wrap", 0),
        group_cak_decryption_unwrap=values.get("group_cak_decryption_unwrap", 0),
        pairwise_cak_derivation=values.get("pairwise_cak_derivation", 0),
        ckn_derivation=values.get("ckn_derivation", 0),
        ick_derivation=values.get("ick_derivation", 0),
        kek_derivation=values.get("kek_derivation", 0),
        invalid_peer_macsec_capability=values.get("invalid_peer_macsec_capability", 0),
    )

    # MACsec Failures
    idx = _scan_to_section(lines, idx, "macsec failures")
    macsec_mapping = {
        "rx sc creation": "rx_sc_creation",
        "tx sc creation": "tx_sc_creation",
        "rx sa installation": "rx_sa_installation",
        "tx sa installation": "tx_sa_installation",
    }
    values, idx = _parse_counter_section(lines, idx, macsec_mapping, ["mkpdu failures"])
    macsec_failures = MacsecFailures(
        rx_sc_creation=values.get("rx_sc_creation", 0),
        tx_sc_creation=values.get("tx_sc_creation", 0),
        rx_sa_installation=values.get("rx_sa_installation", 0),
        tx_sa_installation=values.get("tx_sa_installation", 0),
    )

    # MKPDU Failures
    idx = _scan_to_section(lines, idx, "mkpdu failures")
    mkpdu_mapping = {
        "mkpdu tx": "mkpdu_tx",
        "mkpdu rx icv validation": "mkpdu_rx_icv_validation",
        "mkpdu rx packet validation": "mkpdu_rx_packet_validation",
        "mkpdu rx bad peer mn": "mkpdu_rx_bad_peer_mn",
        "mkpdu rx non-recent peerlist mn": ("mkpdu_rx_non_recent_peerlist_mn"),
        "mkpdu rx drop sakuse, kn mismatch": ("mkpdu_rx_drop_sakuse_kn_mismatch"),
        "mkpdu rx drop sakuse, rx not set": ("mkpdu_rx_drop_sakuse_rx_not_set"),
        "mkpdu rx drop sakuse, key mi mismatch": (
            "mkpdu_rx_drop_sakuse_key_mi_mismatch"
        ),
        "mkpdu rx drop sakuse, an not in use": ("mkpdu_rx_drop_sakuse_an_not_in_use"),
        "mkpdu rx drop sakuse, ks rx/tx not set": (
            "mkpdu_rx_drop_sakuse_ks_rx_tx_not_set"
        ),
    }
    values, idx = _parse_counter_section(lines, idx, mkpdu_mapping, ["iox global"])
    mkpdu_failures = MkpduFailures(
        mkpdu_tx=values.get("mkpdu_tx", 0),
        mkpdu_rx_icv_validation=values.get("mkpdu_rx_icv_validation", 0),
        mkpdu_rx_packet_validation=values.get("mkpdu_rx_packet_validation", 0),
        mkpdu_rx_bad_peer_mn=values.get("mkpdu_rx_bad_peer_mn", 0),
        mkpdu_rx_non_recent_peerlist_mn=values.get(
            "mkpdu_rx_non_recent_peerlist_mn", 0
        ),
        mkpdu_rx_drop_sakuse_kn_mismatch=values.get(
            "mkpdu_rx_drop_sakuse_kn_mismatch", 0
        ),
        mkpdu_rx_drop_sakuse_rx_not_set=values.get(
            "mkpdu_rx_drop_sakuse_rx_not_set", 0
        ),
        mkpdu_rx_drop_sakuse_key_mi_mismatch=values.get(
            "mkpdu_rx_drop_sakuse_key_mi_mismatch", 0
        ),
        mkpdu_rx_drop_sakuse_an_not_in_use=values.get(
            "mkpdu_rx_drop_sakuse_an_not_in_use", 0
        ),
        mkpdu_rx_drop_sakuse_ks_rx_tx_not_set=values.get(
            "mkpdu_rx_drop_sakuse_ks_rx_tx_not_set", 0
        ),
    )

    return (
        MkaErrorCounters(
            session_failures=session_failures,
            sak_failures=sak_failures,
            ppk_failures=ppk_failures,
            ca_failures=ca_failures,
            macsec_failures=macsec_failures,
            mkpdu_failures=mkpdu_failures,
        ),
        idx,
    )


def _build_iox_statistics(lines: list[str], idx: int) -> IoxGlobalStatistics:
    """Parse the IOX Global Statistics block."""
    iox_mapping = {
        "mkpdus rx idb not found": "mkpdus_rx_idb_not_found",
        "mkpdus rx invalid ckn": "mkpdus_rx_invalid_ckn",
        "mkpdus tx invalid idb": "mkpdus_tx_invalid_idb",
        "mkpdus tx pkt build fail": "mkpdus_tx_pkt_build_fail",
    }
    values, _ = _parse_counter_section(lines, idx, iox_mapping, [])
    return IoxGlobalStatistics(
        mkpdus_rx_idb_not_found=values.get("mkpdus_rx_idb_not_found", 0),
        mkpdus_rx_invalid_ckn=values.get("mkpdus_rx_invalid_ckn", 0),
        mkpdus_tx_invalid_idb=values.get("mkpdus_tx_invalid_idb", 0),
        mkpdus_tx_pkt_build_fail=values.get("mkpdus_tx_pkt_build_fail", 0),
    )


@register(
    OS.CISCO_IOSXR,
    r"show macsec mka statistics location (?P<location>\S+)",
)
class ShowMacsecMkaStatisticsLocationParser(
    BaseParser["ShowMacsecMkaStatisticsLocationResult"],
):
    """Parser for 'show macsec mka statistics location' on IOS-XR.

    Parses MKA global statistics and error counters for a given
    location, including session totals, CA/SA/MKPDU statistics,
    and detailed error/failure counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MACSEC,
            ParserTag.SECURITY,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowMacsecMkaStatisticsLocationResult":
        """Parse 'show macsec mka statistics location' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MKA statistics grouped into global statistics
            and error counters.

        Raises:
            ValueError: If no MKA statistics found in output.
        """
        lines = output.splitlines()
        idx = 0

        # Locate MKA Global Statistics header
        idx = _scan_to_section(lines, idx, "mka global statistics")
        if idx >= len(lines):
            msg = "No MKA global statistics found in output"
            raise ValueError(msg)
        idx = _skip_separators(lines, idx)

        # Parse global statistics block
        global_stats, idx = _build_global_statistics(lines, idx)

        # Parse error counters block
        idx = _scan_to_section(lines, idx, "mka error counter")
        error_counters, idx = _build_error_counters(lines, idx)

        # Parse IOX global statistics block
        idx = _scan_to_section(lines, idx, "iox global")
        iox_stats = _build_iox_statistics(lines, idx)

        return ShowMacsecMkaStatisticsLocationResult(
            mka_global_statistics=global_stats,
            mka_error_counters=error_counters,
            iox_global_statistics=iox_stats,
        )
