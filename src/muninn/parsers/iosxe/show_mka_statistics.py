"""Parser for 'show mka statistics' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MkaSessionTotals(TypedDict):
    """Schema for the MKA Session Totals block."""

    secured: int
    fallback_secured: int
    reauthentication_attempts: int
    deleted_secured: int
    keepalive_timeouts: int


class MkaCaStatistics(TypedDict):
    """Schema for the CA Statistics block."""

    pairwise_caks_derived: int
    pairwise_cak_rekeys: int
    group_caks_generated: int
    group_caks_received: int


class MkaSaStatistics(TypedDict):
    """Schema for the SA Statistics block.

    ``sak_rekeyed_as_kn_mismatch`` is emitted on some IOS-XE images and is
    omitted on platforms that do not report it.
    """

    saks_generated: int
    saks_rekeyed: int
    saks_received: int
    sak_responses_received: int
    sak_rekeyed_as_kn_mismatch: NotRequired[int]


class MkaDistributedCounters(TypedDict):
    """Schema for distributed SAK/CAK MKPDU counters."""

    distributed_sak: int
    distributed_cak: int


class MkaMkpduStatistics(TypedDict):
    """Schema for the MKPDU Statistics block."""

    mkpdus_validated_and_received: int
    mkpdus_validated_and_received_breakdown: MkaDistributedCounters
    mkpdus_transmitted: int
    mkpdus_transmitted_breakdown: MkaDistributedCounters


class MkaSessionFailures(TypedDict):
    """Schema for the Session Failures error block."""

    bring_up_failures: int
    reauthentication_failures: int
    duplicate_auth_mgr_handle: int


class MkaSakFailures(TypedDict):
    """Schema for the SAK Failures error block."""

    sak_generation: int
    hash_key_generation: int
    sak_encryption_wrap: int
    sak_decryption_unwrap: int
    sak_cipher_mismatch: int


class MkaCaFailures(TypedDict):
    """Schema for the CA Failures error block."""

    group_cak_generation: int
    group_cak_encryption_wrap: int
    group_cak_decryption_unwrap: int
    pairwise_cak_derivation: int
    ckn_derivation: int
    ick_derivation: int
    kek_derivation: int
    invalid_peer_macsec_capability: int


class MkaMacsecFailures(TypedDict):
    """Schema for the MACsec Failures error block."""

    rx_sc_creation: int
    tx_sc_creation: int
    rx_sa_installation: int
    tx_sa_installation: int


class MkaMkpduFailures(TypedDict):
    """Schema for the MKPDU Failures error block."""

    mkpdu_tx: int
    mkpdu_rx_icv_verification: int
    mkpdu_rx_fallback_icv_verification: int
    mkpdu_rx_validation: int
    mkpdu_rx_bad_peer_mn: int
    mkpdu_rx_non_recent_peerlist_mn: int


class MkaSakUseFailures(TypedDict):
    """Schema for the SAK USE Failures error block.

    This block is not present on every IOS-XE image.
    """

    sak_use_latest_kn_mismatch: int
    sak_use_latest_an_not_in_use: int


class MkaErrorCounterTotals(TypedDict):
    """Schema for the MKA Error Counter Totals section."""

    session_failures: MkaSessionFailures
    sak_failures: MkaSakFailures
    ca_failures: MkaCaFailures
    macsec_failures: MkaMacsecFailures
    mkpdu_failures: MkaMkpduFailures
    sak_use_failures: NotRequired[MkaSakUseFailures]


class ShowMkaStatisticsResult(TypedDict):
    """Schema for 'show mka statistics' parsed output."""

    mka_session_totals: MkaSessionTotals
    ca_statistics: MkaCaStatistics
    sa_statistics: MkaSaStatistics
    mkpdu_statistics: MkaMkpduStatistics
    mka_error_counter_totals: MkaErrorCounterTotals


# Section headers (each may end with optional trailing whitespace; ``=====``
# underline rows are simply ignored as non-matching lines).
_SEC_SESSION_TOTALS = re.compile(r"^MKA\s+Session\s+Totals$", re.I)
_SEC_CA_STATS = re.compile(r"^CA\s+Statistics$", re.I)
_SEC_SA_STATS = re.compile(r"^SA\s+Statistics$", re.I)
_SEC_MKPDU_STATS = re.compile(r"^MKPDU\s+Statistics$", re.I)
_SEC_SESSION_FAIL = re.compile(r"^Session\s+Failures$", re.I)
_SEC_SAK_FAIL = re.compile(r"^SAK\s+Failures$", re.I)
_SEC_CA_FAIL = re.compile(r"^CA\s+Failures$", re.I)
_SEC_MACSEC_FAIL = re.compile(r"^MACsec\s+Failures$", re.I)
_SEC_MKPDU_FAIL = re.compile(r"^MKPDU\s+Failures$", re.I)
_SEC_SAK_USE_FAIL = re.compile(r"^SAK\s+USE\s+Failures$", re.I)

# Dotted-leader counter rows: ``Label.... 12`` and quoted breakdown rows
# ``"Distributed SAK"..... 1``.
_KV_RE = re.compile(r"^(?P<label>.+?)\.{2,}\s*(?P<value>\d+)\s*$")
_BREAKDOWN_RE = re.compile(
    r'^"(?P<label>Distributed\s+(?:SAK|CAK))"\.{2,}\s*(?P<value>\d+)\s*$',
    re.I,
)


# Label -> canonical key mappings for each section. Using exact dotted-label
# matches keeps the parser robust against unknown fields and lets the schema
# stay strict.
_SESSION_TOTALS_MAP = {
    "secured": "secured",
    "fallback secured": "fallback_secured",
    "reauthentication attempts": "reauthentication_attempts",
    "deleted (secured)": "deleted_secured",
    "keepalive timeouts": "keepalive_timeouts",
}
_CA_STATS_MAP = {
    "pairwise caks derived": "pairwise_caks_derived",
    "pairwise cak rekeys": "pairwise_cak_rekeys",
    "group caks generated": "group_caks_generated",
    "group caks received": "group_caks_received",
}
_SA_STATS_MAP = {
    "saks generated": "saks_generated",
    "saks rekeyed": "saks_rekeyed",
    "saks received": "saks_received",
    "sak responses received": "sak_responses_received",
    "sak rekeyed as kn mismatch": "sak_rekeyed_as_kn_mismatch",
}
_SESSION_FAIL_MAP = {
    "bring-up failures": "bring_up_failures",
    "reauthentication failures": "reauthentication_failures",
    "duplicate auth-mgr handle": "duplicate_auth_mgr_handle",
}
_SAK_FAIL_MAP = {
    "sak generation": "sak_generation",
    "hash key generation": "hash_key_generation",
    "sak encryption/wrap": "sak_encryption_wrap",
    "sak decryption/unwrap": "sak_decryption_unwrap",
    "sak cipher mismatch": "sak_cipher_mismatch",
}
_CA_FAIL_MAP = {
    "group cak generation": "group_cak_generation",
    "group cak encryption/wrap": "group_cak_encryption_wrap",
    "group cak decryption/unwrap": "group_cak_decryption_unwrap",
    "pairwise cak derivation": "pairwise_cak_derivation",
    "ckn derivation": "ckn_derivation",
    "ick derivation": "ick_derivation",
    "kek derivation": "kek_derivation",
    "invalid peer macsec capability": "invalid_peer_macsec_capability",
}
_MACSEC_FAIL_MAP = {
    "rx sc creation": "rx_sc_creation",
    "tx sc creation": "tx_sc_creation",
    "rx sa installation": "rx_sa_installation",
    "tx sa installation": "tx_sa_installation",
}
_MKPDU_FAIL_MAP = {
    "mkpdu tx": "mkpdu_tx",
    "mkpdu rx icv verification": "mkpdu_rx_icv_verification",
    "mkpdu rx fallback icv verification": "mkpdu_rx_fallback_icv_verification",
    "mkpdu rx validation": "mkpdu_rx_validation",
    "mkpdu rx bad peer mn": "mkpdu_rx_bad_peer_mn",
    "mkpdu rx non-recent peerlist mn": "mkpdu_rx_non_recent_peerlist_mn",
}
_SAK_USE_FAIL_MAP = {
    "sak use latest kn mismatch": "sak_use_latest_kn_mismatch",
    "sak use latest an not in use": "sak_use_latest_an_not_in_use",
}

# Labels in the MKPDU Statistics block whose values are written without a
# quoted breakdown row. These represent the "total" numbers in that section.
_MKPDU_TOTALS_MAP = {
    "mkpdus validated & rx": "mkpdus_validated_and_received",
    "mkpdus transmitted": "mkpdus_transmitted",
}


class _Acc:
    """Accumulator that walks the output line-by-line tracking section state."""

    __slots__ = ("section", "mkpdu_target", "data")

    def __init__(self) -> None:
        self.section: str | None = None
        # Which MKPDU bucket the next "Distributed SAK/CAK" breakdown row goes
        # into: either ``mkpdus_validated_and_received_breakdown`` or
        # ``mkpdus_transmitted_breakdown``.
        self.mkpdu_target: str | None = None
        self.data: dict[str, dict[str, int | dict[str, int]]] = {}

    def feed(self, raw: str) -> None:
        line = raw.strip()
        if not line:
            return
        if self._maybe_switch_section(line):
            return
        if self._maybe_breakdown(line):
            return
        m = _KV_RE.match(line)
        if not m:
            return
        label = m.group("label").strip().lower()
        value = int(m.group("value"))
        self._record(label, value)

    def _maybe_switch_section(self, line: str) -> bool:
        for section, pattern in _SECTION_HEADERS:
            if pattern.match(line):
                self.section = section
                self.mkpdu_target = None
                return True
        return False

    def _maybe_breakdown(self, line: str) -> bool:
        if self.section != "mkpdu_statistics":
            return False
        m = _BREAKDOWN_RE.match(line)
        if not m:
            return False
        if self.mkpdu_target is None:
            # Stray breakdown row before any totals row; ignore.
            return True
        label = m.group("label").lower()
        key = "distributed_sak" if "sak" in label else "distributed_cak"
        section = self.data.setdefault("mkpdu_statistics", {})
        bucket = section.setdefault(self.mkpdu_target, {})
        if isinstance(bucket, dict):
            bucket[key] = int(m.group("value"))
        return True

    def _record(self, label: str, value: int) -> None:
        if self.section is None:
            return
        section_map = _SECTION_FIELD_MAPS.get(self.section)
        if section_map is None:
            return
        if self.section == "mkpdu_statistics":
            totals_key = _MKPDU_TOTALS_MAP.get(label)
            if totals_key is not None:
                section = self.data.setdefault("mkpdu_statistics", {})
                section[totals_key] = value
                # The next breakdown rows belong with this total.
                self.mkpdu_target = (
                    "mkpdus_validated_and_received_breakdown"
                    if totals_key == "mkpdus_validated_and_received"
                    else "mkpdus_transmitted_breakdown"
                )
            return
        key = section_map.get(label)
        if key is None:
            return
        bucket = self.data.setdefault(self.section, {})
        bucket[key] = value

    def result(self) -> ShowMkaStatisticsResult:
        if not self.data:
            msg = "No MKA statistics parsed from input"
            raise ValueError(msg)
        return _build_result(self.data)


_SECTION_HEADERS: list[tuple[str, re.Pattern[str]]] = [
    ("mka_session_totals", _SEC_SESSION_TOTALS),
    ("ca_statistics", _SEC_CA_STATS),
    ("sa_statistics", _SEC_SA_STATS),
    ("mkpdu_statistics", _SEC_MKPDU_STATS),
    ("session_failures", _SEC_SESSION_FAIL),
    ("sak_failures", _SEC_SAK_FAIL),
    ("ca_failures", _SEC_CA_FAIL),
    ("macsec_failures", _SEC_MACSEC_FAIL),
    ("mkpdu_failures", _SEC_MKPDU_FAIL),
    ("sak_use_failures", _SEC_SAK_USE_FAIL),
]


_SECTION_FIELD_MAPS: dict[str, dict[str, str]] = {
    "mka_session_totals": _SESSION_TOTALS_MAP,
    "ca_statistics": _CA_STATS_MAP,
    "sa_statistics": _SA_STATS_MAP,
    # ``mkpdu_statistics`` is handled specially in ``_record``.
    "mkpdu_statistics": {},
    "session_failures": _SESSION_FAIL_MAP,
    "sak_failures": _SAK_FAIL_MAP,
    "ca_failures": _CA_FAIL_MAP,
    "macsec_failures": _MACSEC_FAIL_MAP,
    "mkpdu_failures": _MKPDU_FAIL_MAP,
    "sak_use_failures": _SAK_USE_FAIL_MAP,
}


def _build_result(
    data: dict[str, dict[str, int | dict[str, int]]],
) -> ShowMkaStatisticsResult:
    """Assemble the final TypedDict result from accumulated section data."""
    error_totals: dict[str, dict[str, int]] = {
        "session_failures": _as_int_dict(data.get("session_failures", {})),
        "sak_failures": _as_int_dict(data.get("sak_failures", {})),
        "ca_failures": _as_int_dict(data.get("ca_failures", {})),
        "macsec_failures": _as_int_dict(data.get("macsec_failures", {})),
        "mkpdu_failures": _as_int_dict(data.get("mkpdu_failures", {})),
    }
    if "sak_use_failures" in data:
        error_totals["sak_use_failures"] = _as_int_dict(data["sak_use_failures"])

    return ShowMkaStatisticsResult(
        mka_session_totals=cast(
            MkaSessionTotals, _as_int_dict(data.get("mka_session_totals", {}))
        ),
        ca_statistics=cast(
            MkaCaStatistics, _as_int_dict(data.get("ca_statistics", {}))
        ),
        sa_statistics=cast(
            MkaSaStatistics, _as_int_dict(data.get("sa_statistics", {}))
        ),
        mkpdu_statistics=_build_mkpdu_section(data.get("mkpdu_statistics", {})),
        mka_error_counter_totals=cast(MkaErrorCounterTotals, error_totals),
    )


def _as_int_dict(section: dict[str, int | dict[str, int]]) -> dict[str, int]:
    """Return a flat int dict, skipping any nested sub-dicts."""
    return {k: v for k, v in section.items() if isinstance(v, int)}


def _breakdown(value: object) -> MkaDistributedCounters:
    """Build a distributed SAK/CAK counter dict, defaulting missing keys to 0."""
    if not isinstance(value, dict):
        return {"distributed_sak": 0, "distributed_cak": 0}
    typed = cast(dict[str, int], value)
    return {
        "distributed_sak": _int(typed.get("distributed_sak")),
        "distributed_cak": _int(typed.get("distributed_cak")),
    }


def _build_mkpdu_section(
    section: dict[str, int | dict[str, int]],
) -> MkaMkpduStatistics:
    """Build the MKPDU statistics block with empty breakdowns when missing."""
    return {
        "mkpdus_validated_and_received": _int(
            section.get("mkpdus_validated_and_received")
        ),
        "mkpdus_validated_and_received_breakdown": _breakdown(
            section.get("mkpdus_validated_and_received_breakdown")
        ),
        "mkpdus_transmitted": _int(section.get("mkpdus_transmitted")),
        "mkpdus_transmitted_breakdown": _breakdown(
            section.get("mkpdus_transmitted_breakdown")
        ),
    }


def _int(value: object) -> int:
    """Return ``value`` as int, defaulting to 0 when missing."""
    return value if isinstance(value, int) else 0


@register(OS.CISCO_IOSXE, "show mka statistics")
class ShowMkaStatisticsParser(BaseParser[ShowMkaStatisticsResult]):
    """Parser for 'show mka statistics' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MACSEC})

    @classmethod
    def parse(cls, output: str) -> ShowMkaStatisticsResult:
        """Parse 'show mka statistics' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MKA global and error statistics.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        acc = _Acc()
        for line in output.splitlines():
            acc.feed(line)
        return acc.result()
