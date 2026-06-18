"""Parser for 'show crypto ikev2 stats' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag

# --- Resource / SA limits ---
_SYSTEM_RESOURCE_LIMIT_RE = re.compile(r"System Resource Limit:\s*(?P<val>\d+)")
_MAX_IKEV2_SAS_RE = re.compile(r"Max IKEv2 SAs:\s*(?P<val>\d+)")
_MAX_IN_NEGO_RE = re.compile(r"Max in nego\(in/out\):\s*(?P<in>\d+)/(?P<out>\d+)")

# --- SA counts (incoming / outgoing) ---
_INCOMING_SA_RE = re.compile(
    r"Total incoming IKEv2 SA Count:\s*(?P<total>\d+)\s+"
    r"active:\s*(?P<active>\d+)\s+"
    r"negotiating:\s*(?P<negotiating>\d+)"
)
_OUTGOING_SA_RE = re.compile(
    r"Total outgoing IKEv2 SA Count:\s*(?P<total>\d+)\s+"
    r"active:\s*(?P<active>\d+)\s+"
    r"negotiating:\s*(?P<negotiating>\d+)"
)

# --- Request counters ---
_INCOMING_REQUESTS_RE = re.compile(
    r"Incoming IKEv2 Requests:\s*(?P<total>\d+)\s+"
    r"accepted:\s*(?P<accepted>\d+)\s+"
    r"rejected:\s*(?P<rejected>\d+)"
)
_OUTGOING_REQUESTS_RE = re.compile(
    r"Outgoing IKEv2 Requests:\s*(?P<total>\d+)\s+"
    r"accepted:\s*(?P<accepted>\d+)\s+"
    r"rejected:\s*(?P<rejected>\d+)"
)
_REJECTED_REQUESTS_RE = re.compile(
    r"Rejected IKEv2 Requests:\s*(?P<total>\d+)\s+"
    r"rsrc low:\s*(?P<rsrc_low>\d+)\s+"
    r"SA limit:\s*(?P<sa_limit>\d+)"
)

# --- Drop / dispatch counters ---
_DISPATCH_DROP_RE = re.compile(r"IKEv2 packets dropped at dispatch:\s*(?P<val>\d+)")
_LOW_Q_DROP_RE = re.compile(
    r"Incoming Requests dropped as LOW Q limit reached\s*:\s*(?P<val>\d+)"
)

# --- Cookie challenge ---
_COOKIE_CHALLENGED_RE = re.compile(
    r"Incoming IKEV2 Cookie Challenged Requests:\s*(?P<total>\d+)"
)
_COOKIE_DETAIL_RE = re.compile(
    r"^\s*accepted:\s*(?P<accepted>\d+)\s+"
    r"rejected:\s*(?P<rejected>\d+)\s+"
    r"rejected no cookie:\s*(?P<rejected_no_cookie>\d+)",
    re.MULTILINE,
)

# --- Miscellaneous counters ---
_CERT_REVOKED_RE = re.compile(
    r"Total Deleted sessions of Cert Revoked Peers:\s*(?P<val>\d+)"
)
_INIT_SA_QUEUE_RE = re.compile(
    r"Total init sa request rejected due to queue limit\s*:\s*(?P<val>\d+)"
)
_SA_STRENGTH_RE = re.compile(
    r"SA Strength Enforcement Rejects\s*-\s*"
    r"incoming:\s*(?P<incoming>\d+)\s+"
    r"outgoing:\s*(?P<outgoing>\d+)"
)
_QUANTUM_RE = re.compile(
    r"Sessions with Quantum Resistance:\s*(?P<total>\d+)\s+"
    r"Manual:\s*(?P<manual>\d+)\s+"
    r"Dynamic:\s*(?P<dynamic>\d+)"
)
_PPK_IDENTITY_RE = re.compile(r"PPK Identity Mismatch:\s*(?P<val>\d+)")
_PPK_RETRIEVE_RE = re.compile(
    r"PPK Retrieve Failure\s*-\s*ALL:\s*(?P<all>\d+)\s+"
    r"With PPK Required:\s*(?P<with_ppk_required>\d+)"
)
_PPK_AUTH_RE = re.compile(
    r"PPK Authentication Failure\s*-\s*ALL:\s*(?P<all>\d+)\s+"
    r"With PPK Required:\s*(?P<with_ppk_required>\d+)"
)


class SaCountEntry(TypedDict):
    """IKEv2 SA count entry (incoming or outgoing)."""

    total: int
    active: int
    negotiating: int


class RequestEntry(TypedDict):
    """IKEv2 request entry (incoming or outgoing)."""

    total: int
    accepted: int
    rejected: int


class RejectedRequestEntry(TypedDict):
    """Rejected IKEv2 request breakdown."""

    total: int
    rsrc_low: int
    sa_limit: int


class CookieChallengedEntry(TypedDict):
    """Cookie-challenged request counters."""

    total: int
    accepted: int
    rejected: int
    rejected_no_cookie: int


class SaStrengthEntry(TypedDict):
    """SA strength enforcement reject counters."""

    incoming: int
    outgoing: int


class QuantumResistanceEntry(TypedDict):
    """Quantum resistance session counters."""

    total: int
    manual: int
    dynamic: int


class PpkFailureEntry(TypedDict):
    """PPK failure counters."""

    all: int
    with_ppk_required: int


class ShowCryptoIkev2StatsResult(TypedDict):
    """Schema for 'show crypto ikev2 stats' parsed output."""

    system_resource_limit: int
    max_ikev2_sas: int
    max_in_negotiation_incoming: int
    max_in_negotiation_outgoing: int
    incoming_sa: SaCountEntry
    outgoing_sa: SaCountEntry
    incoming_requests: RequestEntry
    outgoing_requests: RequestEntry
    rejected_requests: RejectedRequestEntry
    packets_dropped_at_dispatch: int
    incoming_requests_dropped_low_q: int
    cookie_challenged: CookieChallengedEntry
    deleted_sessions_cert_revoked: int
    init_sa_rejected_queue_limit: int
    sa_strength_enforcement_rejects: SaStrengthEntry
    quantum_resistance: NotRequired[QuantumResistanceEntry]
    ppk_identity_mismatch: NotRequired[int]
    ppk_retrieve_failure: NotRequired[PpkFailureEntry]
    ppk_authentication_failure: NotRequired[PpkFailureEntry]


@register(OS.CISCO_IOSXE, "show crypto ikev2 stats")
class ShowCryptoIkev2StatsParser(BaseParser[ShowCryptoIkev2StatsResult]):
    """Parser for 'show crypto ikev2 stats' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoIkev2StatsResult:
        """Parse 'show crypto ikev2 stats' output into structured data.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed IKEv2 statistics with SA counts, request counters,
            and various security metrics.

        Raises:
            ValueError: If required counter sections are missing.
        """
        # Join continuation lines: lines wrapped due to terminal width
        # are recognized because they start with whitespace but do not
        # match any known construct pattern.
        joined = _join_continuation_lines(output)
        result: dict[str, object] = {}

        _parse_limits(joined, result)
        _parse_sa_counts(joined, result)
        _parse_requests(joined, result)
        _parse_drops(joined, result)
        _parse_cookie_challenged(joined, result)
        _parse_misc_counters(joined, result)

        # Validate required fields
        required_fields = (
            "system_resource_limit",
            "max_ikev2_sas",
            "max_in_negotiation_incoming",
            "max_in_negotiation_outgoing",
            "incoming_sa",
            "outgoing_sa",
            "incoming_requests",
            "outgoing_requests",
            "rejected_requests",
            "packets_dropped_at_dispatch",
            "incoming_requests_dropped_low_q",
            "cookie_challenged",
            "deleted_sessions_cert_revoked",
            "init_sa_rejected_queue_limit",
            "sa_strength_enforcement_rejects",
        )
        for field in required_fields:
            if field not in result:
                msg = f"Missing required field: {field}"
                raise ValueError(msg)

        return cast(ShowCryptoIkev2StatsResult, result)


def _join_continuation_lines(output: str) -> str:
    """Join lines that were wrapped due to terminal width.

    Continuation lines start with whitespace and do not match any
    known section pattern (separator, label: value, etc.).
    """
    lines = output.splitlines()
    joined_lines: list[str] = []
    for line in lines:
        if SEPARATOR_DASH_SPACE_RE.match(line):
            joined_lines.append(line)
            continue
        # A continuation line starts with whitespace but is not
        # a separator and not a standalone indented label line
        if (
            joined_lines
            and line
            and line[0] == " "
            and not line.lstrip().startswith(("accepted:", "rejected:"))
            and ":" not in line.split()[0]
            if line.split()
            else False
        ):
            joined_lines[-1] = joined_lines[-1] + " " + line.strip()
        else:
            joined_lines.append(line)
    return "\n".join(joined_lines)


def _parse_limits(text: str, result: dict[str, object]) -> None:
    """Extract system resource limits and max SA counts."""
    m = _SYSTEM_RESOURCE_LIMIT_RE.search(text)
    if m:
        result["system_resource_limit"] = int(m.group("val"))

    m = _MAX_IKEV2_SAS_RE.search(text)
    if m:
        result["max_ikev2_sas"] = int(m.group("val"))

    m = _MAX_IN_NEGO_RE.search(text)
    if m:
        result["max_in_negotiation_incoming"] = int(m.group("in"))
        result["max_in_negotiation_outgoing"] = int(m.group("out"))


def _parse_sa_counts(text: str, result: dict[str, object]) -> None:
    """Extract incoming/outgoing SA totals."""
    m = _INCOMING_SA_RE.search(text)
    if m:
        result["incoming_sa"] = {
            "total": int(m.group("total")),
            "active": int(m.group("active")),
            "negotiating": int(m.group("negotiating")),
        }

    m = _OUTGOING_SA_RE.search(text)
    if m:
        result["outgoing_sa"] = {
            "total": int(m.group("total")),
            "active": int(m.group("active")),
            "negotiating": int(m.group("negotiating")),
        }


def _parse_requests(text: str, result: dict[str, object]) -> None:
    """Extract request counters."""
    m = _INCOMING_REQUESTS_RE.search(text)
    if m:
        result["incoming_requests"] = {
            "total": int(m.group("total")),
            "accepted": int(m.group("accepted")),
            "rejected": int(m.group("rejected")),
        }

    m = _OUTGOING_REQUESTS_RE.search(text)
    if m:
        result["outgoing_requests"] = {
            "total": int(m.group("total")),
            "accepted": int(m.group("accepted")),
            "rejected": int(m.group("rejected")),
        }

    m = _REJECTED_REQUESTS_RE.search(text)
    if m:
        result["rejected_requests"] = {
            "total": int(m.group("total")),
            "rsrc_low": int(m.group("rsrc_low")),
            "sa_limit": int(m.group("sa_limit")),
        }


def _parse_drops(text: str, result: dict[str, object]) -> None:
    """Extract packet drop counters."""
    m = _DISPATCH_DROP_RE.search(text)
    if m:
        result["packets_dropped_at_dispatch"] = int(m.group("val"))

    m = _LOW_Q_DROP_RE.search(text)
    if m:
        result["incoming_requests_dropped_low_q"] = int(m.group("val"))


def _parse_cookie_challenged(text: str, result: dict[str, object]) -> None:
    """Extract cookie-challenged request counters."""
    m = _COOKIE_CHALLENGED_RE.search(text)
    if not m:
        return
    total = int(m.group("total"))

    # The detail line follows the header
    m2 = _COOKIE_DETAIL_RE.search(text)
    if m2:
        result["cookie_challenged"] = {
            "total": total,
            "accepted": int(m2.group("accepted")),
            "rejected": int(m2.group("rejected")),
            "rejected_no_cookie": int(m2.group("rejected_no_cookie")),
        }


def _parse_misc_counters(text: str, result: dict[str, object]) -> None:
    """Extract miscellaneous counters (cert revoked, queue, PPK, etc.)."""
    m = _CERT_REVOKED_RE.search(text)
    if m:
        result["deleted_sessions_cert_revoked"] = int(m.group("val"))

    m = _INIT_SA_QUEUE_RE.search(text)
    if m:
        result["init_sa_rejected_queue_limit"] = int(m.group("val"))

    m = _SA_STRENGTH_RE.search(text)
    if m:
        result["sa_strength_enforcement_rejects"] = {
            "incoming": int(m.group("incoming")),
            "outgoing": int(m.group("outgoing")),
        }

    m = _QUANTUM_RE.search(text)
    if m:
        result["quantum_resistance"] = {
            "total": int(m.group("total")),
            "manual": int(m.group("manual")),
            "dynamic": int(m.group("dynamic")),
        }

    m = _PPK_IDENTITY_RE.search(text)
    if m:
        result["ppk_identity_mismatch"] = int(m.group("val"))

    m = _PPK_RETRIEVE_RE.search(text)
    if m:
        result["ppk_retrieve_failure"] = {
            "all": int(m.group("all")),
            "with_ppk_required": int(m.group("with_ppk_required")),
        }

    m = _PPK_AUTH_RE.search(text)
    if m:
        result["ppk_authentication_failure"] = {
            "all": int(m.group("all")),
            "with_ppk_required": int(m.group("with_ppk_required")),
        }
