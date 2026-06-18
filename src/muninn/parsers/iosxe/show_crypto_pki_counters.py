"""Parser for 'show crypto pki counters' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_COUNTER_RE = re.compile(
    r"^\s*(?P<label>[A-Za-z][A-Za-z \-]+[A-Za-z]):\s*(?P<value>\d+)\s*$"
)

_LABEL_TO_FIELD: dict[str, str] = {
    "PKI Sessions Started": "pki_sessions_started",
    "PKI Sessions Ended": "pki_sessions_ended",
    "PKI Sessions Active": "pki_sessions_active",
    "Successful Validations": "successful_validations",
    "Failed Validations": "failed_validations",
    "Bypassed Validations": "bypassed_validations",
    "Pending Validations": "pending_validations",
    "CRLs checked": "crls_checked",
    "CRL - fetch attempts": "crl_fetch_attempts",
    "CRL - failed attempts": "crl_failed_attempts",
    "CRL - rejected busy fetching": "crl_rejected_busy_fetching",
    "AAA authorizations": "aaa_authorizations",
}


class ShowCryptoPkiCountersResult(TypedDict):
    """Schema for 'show crypto pki counters' parsed output."""

    pki_sessions_started: int
    pki_sessions_ended: int
    pki_sessions_active: int
    successful_validations: int
    failed_validations: int
    bypassed_validations: int
    pending_validations: int
    crls_checked: int
    crl_fetch_attempts: int
    crl_failed_attempts: int
    crl_rejected_busy_fetching: int
    aaa_authorizations: int


@register(OS.CISCO_IOSXE, "show crypto pki counters")
class ShowCryptoPkiCountersParser(BaseParser[ShowCryptoPkiCountersResult]):
    """Parser for 'show crypto pki counters' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiCountersResult:
        """Parse 'show crypto pki counters' output into structured data.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed PKI counters including session, validation, CRL,
            and AAA statistics.

        Raises:
            ValueError: If any of the expected counter lines are missing.
        """
        result: dict[str, int] = {}
        for line in output.splitlines():
            match = _COUNTER_RE.match(line)
            if match is None:
                continue
            label = match.group("label")
            if label in _LABEL_TO_FIELD:
                result[_LABEL_TO_FIELD[label]] = int(match.group("value"))

        for label, field in _LABEL_TO_FIELD.items():
            if field not in result:
                msg = f"Missing required PKI counter: {label}"
                raise ValueError(msg)

        return cast(ShowCryptoPkiCountersResult, result)
