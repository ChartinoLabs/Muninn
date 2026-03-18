"""Parser for 'show platform sudi pki' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register


class SudiIssuerEntry(TypedDict):
    """Schema for a single SUDI issuer."""

    validation_status: str


class ShowPlatformSudiPkiResult(TypedDict):
    """Schema for 'show platform sudi pki' parsed output.

    Keyed by SUDI Issuer-CN name.
    """

    certificate_status: NotRequired[str]
    issuers: dict[str, SudiIssuerEntry]


# 'Cisco Manufacturing CA III' certificate : Enabled
_CERT_STATUS = re.compile(r"^'(?P<name>[^']+)'\s+certificate\s*:\s*(?P<status>\S+)\s*$")

# Table header separator line
_SEPARATOR = SEPARATOR_DASH_RE

# Table header line prefix
_TABLE_HEADER_PREFIX = "SUDI Issuer-CN"

# Table row: issuer CN followed by validation status
# e.g. "Cisco Manufacturing CA              Valid"
# e.g. "Cisco Manufacturing CA III          Not Supported"
_ISSUER_ROW = re.compile(
    r"^(?P<issuer>.+?)\s{2,}(?P<status>Valid|Not Supported|Init Failure|Invalid)\s*$"
)


def _is_skippable(line: str) -> bool:
    """Return True if the line should be skipped during parsing."""
    if not line or _SEPARATOR.match(line) is not None:
        return True
    return line.startswith(_TABLE_HEADER_PREFIX)


def _extract_certificate_status(line: str) -> str | None:
    """Extract certificate status from a line, or return None."""
    match = _CERT_STATUS.match(line)
    return match.group("status") if match else None


def _extract_issuer(line: str) -> tuple[str, SudiIssuerEntry] | None:
    """Extract an issuer entry from a line, or return None."""
    match = _ISSUER_ROW.match(line)
    if not match:
        return None
    return match.group("issuer").strip(), SudiIssuerEntry(
        validation_status=match.group("status"),
    )


@register(OS.CISCO_IOSXE, "show platform sudi pki")
class ShowPlatformSudiPkiParser(BaseParser["ShowPlatformSudiPkiResult"]):
    """Parser for 'show platform sudi pki' command.

    Example output::

        'Cisco Manufacturing CA III' certificate : Enabled

        SUDI Issuer-CN                      Validation status
        -----------------------------------------------------
        Cisco Manufacturing CA              Valid
        Cisco Manufacturing CA III          Valid
        Cisco Manufacturing CA SHA2         Valid
    """

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSudiPkiResult:
        """Parse 'show platform sudi pki' output.

        Args:
            output: Raw CLI output from 'show platform sudi pki'.

        Returns:
            Parsed SUDI PKI data with certificate status and issuers.

        Raises:
            ValueError: If no SUDI PKI data is found.
        """
        issuers: dict[str, SudiIssuerEntry] = {}
        result = ShowPlatformSudiPkiResult(issuers=issuers)

        for line in output.splitlines():
            stripped = line.strip()
            if _is_skippable(stripped):
                continue

            cert_status = _extract_certificate_status(stripped)
            if cert_status:
                result["certificate_status"] = cert_status
                continue

            issuer = _extract_issuer(stripped)
            if issuer:
                issuers[issuer[0]] = issuer[1]

        if not issuers and "certificate_status" not in result:
            msg = "No SUDI PKI data found in output"
            raise ValueError(msg)

        return result
