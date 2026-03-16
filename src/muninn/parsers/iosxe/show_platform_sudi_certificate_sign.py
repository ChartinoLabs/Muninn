"""Parser for 'show platform sudi certificate sign' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# PEM certificate block boundaries
_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_PEM_END = "-----END CERTIFICATE-----"

# Signature version line: "Signature version: 1"
_SIG_VERSION = re.compile(r"^Signature\s+version:\s+(?P<version>\d+)\s*$")

# Signature hex data (one or more lines of hex characters)
_HEX_LINE = re.compile(r"^[0-9A-Fa-f]+$")

# Certificate label order used as dictionary keys
_CERT_LABELS = ("root_ca", "subordinate_ca", "sudi")


class CertificateEntry(TypedDict):
    """Schema for a single PEM certificate."""

    pem: str


class ShowPlatformSudiCertificateSignResult(TypedDict):
    """Schema for 'show platform sudi certificate sign' parsed output.

    Keyed by certificate role in the SUDI chain:
    ``root_ca``, ``subordinate_ca``, ``sudi``.
    """

    certificates: dict[str, CertificateEntry]
    signature_version: NotRequired[int]
    signature: NotRequired[str]


def _extract_certificates(lines: list[str]) -> dict[str, CertificateEntry]:
    """Extract PEM certificates from output lines.

    Certificates are returned keyed by their role in the SUDI chain:
    root_ca (Cisco Root CA 2048), subordinate_ca (ACT2 SUDI CA),
    and sudi (device certificate).
    """
    certificates: dict[str, CertificateEntry] = {}
    cert_index = 0
    in_cert = False
    current_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        if stripped == _PEM_BEGIN:
            in_cert = True
            current_lines = [stripped]
            continue

        if stripped == _PEM_END:
            current_lines.append(stripped)
            if cert_index < len(_CERT_LABELS):
                label = _CERT_LABELS[cert_index]
                pem_text = "\n".join(current_lines)
                certificates[label] = CertificateEntry(pem=pem_text)
                cert_index += 1
            in_cert = False
            current_lines = []
            continue

        if in_cert:
            current_lines.append(stripped)

    return certificates


def _extract_signature(lines: list[str]) -> tuple[int | None, str | None]:
    """Extract signature version and hex signature from output lines.

    Returns:
        Tuple of (signature_version, signature_hex) where either may be None
        if the corresponding data is not present.
    """
    sig_version: int | None = None
    sig_hex_parts: list[str] = []
    reading_sig = False

    for line in lines:
        stripped = line.strip()

        version_match = _SIG_VERSION.match(stripped)
        if version_match:
            sig_version = int(version_match.group("version"))
            continue

        if stripped == "Signature:":
            reading_sig = True
            continue

        if reading_sig:
            if _HEX_LINE.match(stripped):
                sig_hex_parts.append(stripped)
            elif stripped:
                # Non-hex, non-empty line ends signature reading
                reading_sig = False

    signature = "".join(sig_hex_parts) if sig_hex_parts else None
    return sig_version, signature


@register(OS.CISCO_IOSXE, "show platform sudi certificate sign")
class ShowPlatformSudiCertificateSignParser(
    BaseParser["ShowPlatformSudiCertificateSignResult"],
):
    """Parser for 'show platform sudi certificate sign' command.

    Example output::

        -----BEGIN CERTIFICATE-----
        MIIDQzCCAiugAwIBAgIQX/h7KCtU3I1CoxW1aMmt/zANBgkqhkiG9w0BAQUFADA1
        ...
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        ...
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        ...
        -----END CERTIFICATE-----

        Signature version: 1
        Signature:
        1809AF26E52292B71217418F6111DDD50707B516...
    """

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSudiCertificateSignResult:
        """Parse 'show platform sudi certificate sign' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed SUDI certificate sign data with certificates and signature.

        Raises:
            ValueError: If no certificate data is found.
        """
        lines = output.splitlines()
        certificates = _extract_certificates(lines)

        if not certificates:
            msg = "No SUDI certificate data found in output"
            raise ValueError(msg)

        result = ShowPlatformSudiCertificateSignResult(certificates=certificates)

        sig_version, signature = _extract_signature(lines)
        if sig_version is not None:
            result["signature_version"] = sig_version
        if signature is not None:
            result["signature"] = signature

        return result
