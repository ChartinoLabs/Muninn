"""Parser for 'show crypto pki certificates' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# Type alias for validity parse result
_ValidityResult = tuple["ValidityDate | None", int]


class ValidityDate(TypedDict):
    """Schema for certificate validity dates."""

    start_date: str
    end_date: str


class CertificateEntry(TypedDict):
    """Schema for a single certificate entry."""

    status: str
    serial_number: str
    usage: str
    issuer: dict[str, str]
    subject: dict[str, str]
    validity_date: ValidityDate
    associated_trustpoints: str
    crl_distribution_points: NotRequired[str]
    storage: NotRequired[str]
    subject_name: NotRequired[str]
    fingerprint_md5: NotRequired[str]
    fingerprint_sha1: NotRequired[str]
    key_label: NotRequired[str]
    key_usage: NotRequired[str]


class ShowCryptoPkiCertificatesResult(TypedDict):
    """Schema for 'show crypto pki certificates' parsed output.

    Keyed by trustpoint name, then by certificate type
    (e.g. "CA Certificate", "Certificate").
    """

    trustpoints: dict[str, dict[str, CertificateEntry]]


# --- Regex patterns ---

# Certificate type header (e.g. "CA Certificate", "Certificate",
# "Router Certificate", "RA Certificate")
_CERT_TYPE_RE = re.compile(r"^((?:CA |RA |Router )?Certificate)\s*$")

# Status line
_STATUS_RE = re.compile(r"^\s+Status:\s+(.+?)\s*$")

# Serial number
_SERIAL_RE = re.compile(r"^\s+Certificate Serial Number\s*(?:\(hex\))?\s*:\s*(.+?)\s*$")

# Usage
_USAGE_RE = re.compile(r"^\s+Certificate Usage:\s+(.+?)\s*$")

# Issuer / Subject section header
_SECTION_RE = re.compile(r"^\s+(Issuer|Subject)\s*:\s*$")

# Associated Trustpoints line
_TRUSTPOINT_RE = re.compile(r"^\s+Associated Trustpoints:\s+(.+?)\s*$")

# CRL Distribution Points
_CRL_RE = re.compile(r"^\s+CRL Distribution Points?\s*:\s+(.+?)\s*$")

# Storage
_STORAGE_RE = re.compile(r"^\s+Storage:\s+(.+?)\s*$")

# Key label
_KEY_LABEL_RE = re.compile(r"^\s+Key Label:\s+(.+?)\s*$")

# Key usage
_KEY_USAGE_RE = re.compile(r"^\s+Key Usage:\s+(.+?)\s*$")

# Fingerprint MD5
_FP_MD5_RE = re.compile(r"^\s+Fingerprint MD5:\s+(.+?)\s*$")

# Fingerprint SHA1
_FP_SHA1_RE = re.compile(r"^\s+Fingerprint SHA1:\s+(.+?)\s*$")

# Validity Date section header
_VALIDITY_HEADER_RE = re.compile(r"^\s+Validity Date\s*:\s*$")

# start date / end date
_START_DATE_RE = re.compile(r"^\s+start date:\s+(.+?)\s*$")
_END_DATE_RE = re.compile(r"^\s+end\s+date:\s+(.+?)\s*$")

# Subject Name line (within Subject section)
_SUBJECT_NAME_RE = re.compile(r"^\s+Name:\s+(.+?)\s*$")

# DN attribute line (e.g. "cn=...", "o=...", "ou=...")
_DN_ATTR_RE = re.compile(r"^\s+(\w+)=(.+?)\s*$")

# Simple key-value patterns mapped to entry keys
_SIMPLE_FIELD_PATTERNS = [
    (_STATUS_RE, "status"),
    (_SERIAL_RE, "serial_number"),
    (_USAGE_RE, "usage"),
    (_TRUSTPOINT_RE, "associated_trustpoints"),
    (_CRL_RE, "crl_distribution_points"),
    (_STORAGE_RE, "storage"),
    (_KEY_LABEL_RE, "key_label"),
    (_KEY_USAGE_RE, "key_usage"),
    (_FP_MD5_RE, "fingerprint_md5"),
    (_FP_SHA1_RE, "fingerprint_sha1"),
]


def _split_certificate_blocks(output: str) -> list[list[str]]:
    """Split output into per-certificate blocks.

    Each block starts with a line matching "Certificate",
    "CA Certificate", etc.
    """
    blocks: list[list[str]] = []
    current: list[str] = []

    for line in output.splitlines():
        if _CERT_TYPE_RE.match(line):
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            current.append(line)

    if current:
        blocks.append(current)

    return blocks


def _parse_dn_section(
    lines: list[str],
    start_idx: int,
) -> tuple[dict[str, str], int]:
    """Parse a DN section (Issuer or Subject) after the header.

    Returns:
        Tuple of (dn_dict, next_index) where next_index is the
        first line not consumed by this section.
    """
    dn: dict[str, str] = {}
    idx = start_idx

    while idx < len(lines):
        line = lines[idx]
        m = _DN_ATTR_RE.match(line)
        if m:
            dn[m.group(1)] = m.group(2)
            idx += 1
            continue
        # Name line in Subject section is not a DN attribute
        m = _SUBJECT_NAME_RE.match(line)
        if m:
            idx += 1
            continue
        break

    return dn, idx


def _parse_validity(
    lines: list[str],
    start_idx: int,
) -> _ValidityResult:
    """Parse validity date section.

    Returns:
        Tuple of (validity_dict, next_index).
    """
    start_date = ""
    end_date = ""
    idx = start_idx

    while idx < len(lines):
        line = lines[idx]
        m = _START_DATE_RE.match(line)
        if m:
            start_date = m.group(1)
            idx += 1
            continue
        m = _END_DATE_RE.match(line)
        if m:
            end_date = m.group(1)
            idx += 1
            continue
        if not line.strip():
            idx += 1
            continue
        break

    if start_date and end_date:
        return {"start_date": start_date, "end_date": end_date}, idx
    return None, idx


def _try_simple_field(line: str, entry: dict) -> bool:
    """Try to match a line against simple key-value patterns.

    Returns True if a match was found.
    """
    for pattern, key in _SIMPLE_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[key] = m.group(1)
            return True
    return False


def _parse_section_or_validity(
    lines: list[str],
    idx: int,
    entry: dict,
) -> tuple[str, int]:
    """Parse DN section or validity block at the current index.

    Returns:
        Tuple of (subject_name, next_index).
    """
    line = lines[idx]
    subject_name = ""

    m = _SECTION_RE.match(line)
    if m:
        section_name = m.group(1).lower()
        idx += 1
        if section_name == "subject" and idx < len(lines):
            name_m = _SUBJECT_NAME_RE.match(lines[idx])
            if name_m:
                subject_name = name_m.group(1)
        dn, idx = _parse_dn_section(lines, idx)
        entry[section_name] = dn
        return subject_name, idx

    m = _VALIDITY_HEADER_RE.match(line)
    if m:
        idx += 1
        validity, idx = _parse_validity(lines, idx)
        if validity is not None:
            entry["validity_date"] = validity
        return subject_name, idx

    return subject_name, idx + 1


def _parse_certificate_block(
    lines: list[str],
) -> tuple[str, CertificateEntry] | None:
    """Parse a single certificate block.

    Returns:
        Tuple of (cert_type, entry) or None if unparseable.
    """
    if not lines:
        return None

    header = _CERT_TYPE_RE.match(lines[0])
    if not header:
        return None

    cert_type = header.group(1)
    entry: dict = {}
    subject_name = ""

    idx = 1
    while idx < len(lines):
        line = lines[idx]

        if _try_simple_field(line, entry):
            idx += 1
            continue

        if _SECTION_RE.match(line) or _VALIDITY_HEADER_RE.match(line):
            name, idx = _parse_section_or_validity(lines, idx, entry)
            if name:
                subject_name = name
            continue

        idx += 1

    if subject_name:
        entry["subject_name"] = subject_name

    return cert_type, entry  # type: ignore[return-value]


def _extract_trustpoint(entry: dict) -> str:
    """Extract trustpoint name from associated_trustpoints field.

    Returns the first trustpoint name (before any space or comma).
    """
    raw = entry.get("associated_trustpoints", "")
    return raw.split()[0].strip(",") if raw else ""


@register(OS.CISCO_IOS, "show crypto pki certificates")
class ShowCryptoPkiCertificatesParser(
    BaseParser["ShowCryptoPkiCertificatesResult"],
):
    """Parser for 'show crypto pki certificates' on IOS."""

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiCertificatesResult:
        """Parse 'show crypto pki certificates' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed PKI certificate details keyed by trustpoint name,
            then by certificate type.

        Raises:
            ValueError: If no certificate entries found in output.
        """
        blocks = _split_certificate_blocks(output)
        trustpoints: dict[str, dict[str, CertificateEntry]] = {}

        for block_lines in blocks:
            result = _parse_certificate_block(block_lines)
            if result is None:
                continue
            cert_type, entry = result
            tp_name = _extract_trustpoint(entry)
            if tp_name:
                trustpoints.setdefault(tp_name, {})[cert_type] = entry

        if not trustpoints:
            msg = "No PKI certificate entries found in output"
            raise ValueError(msg)

        return {"trustpoints": trustpoints}
