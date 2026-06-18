"""Parser for 'show crypto pki certificate verbose' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ValidityDate(TypedDict):
    """Schema for certificate validity dates."""

    start_date: str
    end_date: str


class SubjectKeyInfo(TypedDict):
    """Schema for subject key information."""

    public_key_algorithm: str
    key_size: NotRequired[str]


class X509v3Extensions(TypedDict):
    """Schema for X.509v3 extensions."""

    key_usage: NotRequired[str]
    key_usage_details: NotRequired[list[str]]
    subject_key_id: NotRequired[str]
    authority_key_id: NotRequired[str]
    authority_info_access: NotRequired[str]
    extended_key_usage: NotRequired[list[str]]


class CertificateEntry(TypedDict):
    """Schema for a single verbose certificate entry."""

    status: str
    version: int
    serial_number: str
    usage: str
    issuer: dict[str, str]
    subject: dict[str, str]
    validity_date: ValidityDate
    associated_trustpoints: str
    subject_name: NotRequired[str]
    subject_serial_number: NotRequired[str]
    crl_distribution_points: NotRequired[str]
    subject_key_info: NotRequired[SubjectKeyInfo]
    signature_algorithm: NotRequired[str]
    fingerprint_md5: NotRequired[str]
    fingerprint_sha1: NotRequired[str]
    x509v3_extensions: NotRequired[X509v3Extensions]
    cert_install_time: NotRequired[str]
    key_label: NotRequired[str]


class ShowCryptoPkiCertificateVerboseResult(TypedDict):
    """Schema for 'show crypto pki certificate verbose' parsed output.

    Keyed by trustpoint name, then by certificate type
    (e.g. "CA Certificate", "Certificate").
    """

    trustpoints: dict[str, dict[str, CertificateEntry]]


# --- Regex patterns ---

_CERT_TYPE_RE = re.compile(r"^((?:CA |RA |Router )?Certificate)\s*$")
_STATUS_RE = re.compile(r"^\s+Status:\s+(.+?)\s*$")
_VERSION_RE = re.compile(r"^\s+Version:\s+(\d+)\s*$")
_SERIAL_RE = re.compile(r"^\s+Certificate Serial Number\s*(?:\(hex\))?\s*:\s*(.+?)\s*$")
_USAGE_RE = re.compile(r"^\s+Certificate Usage:\s+(.+?)\s*$")
_SECTION_RE = re.compile(r"^\s+(Issuer|Subject)\s*:\s*$")
_TRUSTPOINT_RE = re.compile(r"^\s+Associated Trustpoints:\s+(.+?)\s*$")
_CRL_RE = re.compile(r"^\s+CRL Distribution Points?\s*:\s*$")
_VALIDITY_HEADER_RE = re.compile(r"^\s+Validity Date\s*:\s*$")
_START_DATE_RE = re.compile(r"^\s+start date:\s+(.+?)\s*$")
_END_DATE_RE = re.compile(r"^\s+end\s+date:\s+(.+?)\s*$")
_SUBJECT_NAME_RE = re.compile(r"^\s+Name:\s+(.+?)\s*$")
_SUBJECT_SERIAL_RE = re.compile(r"^\s+Serial Number:\s+(.+?)\s*$")
_DN_ATTR_RE = re.compile(r"^\s+(\w+)=(.+?)\s*$")
_SUBJECT_KEY_INFO_RE = re.compile(r"^\s+Subject Key Info\s*:\s*$")
_PUB_KEY_ALG_RE = re.compile(r"^\s+Public Key Algorithm:\s+(.+?)\s*$")
_RSA_KEY_RE = re.compile(r"^\s+RSA Public Key:\s+\((\d+ bit)\)\s*$")
_SIG_ALG_RE = re.compile(r"^\s+Signature Algorithm:\s+(.+?)\s*$")
_FP_MD5_RE = re.compile(r"^\s+Fingerprint MD5:\s+(.+?)\s*$")
_FP_SHA1_RE = re.compile(r"^\s+Fingerprint SHA1:\s+(.+?)\s*$")
_X509V3_HEADER_RE = re.compile(r"^\s+X509v3 extensions\s*:\s*$")
_X509V3_KEY_USAGE_RE = re.compile(r"^\s+X509v3 Key Usage:\s+(.+?)\s*$")
_X509V3_SUBJECT_KEY_ID_RE = re.compile(r"^\s+X509v3 Subject Key ID:\s+(.+?)\s*$")
_X509V3_AUTH_KEY_ID_RE = re.compile(r"^\s+X509v3 Authority Key ID:\s+(.+?)\s*$")
_AUTH_INFO_ACCESS_RE = re.compile(r"^\s+Authority Info Access\s*:\s*$")
_CA_ISSUERS_RE = re.compile(r"^\s+CA ISSUERS:\s+(.+?)\s*$")
_EXT_KEY_USAGE_HEADER_RE = re.compile(r"^\s+Extended Key Usage\s*:\s*$")
_EXT_KEY_USAGE_VALUE_RE = re.compile(r"^\s{8,}(\S.+?)\s*$")
_CERT_INSTALL_RE = re.compile(r"^\s+Cert install time:\s+(.+?)\s*$")
_KEY_LABEL_RE = re.compile(r"^\s+Key Label:\s+(.+?)\s*$")
_KEY_USAGE_DETAIL_RE = re.compile(r"^\s{6,}([A-Z].+?)\s*$")

# Simple single-line field patterns for _try_simple_field
_SIMPLE_FIELD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_STATUS_RE, "status"),
    (_SERIAL_RE, "serial_number"),
    (_USAGE_RE, "usage"),
    (_TRUSTPOINT_RE, "associated_trustpoints"),
    (_SIG_ALG_RE, "signature_algorithm"),
    (_FP_MD5_RE, "fingerprint_md5"),
    (_FP_SHA1_RE, "fingerprint_sha1"),
    (_CERT_INSTALL_RE, "cert_install_time"),
    (_KEY_LABEL_RE, "key_label"),
]


def _split_certificate_blocks(output: str) -> list[list[str]]:
    """Split output into per-certificate blocks."""
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
    entry: dict,
    section_name: str,
) -> int:
    """Parse a DN section (Issuer or Subject) after the header.

    Returns the next index not consumed by this section.
    """
    dn: dict[str, str] = {}
    idx = start_idx

    while idx < len(lines):
        line = lines[idx]
        if section_name == "subject":
            m = _SUBJECT_NAME_RE.match(line)
            if m:
                entry["subject_name"] = m.group(1)
                idx += 1
                continue
            m = _SUBJECT_SERIAL_RE.match(line)
            if m:
                entry["subject_serial_number"] = m.group(1)
                idx += 1
                continue
        m = _DN_ATTR_RE.match(line)
        if m:
            dn[m.group(1)] = m.group(2)
            idx += 1
            continue
        break

    entry[section_name] = dn
    return idx


def _parse_validity(
    lines: list[str], start_idx: int
) -> tuple[ValidityDate | None, int]:
    """Parse validity date section."""
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
        break

    if start_date and end_date:
        return {"start_date": start_date, "end_date": end_date}, idx
    return None, idx


def _parse_subject_key_info(
    lines: list[str], start_idx: int
) -> tuple[SubjectKeyInfo | None, int]:
    """Parse Subject Key Info section."""
    idx = start_idx
    algorithm = ""
    key_size = ""

    while idx < len(lines):
        line = lines[idx]
        m = _PUB_KEY_ALG_RE.match(line)
        if m:
            algorithm = m.group(1)
            idx += 1
            continue
        m = _RSA_KEY_RE.match(line)
        if m:
            key_size = m.group(1)
            idx += 1
            continue
        break

    if algorithm:
        info: dict[str, str] = {"public_key_algorithm": algorithm}
        if key_size:
            info["key_size"] = key_size
        return cast(SubjectKeyInfo, info), idx
    return None, idx


def _try_x509v3_key_usage(lines: list[str], idx: int, ext: dict) -> int:
    """Parse X509v3 Key Usage and its detail lines."""
    m = _X509V3_KEY_USAGE_RE.match(lines[idx])
    if not m:
        return idx
    ext["key_usage"] = m.group(1)
    idx += 1
    details: list[str] = []
    while idx < len(lines):
        dm = _KEY_USAGE_DETAIL_RE.match(lines[idx])
        if dm:
            details.append(dm.group(1))
            idx += 1
        else:
            break
    if details:
        ext["key_usage_details"] = details
    return idx


def _try_x509v3_ext_key_usage(lines: list[str], idx: int, ext: dict) -> int:
    """Parse Extended Key Usage header and value lines."""
    m = _EXT_KEY_USAGE_HEADER_RE.match(lines[idx])
    if not m:
        return idx
    idx += 1
    usages: list[str] = []
    while idx < len(lines):
        um = _EXT_KEY_USAGE_VALUE_RE.match(lines[idx])
        if um:
            usages.append(um.group(1))
            idx += 1
        else:
            break
    if usages:
        ext["extended_key_usage"] = usages
    return idx


def _try_x509v3_auth_info(lines: list[str], idx: int, ext: dict) -> int:
    """Parse Authority Info Access and its CA ISSUERS line."""
    m = _AUTH_INFO_ACCESS_RE.match(lines[idx])
    if not m:
        return idx
    idx += 1
    if idx < len(lines):
        ca_m = _CA_ISSUERS_RE.match(lines[idx])
        if ca_m:
            ext["authority_info_access"] = ca_m.group(1)
            idx += 1
    return idx


def _parse_x509v3_extensions(
    lines: list[str], start_idx: int
) -> tuple[X509v3Extensions | None, int]:
    """Parse X509v3 extensions section."""
    idx = start_idx
    ext: dict = {}

    while idx < len(lines):
        line = lines[idx]

        if _X509V3_KEY_USAGE_RE.match(line):
            idx = _try_x509v3_key_usage(lines, idx, ext)
            continue

        m = _X509V3_SUBJECT_KEY_ID_RE.match(line)
        if m:
            ext["subject_key_id"] = m.group(1)
            idx += 1
            continue

        m = _X509V3_AUTH_KEY_ID_RE.match(line)
        if m:
            ext["authority_key_id"] = m.group(1)
            idx += 1
            continue

        if _AUTH_INFO_ACCESS_RE.match(line):
            idx = _try_x509v3_auth_info(lines, idx, ext)
            continue

        if _EXT_KEY_USAGE_HEADER_RE.match(line):
            idx = _try_x509v3_ext_key_usage(lines, idx, ext)
            continue

        break

    if ext:
        return cast(X509v3Extensions, ext), idx
    return None, idx


def _parse_crl_distribution(lines: list[str], start_idx: int) -> tuple[str | None, int]:
    """Parse CRL Distribution Points (URL on next line)."""
    idx = start_idx
    if idx < len(lines):
        stripped = lines[idx].strip()
        if stripped and stripped.startswith("http"):
            return stripped, idx + 1
    return None, idx


def _try_simple_field(line: str, entry: dict) -> bool:
    """Try to match a line against simple single-value patterns.

    Returns True if a match was found and the field was written.
    """
    for pattern, key in _SIMPLE_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[key] = m.group(1)
            return True
    return False


def _try_verbose_section(lines: list[str], idx: int, entry: dict) -> int | None:
    """Try to parse verbose-specific multi-line sections.

    Handles Subject Key Info and X509v3 extensions.
    Returns the new index if a section was parsed, or None.
    """
    line = lines[idx]

    if _SUBJECT_KEY_INFO_RE.match(line):
        ski, new_idx = _parse_subject_key_info(lines, idx + 1)
        if ski is not None:
            entry["subject_key_info"] = ski
        return new_idx

    if _X509V3_HEADER_RE.match(line):
        extensions, new_idx = _parse_x509v3_extensions(lines, idx + 1)
        if extensions is not None:
            entry["x509v3_extensions"] = extensions
        return new_idx

    return None


def _try_section_block(lines: list[str], idx: int, entry: dict) -> int | None:
    """Try to parse a multi-line section block at the given index.

    Returns the new index if a section was parsed, or None if not.
    """
    line = lines[idx]

    m = _VERSION_RE.match(line)
    if m:
        entry["version"] = int(m.group(1))
        return idx + 1

    m = _SECTION_RE.match(line)
    if m:
        section_name = m.group(1).lower()
        return _parse_dn_section(lines, idx + 1, entry, section_name)

    if _VALIDITY_HEADER_RE.match(line):
        validity, new_idx = _parse_validity(lines, idx + 1)
        if validity is not None:
            entry["validity_date"] = validity
        return new_idx

    if _CRL_RE.match(line):
        crl_url, new_idx = _parse_crl_distribution(lines, idx + 1)
        if crl_url:
            entry["crl_distribution_points"] = crl_url
        return new_idx

    return _try_verbose_section(lines, idx, entry)


def _parse_certificate_block(
    lines: list[str],
) -> tuple[str, dict] | None:
    """Parse a single certificate block into (cert_type, entry)."""
    if not lines:
        return None

    header = _CERT_TYPE_RE.match(lines[0])
    if not header:
        return None

    cert_type = header.group(1)
    entry: dict = {}

    idx = 1
    while idx < len(lines):
        line = lines[idx]

        if _try_simple_field(line, entry):
            idx += 1
            continue

        new_idx = _try_section_block(lines, idx, entry)
        if new_idx is not None:
            idx = new_idx
            continue

        idx += 1

    return cert_type, entry


def _extract_trustpoint(entry: dict) -> str:
    """Extract trustpoint name from associated_trustpoints field."""
    raw = entry.get("associated_trustpoints", "")
    return raw.split()[0].strip(",") if raw else ""


@register(OS.CISCO_IOSXE, "show crypto pki certificate verbose")
@register(OS.CISCO_IOSXE, "show crypto pki certificates verbose")
class ShowCryptoPkiCertificateVerboseParser(
    BaseParser["ShowCryptoPkiCertificateVerboseResult"],
):
    """Parser for 'show crypto pki certificate verbose' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiCertificateVerboseResult:
        """Parse 'show crypto pki certificate verbose' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed verbose PKI certificate details keyed by trustpoint
            name, then by certificate type.

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
                trustpoints.setdefault(tp_name, {})[cert_type] = cast(
                    CertificateEntry, entry
                )

        if not trustpoints:
            msg = "No PKI certificate entries found in output"
            raise ValueError(msg)

        return {"trustpoints": trustpoints}
