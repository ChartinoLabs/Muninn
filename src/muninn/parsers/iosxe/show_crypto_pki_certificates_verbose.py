"""Parser for 'show crypto pki certificates verbose' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# --- Regex patterns ---

_CERT_TYPE_RE = re.compile(r"^((?:CA |RA |Router )?Certificate)\s*$")
_STATUS_RE = re.compile(r"^\s+Status:\s+(.+?)\s*$")
_VERSION_RE = re.compile(r"^\s+Version:\s+(\d+)\s*$")
_SERIAL_RE = re.compile(r"^\s+Certificate Serial Number\s*(?:\(hex\))?\s*:\s*(.+?)\s*$")
_USAGE_RE = re.compile(r"^\s+Certificate Usage:\s+(.+?)\s*$")
_SECTION_RE = re.compile(r"^\s+(Issuer|Subject)\s*:\s*$")
_VALIDITY_HEADER_RE = re.compile(r"^\s+Validity Date\s*:\s*$")
_START_DATE_RE = re.compile(r"^\s+start date:\s+(.+?)\s*$")
_END_DATE_RE = re.compile(r"^\s+end\s+date:\s+(.+?)\s*$")
_TRUSTPOINT_RE = re.compile(r"^\s+Associated Trustpoints:\s+(.+?)\s*$")
_CRL_HEADER_RE = re.compile(r"^\s+CRL Distribution Points?\s*:\s*$")
_CRL_URL_RE = re.compile(r"^\s+(https?://\S+)\s*$")
_SUBJECT_NAME_RE = re.compile(r"^\s+Name:\s+(.+?)\s*$")
_SERIAL_NUMBER_FIELD_RE = re.compile(r"^\s+Serial Number:\s+(.+?)\s*$")
_DN_ATTR_RE = re.compile(r"^\s+(\w+)=(.+?)\s*$")
_SUBJECT_KEY_INFO_RE = re.compile(r"^\s+Subject Key Info\s*:\s*$")
_PUB_KEY_ALGO_RE = re.compile(r"^\s+Public Key Algorithm:\s+(.+?)\s*$")
_RSA_KEY_RE = re.compile(r"^\s+RSA Public Key:\s+\((\d+)\s+bit\)\s*$")
_EC_KEY_RE = re.compile(r"^\s+EC Public Key:\s+\((\d+)\s+bit\)\s*$")
_SIG_ALGO_RE = re.compile(r"^\s+Signature Algorithm:\s+(.+?)\s*$")
_FP_MD5_RE = re.compile(r"^\s+Fingerprint MD5:\s+(.+?)\s*$")
_FP_SHA1_RE = re.compile(r"^\s+Fingerprint SHA1:\s+(.+?)\s*$")
_X509V3_EXT_HEADER_RE = re.compile(r"^\s+X509v3 extensions\s*:\s*$")
_KEY_USAGE_HEADER_RE = re.compile(r"^\s+X509v3 Key Usage:\s+(.+?)\s*$")
_SUBJECT_KEY_ID_RE = re.compile(r"^\s+X509v3 Subject Key ID:\s+(.+?)\s*$")
_AUTH_KEY_ID_RE = re.compile(r"^\s+X509v3 Authority Key ID:\s+(.+?)\s*$")
_AUTH_INFO_ACCESS_RE = re.compile(r"^\s+Authority Info Access\s*:\s*$")
_CA_ISSUERS_RE = re.compile(r"^\s+CA ISSUERS:\s+(.+?)\s*$")
_EXT_KEY_USAGE_HEADER_RE = re.compile(r"^\s+Extended Key Usage\s*:\s*$")
_CERT_INSTALL_TIME_RE = re.compile(r"^\s+Cert install time:\s+(.+?)\s*$")
_KEY_LABEL_RE = re.compile(r"^\s+Key Label:\s+(.+?)\s*$")
_STORAGE_RE = re.compile(r"^\s+Storage:\s+(.+?)\s*$")
_KEY_USAGE_VALUE_RE = re.compile(r"^\s{6,}([A-Z][A-Za-z ]+)\s*$")

# Simple one-line field patterns mapped to entry keys
_SIMPLE_FIELDS: list[tuple[re.Pattern[str], str]] = [
    (_STATUS_RE, "status"),
    (_SERIAL_RE, "serial_number"),
    (_USAGE_RE, "usage"),
    (_SIG_ALGO_RE, "signature_algorithm"),
    (_FP_MD5_RE, "fingerprint_md5"),
    (_FP_SHA1_RE, "fingerprint_sha1"),
    (_CERT_INSTALL_TIME_RE, "cert_install_time"),
    (_TRUSTPOINT_RE, "associated_trustpoints"),
    (_KEY_LABEL_RE, "key_label"),
    (_STORAGE_RE, "storage"),
]


class ValidityDate(TypedDict):
    """Schema for certificate validity dates."""

    start_date: str
    end_date: str


class SubjectKeyInfo(TypedDict):
    """Schema for Subject Key Info section."""

    public_key_algorithm: str
    key_size_bits: NotRequired[int]


class X509v3Extensions(TypedDict):
    """Schema for X509v3 extensions section."""

    key_usage_hex: NotRequired[str]
    key_usage: NotRequired[list[str]]
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
    crl_distribution_points: NotRequired[list[str]]
    subject_key_info: NotRequired[SubjectKeyInfo]
    signature_algorithm: NotRequired[str]
    fingerprint_md5: NotRequired[str]
    fingerprint_sha1: NotRequired[str]
    x509v3_extensions: NotRequired[X509v3Extensions]
    cert_install_time: NotRequired[str]
    key_label: NotRequired[str]
    storage: NotRequired[str]


class ShowCryptoPkiCertificatesVerboseResult(TypedDict):
    """Schema for 'show crypto pki certificates verbose' parsed output.

    Keyed by trustpoint name, then by certificate type.
    """

    trustpoints: dict[str, dict[str, CertificateEntry]]


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
) -> tuple[dict[str, str], int]:
    """Parse a DN section (Issuer or Subject) returning attributes."""
    dn: dict[str, str] = {}
    idx = start_idx

    while idx < len(lines):
        line = lines[idx]
        m = _DN_ATTR_RE.match(line)
        if m:
            dn[m.group(1)] = m.group(2)
            idx += 1
            continue
        if _SUBJECT_NAME_RE.match(line) or _SERIAL_NUMBER_FIELD_RE.match(line):
            idx += 1
            continue
        break

    return dn, idx


def _parse_validity(
    lines: list[str],
    start_idx: int,
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
        if not line.strip():
            idx += 1
            continue
        break

    if start_date and end_date:
        return {"start_date": start_date, "end_date": end_date}, idx
    return None, idx


def _parse_subject_key_info(
    lines: list[str],
    start_idx: int,
) -> tuple[SubjectKeyInfo | None, int]:
    """Parse Subject Key Info section."""
    algorithm = ""
    key_size: int | None = None
    idx = start_idx

    while idx < len(lines):
        line = lines[idx]
        m = _PUB_KEY_ALGO_RE.match(line)
        if m:
            algorithm = m.group(1)
            idx += 1
            continue
        m = _RSA_KEY_RE.match(line) or _EC_KEY_RE.match(line)
        if m:
            key_size = int(m.group(1))
            idx += 1
            continue
        if not line.strip():
            idx += 1
            continue
        break

    if algorithm:
        info: dict[str, str | int] = {"public_key_algorithm": algorithm}
        if key_size is not None:
            info["key_size_bits"] = key_size
        return cast(SubjectKeyInfo, info), idx
    return None, idx


def _try_ext_key_usage(
    lines: list[str],
    idx: int,
    ext: dict[str, str | list[str]],
    line: str,
) -> int | None:
    """Try to parse X509v3 Key Usage within extensions."""
    m = _KEY_USAGE_HEADER_RE.match(line)
    if not m:
        return None
    ext["key_usage_hex"] = m.group(1)
    idx += 1
    usages: list[str] = []
    while idx < len(lines):
        um = _KEY_USAGE_VALUE_RE.match(lines[idx])
        if um and lines[idx].startswith("      "):
            usages.append(um.group(1).strip())
            idx += 1
        else:
            break
    if usages:
        ext["key_usage"] = usages
    return idx


def _try_ext_extended_key_usage(
    lines: list[str],
    idx: int,
    ext: dict[str, str | list[str]],
    line: str,
) -> int | None:
    """Try to parse Extended Key Usage within extensions."""
    m = _EXT_KEY_USAGE_HEADER_RE.match(line)
    if not m:
        return None
    idx += 1
    eku: list[str] = []
    while idx < len(lines):
        eku_line = lines[idx]
        if eku_line.startswith("        "):
            val = eku_line.strip()
            if val:
                eku.append(val)
            idx += 1
        else:
            break
    if eku:
        ext["extended_key_usage"] = eku
    return idx


def _try_ext_auth_info_access(
    lines: list[str],
    idx: int,
    ext: dict[str, str | list[str]],
    line: str,
) -> int | None:
    """Try to parse Authority Info Access within extensions."""
    m = _AUTH_INFO_ACCESS_RE.match(line)
    if not m:
        return None
    idx += 1
    if idx < len(lines):
        ca_m = _CA_ISSUERS_RE.match(lines[idx])
        if ca_m:
            ext["authority_info_access"] = ca_m.group(1)
            idx += 1
    return idx


def _parse_x509v3_extensions(
    lines: list[str],
    start_idx: int,
) -> tuple[X509v3Extensions | None, int]:
    """Parse X509v3 extensions section."""
    ext: dict[str, str | list[str]] = {}
    idx = start_idx

    while idx < len(lines):
        line = lines[idx]

        if line.strip() and not line.startswith("    "):
            break

        result = _try_ext_key_usage(lines, idx, ext, line)
        if result is not None:
            idx = result
            continue

        m = _SUBJECT_KEY_ID_RE.match(line)
        if m:
            ext["subject_key_id"] = m.group(1)
            idx += 1
            continue

        m = _AUTH_KEY_ID_RE.match(line)
        if m:
            ext["authority_key_id"] = m.group(1)
            idx += 1
            continue

        result = _try_ext_auth_info_access(lines, idx, ext, line)
        if result is not None:
            idx = result
            continue

        result = _try_ext_extended_key_usage(lines, idx, ext, line)
        if result is not None:
            idx = result
            continue

        idx += 1

    if ext:
        return cast(X509v3Extensions, ext), idx
    return None, idx


def _parse_crl_distribution_points(
    lines: list[str],
    start_idx: int,
) -> tuple[list[str], int]:
    """Parse CRL Distribution Points URLs."""
    urls: list[str] = []
    idx = start_idx

    while idx < len(lines):
        m = _CRL_URL_RE.match(lines[idx])
        if m:
            urls.append(m.group(1))
            idx += 1
        else:
            break

    return urls, idx


def _try_simple_field(line: str, entry: dict[str, object]) -> bool:
    """Try to match a line against simple key-value patterns."""
    for pattern, key in _SIMPLE_FIELDS:
        m = pattern.match(line)
        if m:
            entry[key] = m.group(1)
            return True
    return False


def _try_version(line: str, entry: dict[str, object]) -> bool:
    """Try to parse the Version field."""
    m = _VERSION_RE.match(line)
    if m:
        entry["version"] = int(m.group(1))
        return True
    return False


def _parse_subject_section(
    lines: list[str],
    idx: int,
) -> tuple[str, str, dict[str, str], int]:
    """Parse Subject section, extracting name and serial number."""
    subject_name = ""
    subject_serial = ""
    if idx < len(lines):
        name_m = _SUBJECT_NAME_RE.match(lines[idx])
        if name_m:
            subject_name = name_m.group(1)
    scan_idx = idx
    while scan_idx < len(lines):
        sn_m = _SERIAL_NUMBER_FIELD_RE.match(lines[scan_idx])
        if sn_m:
            subject_serial = sn_m.group(1)
            break
        if not _DN_ATTR_RE.match(lines[scan_idx]) and not _SUBJECT_NAME_RE.match(
            lines[scan_idx]
        ):
            break
        scan_idx += 1
    dn, idx = _parse_dn_section(lines, idx)
    return subject_name, subject_serial, dn, idx


def _try_dn_section(
    lines: list[str],
    idx: int,
    line: str,
    entry: dict[str, object],
    names: list[str],
) -> int | None:
    """Try to parse Issuer/Subject DN section.

    Appends [subject_name, subject_serial] into *names* when found.
    """
    m = _SECTION_RE.match(line)
    if not m:
        return None
    section_name = m.group(1).lower()
    idx += 1
    if section_name == "subject":
        sn, ss, dn, idx = _parse_subject_section(lines, idx)
        if sn:
            names.append(sn)
        if ss:
            names.append(ss)
    else:
        dn, idx = _parse_dn_section(lines, idx)
    entry[section_name] = dn
    return idx


def _parse_certificate_block(
    lines: list[str],
) -> tuple[str, CertificateEntry] | None:
    """Parse a single verbose certificate block."""
    if not lines:
        return None

    header = _CERT_TYPE_RE.match(lines[0])
    if not header:
        return None

    cert_type = header.group(1)
    entry: dict[str, object] = {}
    names: list[str] = []

    idx = 1
    while idx < len(lines):
        line = lines[idx]

        if _try_simple_field(line, entry) or _try_version(line, entry):
            idx += 1
            continue

        dn_result = _try_dn_section(lines, idx, line, entry, names)
        if dn_result is not None:
            idx = dn_result
            continue

        idx = _try_block_sections(lines, idx, line, entry)

    if names:
        entry["subject_name"] = names[0]
    if len(names) > 1:
        entry["subject_serial_number"] = names[1]

    return cert_type, cast(CertificateEntry, entry)


def _try_block_sections(
    lines: list[str],
    idx: int,
    line: str,
    entry: dict[str, object],
) -> int:
    """Try to parse block-level sections (validity, CRL, etc.)."""
    if _VALIDITY_HEADER_RE.match(line):
        idx += 1
        validity, idx = _parse_validity(lines, idx)
        if validity is not None:
            entry["validity_date"] = validity
        return idx

    if _CRL_HEADER_RE.match(line):
        idx += 1
        urls, idx = _parse_crl_distribution_points(lines, idx)
        if urls:
            entry["crl_distribution_points"] = urls
        return idx

    if _SUBJECT_KEY_INFO_RE.match(line):
        idx += 1
        ski, idx = _parse_subject_key_info(lines, idx)
        if ski is not None:
            entry["subject_key_info"] = ski
        return idx

    if _X509V3_EXT_HEADER_RE.match(line):
        idx += 1
        extensions, idx = _parse_x509v3_extensions(lines, idx)
        if extensions is not None:
            entry["x509v3_extensions"] = extensions
        return idx

    return idx + 1


def _extract_trustpoint(entry: CertificateEntry) -> str:
    """Extract trustpoint name from associated_trustpoints field."""
    raw = entry.get("associated_trustpoints", "")
    return raw.split()[0].strip(",") if raw else ""


@register(OS.CISCO_IOSXE, "show crypto pki certificates verbose")
class ShowCryptoPkiCertificatesVerboseParser(
    BaseParser["ShowCryptoPkiCertificatesVerboseResult"],
):
    """Parser for 'show crypto pki certificates verbose' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiCertificatesVerboseResult:
        """Parse 'show crypto pki certificates verbose' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed verbose PKI certificate details keyed by
            trustpoint name, then by certificate type.

        Raises:
            ValueError: If no certificate entries found in output.
        """
        blocks = _split_certificate_blocks(output)
        trustpoints: dict[str, dict[str, CertificateEntry]] = {}

        for block_lines in blocks:
            result = _parse_certificate_block(block_lines)
            if result is None:
                continue
            cert_type, cert_entry = result
            tp_name = _extract_trustpoint(cert_entry)
            if tp_name:
                trustpoints.setdefault(tp_name, {})[cert_type] = cert_entry

        if not trustpoints:
            msg = "No PKI certificate entries found in output"
            raise ValueError(msg)

        return {"trustpoints": trustpoints}
