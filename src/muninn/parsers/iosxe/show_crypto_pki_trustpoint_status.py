"""Parser for 'show crypto pki trustpoint status' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Trustpoint header, e.g. ``Trustpoint TP-self-signed-4032138694:``
_TRUSTPOINT_HEADER_RE = re.compile(r"^Trustpoint\s+(?P<name>\S+)\s*:\s*$")

# Certificate section header, e.g. ``Issuing CA certificate configured:``
# or ``Router General Purpose certificate configured:``
_CERT_SECTION_RE = re.compile(
    r"^\s+(?P<type>.+?)\s+certificate\s+configured\s*:\s*$", re.IGNORECASE
)

# Subject Name line (the label, not the value)
_SUBJECT_NAME_LABEL_RE = re.compile(r"^\s+Subject Name\s*:\s*$")

# Subject Name value (indented DN line, e.g. ``cn=...,o=...``)
_SUBJECT_NAME_VALUE_RE = re.compile(r"^\s+(?P<dn>\S.*\S)\s*$")

# Fingerprint lines
_FINGERPRINT_MD5_RE = re.compile(
    r"^\s+Fingerprint MD5\s*:\s*(?P<value>[0-9A-Fa-f ]+)\s*$"
)
_FINGERPRINT_SHA1_RE = re.compile(
    r"^\s+Fingerprint SHA1\s*:\s*(?P<value>[0-9A-Fa-f ]+)\s*$"
)

# State section header
_STATE_HEADER_RE = re.compile(r"^\s+State\s*:\s*$")

# State key-value lines, e.g.
# ``Keys generated ............. Yes (General Purpose, non-exportable)``
_STATE_LINE_RE = re.compile(
    r"^\s+(?P<label>[A-Za-z][A-Za-z() ]+?)\s+\.{2,}\s+(?P<value>.+?)\s*$"
)

# Map state labels to canonical field names
_STATE_LABEL_MAP: dict[str, str] = {
    "keys generated": "keys_generated",
    "issuing ca authenticated": "issuing_ca_authenticated",
    "certificate request(s)": "certificate_requests",
}


class CertificateInfo(TypedDict):
    """Schema for a configured certificate within a trustpoint."""

    subject_name: str
    fingerprint_md5: NotRequired[str]
    fingerprint_sha1: NotRequired[str]


class TrustpointState(TypedDict):
    """Schema for the state section of a trustpoint."""

    keys_generated: NotRequired[str]
    issuing_ca_authenticated: NotRequired[str]
    certificate_requests: NotRequired[str]


class TrustpointEntry(TypedDict):
    """Schema for a single trustpoint entry."""

    name: str
    certificates: NotRequired[dict[str, CertificateInfo]]
    state: NotRequired[TrustpointState]


class ShowCryptoPkiTrustpointStatusResult(TypedDict):
    """Schema for 'show crypto pki trustpoint status' parsed output.

    Keyed by trustpoint name.
    """

    trustpoints: dict[str, TrustpointEntry]


def _normalize_cert_type(raw: str) -> str:
    """Normalize certificate type to a canonical key.

    Examples:
        'Issuing CA' -> 'issuing_ca'
        'Router General Purpose' -> 'router_general_purpose'
    """
    return raw.strip().lower().replace(" ", "_")


def _parse_state_label(label: str) -> str | None:
    """Map a state label to its canonical field name."""
    return _STATE_LABEL_MAP.get(label.strip().lower())


def _is_section_boundary(line: str) -> bool:
    """Return True if the line starts a new major section."""
    return bool(
        _TRUSTPOINT_HEADER_RE.match(line)
        or _CERT_SECTION_RE.match(line)
        or _STATE_HEADER_RE.match(line)
    )


def _try_fingerprint(line: str, cert_info: dict[str, str]) -> bool:
    """Try to match a fingerprint line and store it.

    Returns True if a fingerprint was matched.
    """
    fp_md5 = _FINGERPRINT_MD5_RE.match(line)
    if fp_md5:
        cert_info["fingerprint_md5"] = fp_md5.group("value").strip()
        return True
    fp_sha1 = _FINGERPRINT_SHA1_RE.match(line)
    if fp_sha1:
        cert_info["fingerprint_sha1"] = fp_sha1.group("value").strip()
        return True
    return False


def _collect_subject_name(
    lines: list[str],
    idx: int,
    cert_info: dict[str, str],
) -> tuple[list[str], int]:
    """Collect subject name DN parts until a fingerprint or section boundary.

    Returns the list of DN parts and the next index to process.
    """
    subject_parts: list[str] = []
    while idx < len(lines):
        line = lines[idx]
        if _is_section_boundary(line) or _try_fingerprint(line, cert_info):
            break
        val_match = _SUBJECT_NAME_VALUE_RE.match(line)
        if val_match:
            subject_parts.append(val_match.group("dn"))
        idx += 1
    return subject_parts, idx


def _try_parse_certificate_section(
    lines: list[str],
    idx: int,
    trustpoint: dict,
) -> int:
    r"""Parse a certificate section starting at idx.

    Returns the next index to continue processing from.
    """
    match = _CERT_SECTION_RE.match(lines[idx])
    if match is None:
        return idx
    cert_type = _normalize_cert_type(match.group("type"))
    idx += 1
    cert_info: dict[str, str] = {}
    subject_parts: list[str] = []

    while idx < len(lines):
        line = lines[idx]

        if _is_section_boundary(line):
            break

        if _SUBJECT_NAME_LABEL_RE.match(line):
            idx += 1
            parts, idx = _collect_subject_name(lines, idx, cert_info)
            subject_parts.extend(parts)
            continue

        if _try_fingerprint(line, cert_info):
            idx += 1
            continue

        if not line.strip():
            idx += 1
            break

        idx += 1

    if subject_parts:
        cert_info["subject_name"] = ",".join(subject_parts)

    if cert_info:
        certs = trustpoint.setdefault("certificates", {})
        certs[cert_type] = cert_info

    return idx


def _try_parse_state_section(
    lines: list[str],
    idx: int,
    trustpoint: dict,
) -> int:
    """Parse the State section starting at idx.

    Returns the next index to continue processing from.
    """
    if not _STATE_HEADER_RE.match(lines[idx]):
        return idx
    idx += 1
    state: dict[str, str] = {}

    while idx < len(lines):
        line = lines[idx]

        if _TRUSTPOINT_HEADER_RE.match(line):
            break

        if not line.strip():
            idx += 1
            break

        state_match = _STATE_LINE_RE.match(line)
        if state_match:
            field = _parse_state_label(state_match.group("label"))
            value = state_match.group("value")
            if field and value.lower() != "none":
                state[field] = value
            idx += 1
            continue

        idx += 1

    if state:
        trustpoint["state"] = state

    return idx


@register(OS.CISCO_IOSXE, "show crypto pki trustpoint status")
class ShowCryptoPkiTrustpointStatusParser(
    BaseParser["ShowCryptoPkiTrustpointStatusResult"],
):
    """Parser for 'show crypto pki trustpoint status' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiTrustpointStatusResult:
        """Parse 'show crypto pki trustpoint status' output.

        Args:
            output: Raw CLI output from the device.

        Returns:
            Structured mapping of trustpoint name to its parsed entry.

        Raises:
            ValueError: If no trustpoint entries are found in output.
        """
        lines = output.splitlines()
        trustpoints: dict[str, TrustpointEntry] = {}
        idx = 0

        while idx < len(lines):
            line = lines[idx]

            header = _TRUSTPOINT_HEADER_RE.match(line)
            if header:
                tp_name = header.group("name")
                trustpoint: dict = {"name": tp_name}
                idx += 1

                # Parse sections within this trustpoint
                while idx < len(lines):
                    cur_line = lines[idx]

                    # Next trustpoint starts
                    if _TRUSTPOINT_HEADER_RE.match(cur_line):
                        break

                    if _CERT_SECTION_RE.match(cur_line):
                        idx = _try_parse_certificate_section(lines, idx, trustpoint)
                        continue

                    if _STATE_HEADER_RE.match(cur_line):
                        idx = _try_parse_state_section(lines, idx, trustpoint)
                        continue

                    idx += 1

                trustpoints[tp_name] = cast(TrustpointEntry, trustpoint)
            else:
                idx += 1

        if not trustpoints:
            msg = (
                "No trustpoint entries found in output; output does not "
                "appear to be from 'show crypto pki trustpoint status'."
            )
            raise ValueError(msg)

        return cast(
            ShowCryptoPkiTrustpointStatusResult,
            {"trustpoints": trustpoints},
        )
