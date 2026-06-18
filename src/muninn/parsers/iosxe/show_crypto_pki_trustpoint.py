"""Parser for 'show crypto pki trustpoint' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Trustpoint header, e.g. ``Trustpoint TP-self-signed-4032138694:``
_TRUSTPOINT_HEADER_RE = re.compile(r"^\s*Trustpoint\s+(?P<name>.+?)\s*:\s*$")

# Serial Number (hex): 01
_SERIAL_RE = re.compile(r"^\s*Serial\s+Number\s*\(hex\)\s*:\s*(?P<serial>\S+)\s*$")

# DN attribute line, e.g. ``cn=IOS-Self-Signed-Certificate-4032138694``
_DN_ATTR_RE = re.compile(r"^\s+(?P<key>\w+)=(?P<value>.+?)\s*$")

# ``Using key label <label>``
_KEY_LABEL_RE = re.compile(r"^\s*Using\s+key\s+label\s+(?P<label>\S+)\s*$")


class TrustpointEntry(TypedDict):
    """Schema for a single trustpoint entry.

    Attributes:
        subject_name: Mapping of DN attribute abbreviation to value
            (e.g. ``{"cn": "...", "o": "..."}``) using standard X.509
            attribute short names.
        serial_number_hex: Certificate serial number in hexadecimal.
        status: Status description line (e.g. "Certificate configured.",
            "Persistent self-signed certificate trust point").
        key_label: Key label when the trustpoint uses a named key.
            Omitted when not present.
    """

    subject_name: dict[str, str]
    serial_number_hex: str
    status: str
    key_label: NotRequired[str]


class ShowCryptoPkiTrustpointResult(TypedDict):
    """Schema for 'show crypto pki trustpoint' parsed output.

    Keyed by trustpoint name.
    """

    trustpoints: dict[str, TrustpointEntry]


def _is_subject_name_header(line: str) -> bool:
    """Return True when line is the 'Subject Name:' section header."""
    return line.strip().lower() == "subject name:"


def _is_status_line(line: str) -> bool:
    """Return True when the line is a known status/description line.

    Status lines are indented text that are not DN attributes, not
    serial number lines, not key label lines, and not the Subject Name
    header.  They describe the trustpoint state.
    """
    stripped = line.strip()
    if not stripped:
        return False
    # Must be indented content that doesn't match other patterns
    if _DN_ATTR_RE.match(line):
        return False
    if _SERIAL_RE.match(line):
        return False
    if _KEY_LABEL_RE.match(line):
        return False
    if _is_subject_name_header(line):
        return False
    if _TRUSTPOINT_HEADER_RE.match(line):
        return False
    return True


def _parse_trustpoint_block(
    lines: list[str],
) -> TrustpointEntry:
    """Parse a single trustpoint block into a TrustpointEntry.

    Expects lines after the ``Trustpoint <name>:`` header.
    """
    entry: dict[str, object] = {"subject_name": {}}
    subject_name = cast(dict[str, str], entry["subject_name"])

    for line in lines:
        serial_m = _SERIAL_RE.match(line)
        if serial_m:
            entry["serial_number_hex"] = serial_m.group("serial")
            continue

        dn_m = _DN_ATTR_RE.match(line)
        if dn_m:
            subject_name[dn_m.group("key")] = dn_m.group("value")
            continue

        key_m = _KEY_LABEL_RE.match(line)
        if key_m:
            entry["key_label"] = key_m.group("label")
            continue

        if _is_subject_name_header(line):
            continue

        if _is_status_line(line):
            entry["status"] = line.strip()

    return cast(TrustpointEntry, entry)


@register(OS.CISCO_IOSXE, "show crypto pki trustpoint")
class ShowCryptoPkiTrustpointParser(
    BaseParser["ShowCryptoPkiTrustpointResult"],
):
    """Parser for 'show crypto pki trustpoint' on IOS-XE.

    Produces a mapping of trustpoint name to its parsed entry including
    subject name DN attributes, serial number, status description, and
    optional key label.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiTrustpointResult:
        """Parse 'show crypto pki trustpoint' output.

        Args:
            output: Raw CLI output from the device.

        Returns:
            Structured mapping of trustpoint name to its parsed entry.

        Raises:
            ValueError: If no trustpoint entries are found in the output.
        """
        trustpoints: dict[str, TrustpointEntry] = {}
        current_name: str | None = None
        current_lines: list[str] = []

        for line in output.splitlines():
            header_m = _TRUSTPOINT_HEADER_RE.match(line)
            if header_m:
                if current_name is not None:
                    trustpoints[current_name] = _parse_trustpoint_block(current_lines)
                current_name = header_m.group("name")
                current_lines = []
                continue
            if current_name is not None:
                current_lines.append(line)

        if current_name is not None:
            trustpoints[current_name] = _parse_trustpoint_block(current_lines)

        if not trustpoints:
            msg = "No trustpoint entries found in output"
            raise ValueError(msg)

        return cast(ShowCryptoPkiTrustpointResult, {"trustpoints": trustpoints})
