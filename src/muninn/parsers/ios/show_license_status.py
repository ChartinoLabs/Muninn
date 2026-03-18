"""Parser for 'show license status' command on IOS."""

import re
from collections.abc import Callable
from typing import Any, ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# --- Section header constants ---
_SECTION_LICENSE_TYPE = "license type supported"
_SECTION_LICENSE_OPERATION = "license operation supported"
_SECTION_CALLHOME_OPERATION = "call-home operation supported"
_SECTION_DEVICE_STATUS = "device status"
_SECTION_SWIFT_URL_STATUS = "swift url status"


class LicenseTypeEntry(TypedDict):
    """Schema for a supported license type."""

    description: str


class LicenseOperationEntry(TypedDict):
    """Schema for a supported license operation."""

    description: str


class CallHomeOperationEntry(TypedDict):
    """Schema for a supported call-home operation."""

    description: str


class DeviceStatusEntry(TypedDict):
    """Schema for device status information."""

    credential_type: str
    credential_verification: str
    rehost_type: str


class ShowLicenseStatusResult(TypedDict):
    """Schema for 'show license status' parsed output."""

    license_types: NotRequired[dict[str, LicenseTypeEntry]]
    license_operations: NotRequired[dict[str, LicenseOperationEntry]]
    callhome_operations: NotRequired[dict[str, CallHomeOperationEntry]]
    device_status: NotRequired[DeviceStatusEntry]
    swift_url: NotRequired[str]


# --- Regex patterns ---

# Single-word key entry (license types): "keyword  Description text"
_SINGLE_KEY_ENTRY_RE = re.compile(r"^\s+(\S+)\s+(\S.+?)\s*$")

# Multi-word key entry (operations): "keyword  Description" or "key word  Description"
_MULTI_KEY_ENTRY_RE = re.compile(r"^\s+(\S+(?:\s\S+)?)\s{2,}(.+?)\s*$")

# Device credential type
_CREDENTIAL_TYPE_RE = re.compile(
    r"^\s*Device\s+Credential\s+type:\s+(\S+)\s*$", re.IGNORECASE
)

# Device credential verification
_CREDENTIAL_VERIFY_RE = re.compile(
    r"^\s*Device\s+Credential\s+Verification:\s+(\S+)\s*$", re.IGNORECASE
)

# Rehost type
_REHOST_TYPE_RE = re.compile(r"^\s*Rehost\s+Type:\s+(\S+)\s*$", re.IGNORECASE)

# SWIFT URL line
_SWIFT_URL_RE = re.compile(
    r"^\s*Swift\s+URL\s+.*?:\s+(https?://\S+)\s*$", re.IGNORECASE
)


def _detect_section(line: str) -> str | None:
    """Detect if a line is a section header, returning normalized section name."""
    stripped = line.strip().lower()
    known_sections = (
        _SECTION_LICENSE_TYPE,
        _SECTION_LICENSE_OPERATION,
        _SECTION_CALLHOME_OPERATION,
        _SECTION_DEVICE_STATUS,
        _SECTION_SWIFT_URL_STATUS,
    )
    for section in known_sections:
        if stripped == section:
            return section
    return None


def _parse_license_types(
    lines: list[str], start: int
) -> tuple[dict[str, LicenseTypeEntry], int]:
    """Parse the License Type Supported section.

    License type keys are always single words (permanent, extension, evaluation).
    """
    types: dict[str, LicenseTypeEntry] = {}
    idx = start
    while idx < len(lines):
        line = lines[idx]
        if _detect_section(line) is not None:
            break
        match = _SINGLE_KEY_ENTRY_RE.match(line)
        if match:
            types[match.group(1)] = LicenseTypeEntry(description=match.group(2))
        idx += 1
    return types, idx


def _parse_operations(
    lines: list[str], start: int
) -> tuple[dict[str, LicenseOperationEntry], int]:
    """Parse a License Operation Supported section.

    Operation keys may be multi-word (e.g. call-home) so require 2+ space delimiter.
    """
    ops: dict[str, LicenseOperationEntry] = {}
    idx = start
    while idx < len(lines):
        line = lines[idx]
        if _detect_section(line) is not None:
            break
        match = _MULTI_KEY_ENTRY_RE.match(line)
        if match:
            ops[match.group(1)] = LicenseOperationEntry(description=match.group(2))
        idx += 1
    return ops, idx


def _parse_callhome_operations(
    lines: list[str], start: int
) -> tuple[dict[str, CallHomeOperationEntry], int]:
    """Parse the Call-home Operation Supported section.

    Call-home operation keys may be multi-word (e.g. show pak).
    """
    ops: dict[str, CallHomeOperationEntry] = {}
    idx = start
    while idx < len(lines):
        line = lines[idx]
        if _detect_section(line) is not None:
            break
        match = _MULTI_KEY_ENTRY_RE.match(line)
        if match:
            ops[match.group(1)] = CallHomeOperationEntry(description=match.group(2))
        idx += 1
    return ops, idx


def _parse_device_status(
    lines: list[str], start: int
) -> tuple[DeviceStatusEntry | None, int]:
    """Parse the Device status section."""
    credential_type = ""
    credential_verification = ""
    rehost_type = ""
    idx = start
    while idx < len(lines):
        line = lines[idx]
        if _detect_section(line) is not None:
            break

        match = _CREDENTIAL_TYPE_RE.match(line)
        if match:
            credential_type = match.group(1)
            idx += 1
            continue

        match = _CREDENTIAL_VERIFY_RE.match(line)
        if match:
            credential_verification = match.group(1)
            idx += 1
            continue

        match = _REHOST_TYPE_RE.match(line)
        if match:
            rehost_type = match.group(1)
            idx += 1
            continue

        idx += 1

    if credential_type and credential_verification and rehost_type:
        entry = DeviceStatusEntry(
            credential_type=credential_type,
            credential_verification=credential_verification,
            rehost_type=rehost_type,
        )
        return entry, idx
    return None, idx


def _parse_swift_url(lines: list[str], start: int) -> tuple[str | None, int]:
    """Parse the SWIFT url status section."""
    idx = start
    while idx < len(lines):
        line = lines[idx]
        if _detect_section(line) is not None:
            break
        match = _SWIFT_URL_RE.match(line)
        if match:
            return match.group(1), idx + 1
        idx += 1
    return None, idx


# Map section name -> (result key, parser function)
_SectionHandler = tuple[str, Callable[[list[str], int], tuple[Any, int]]]

_SECTION_HANDLERS: dict[str, _SectionHandler] = {
    _SECTION_LICENSE_TYPE: ("license_types", _parse_license_types),
    _SECTION_LICENSE_OPERATION: ("license_operations", _parse_operations),
    _SECTION_CALLHOME_OPERATION: ("callhome_operations", _parse_callhome_operations),
    _SECTION_DEVICE_STATUS: ("device_status", _parse_device_status),
    _SECTION_SWIFT_URL_STATUS: ("swift_url", _parse_swift_url),
}


def _dispatch_section(section: str, lines: list[str], idx: int, result: dict) -> int:
    """Dispatch parsing to the appropriate section handler.

    Returns the updated line index after parsing the section.
    """
    handler = _SECTION_HANDLERS.get(section)
    if handler is None:
        return idx

    key, parse_fn = handler
    parsed, idx = parse_fn(lines, idx)
    if parsed is not None and parsed:
        result[key] = parsed

    return idx


@register(OS.CISCO_IOS, "show license status")
class ShowLicenseStatusParser(BaseParser["ShowLicenseStatusResult"]):
    """Parser for 'show license status' on IOS.

    Parses license type support, license operations, call-home operations,
    device credential status, and SWIFT URL configuration.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowLicenseStatusResult:
        """Parse 'show license status' output.

        Args:
            output: Raw CLI output from 'show license status' command.

        Returns:
            Parsed license status data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        result: dict = {}
        idx = 0

        while idx < len(lines):
            section = _detect_section(lines[idx])
            if section is None:
                idx += 1
                continue

            idx += 1  # Move past the section header
            idx = _dispatch_section(section, lines, idx, result)

        if not result:
            msg = "No license status information found in output"
            raise ValueError(msg)

        return result  # type: ignore[return-value]
