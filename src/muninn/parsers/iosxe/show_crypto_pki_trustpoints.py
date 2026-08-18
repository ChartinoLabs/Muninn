"""Parser for 'show crypto pki trustpoints' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Module-level compiled regexes
_TRUSTPOINT_HEADER_RE = re.compile(r"^Trustpoint\s+(.+?)\s*:\s*$")
_SUBJECT_NAME_RE = re.compile(r"^\s+Subject Name:\s*$")
_DN_ATTR_RE = re.compile(r"^\s+(\w+)=(.+?)\s*$")
_SERIAL_RE = re.compile(r"^\s+Serial Number\s*\(hex\)\s*:\s*([0-9A-Fa-f]+)\s*$")
_KEY_LABEL_RE = re.compile(r"^\s+Using key label\s+(.+?)\s*$")


class TrustpointEntry(TypedDict):
    """Schema for a single trustpoint entry."""

    subject_name: NotRequired[dict[str, str]]
    serial_number: NotRequired[str]
    status: NotRequired[str]
    key_label: NotRequired[str]


class ShowCryptoPkiTrustpointsResult(TypedDict):
    """Schema for 'show crypto pki trustpoints' parsed output.

    Keyed by trustpoint name.
    """

    trustpoints: dict[str, TrustpointEntry]


class _ParseState:
    """Mutable state for the trustpoint parser loop."""

    __slots__ = (
        "current_name",
        "current_entry",
        "in_subject_name",
        "subject_dn",
        "trustpoints",
    )

    def __init__(self) -> None:
        self.trustpoints: dict[str, TrustpointEntry] = {}
        self.current_name: str | None = None
        self.current_entry: dict[str, str | dict[str, str]] = {}
        self.in_subject_name: bool = False
        self.subject_dn: dict[str, str] = {}

    def start_new_trustpoint(self, name: str) -> None:
        """Finalize current entry and start a new trustpoint."""
        _finalize_entry(self)
        self.current_name = name
        self.current_entry = {}
        self.in_subject_name = False
        self.subject_dn = {}


def _finalize_entry(state: "_ParseState") -> None:
    """Finalize and store the current trustpoint entry."""
    if state.current_name is None:
        return

    if state.subject_dn:
        state.current_entry["subject_name"] = state.subject_dn

    state.trustpoints[state.current_name] = cast(
        TrustpointEntry, dict(state.current_entry)
    )


def _try_detail_line(
    line: str,
    state: "_ParseState",
) -> bool:
    """Try to parse a detail line (serial, key label, or status).

    Returns True if the line was consumed.
    """
    serial_m = _SERIAL_RE.match(line)
    if serial_m:
        state.current_entry["serial_number"] = serial_m.group(1)
        return True

    key_m = _KEY_LABEL_RE.match(line)
    if key_m:
        state.current_entry["key_label"] = key_m.group(1)
        return True

    # Status line (e.g. "Certificate configured.",
    # "Persistent self-signed certificate trust point")
    stripped = line.strip()
    if stripped:
        state.current_entry["status"] = stripped
        return True

    return False


@register(OS.CISCO_IOSXE, "show crypto pki trustpoints")
class ShowCryptoPkiTrustpointsParser(
    BaseParser["ShowCryptoPkiTrustpointsResult"],
):
    """Parser for 'show crypto pki trustpoints' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiTrustpointsResult:
        """Parse 'show crypto pki trustpoints' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed trustpoint details keyed by trustpoint name.

        Raises:
            ValueError: If no trustpoint entries found in output.
        """
        state = _ParseState()

        for line in output.splitlines():
            m = _TRUSTPOINT_HEADER_RE.match(line)
            if m:
                state.start_new_trustpoint(m.group(1))
                continue

            if state.current_name is None:
                continue

            if _SUBJECT_NAME_RE.match(line):
                state.in_subject_name = True
                continue

            if state.in_subject_name:
                dn_m = _DN_ATTR_RE.match(line)
                if dn_m:
                    state.subject_dn[dn_m.group(1)] = dn_m.group(2)
                    continue
                state.in_subject_name = False

            _try_detail_line(line, state)

        # Finalize last entry
        _finalize_entry(state)

        if not state.trustpoints:
            msg = "No PKI trustpoint entries found in output"
            raise ValueError(msg)

        return cast(
            ShowCryptoPkiTrustpointsResult,
            {"trustpoints": state.trustpoints},
        )
