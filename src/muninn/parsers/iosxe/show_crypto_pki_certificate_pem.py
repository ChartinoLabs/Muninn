"""Parser for 'show crypto pki certificate pem' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Trustpoint section header: ``------Trustpoint: <name>------``
_TRUSTPOINT_RE = re.compile(r"^-{2,}Trustpoint:\s*(?P<name>.+?)-{2,}$")

# Certificate type label: ``% Self-signed CA certificate:``
_CERT_TYPE_RE = re.compile(r"^%\s+(?P<type>.+?)\s*:\s*$")

# Not-enrolled message: ``% The specified trustpoint is not enrolled (<name>).``
_NOT_ENROLLED_RE = re.compile(r"^%\s+The specified trustpoint is not enrolled")

# PEM envelope markers.
_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_PEM_END = "-----END CERTIFICATE-----"


class CertificateEntry(TypedDict):
    """Schema for a single PEM certificate entry.

    Attributes:
        type: The certificate type label as printed by the device
            (e.g. ``Self-signed CA certificate``,
            ``General Purpose Certificate``).
        pem: Full PEM block including BEGIN/END markers.
        not_enrolled: Present and ``True`` when the trustpoint reports
            it is not enrolled for this certificate type.
    """

    type: str
    pem: NotRequired[str]
    not_enrolled: NotRequired[bool]


class ShowCryptoPkiCertificatePemResult(TypedDict):
    r"""Schema for 'show crypto pki certificate pem' parsed output.

    Keyed by trustpoint name, then by certificate type label.
    """

    trustpoints: dict[str, dict[str, CertificateEntry]]


class _ParseState:
    """Mutable parsing state for the certificate PEM parser."""

    __slots__ = (
        "trustpoints",
        "current_tp",
        "current_tp_name",
        "cert_type",
        "pem_lines",
        "in_pem",
        "not_enrolled",
    )

    def __init__(self) -> None:
        self.trustpoints: dict[str, dict[str, CertificateEntry]] = {}
        self.current_tp: dict[str, CertificateEntry] | None = None
        self.current_tp_name: str | None = None
        self.cert_type: str | None = None
        self.pem_lines: list[str] = []
        self.in_pem: bool = False
        self.not_enrolled: bool = False

    def finalize_current_cert(self) -> None:
        """Write the in-progress certificate entry to the trustpoint."""
        if self.current_tp is None or self.cert_type is None:
            return
        entry: dict[str, object] = {"type": self.cert_type}
        if self.pem_lines:
            entry["pem"] = "\n".join(self.pem_lines)
        if self.not_enrolled:
            entry["not_enrolled"] = True
        self.current_tp[self.cert_type] = cast(CertificateEntry, entry)

    def start_new_trustpoint(self, name: str) -> None:
        """Finalize the previous trustpoint and start a new one."""
        self.finalize_current_cert()
        if self.current_tp is not None and self.current_tp_name is not None:
            self.trustpoints[self.current_tp_name] = self.current_tp
        self.current_tp_name = name
        self.current_tp = {}
        self.cert_type = None
        self.pem_lines = []
        self.in_pem = False
        self.not_enrolled = False

    def start_new_cert_type(self, cert_type: str) -> None:
        """Finalize the previous cert and start collecting a new type."""
        self.finalize_current_cert()
        self.cert_type = cert_type
        self.pem_lines = []
        self.in_pem = False


def _process_pem_line(state: _ParseState, stripped: str) -> None:
    """Attempt to consume the line as PEM content."""
    if stripped == _PEM_BEGIN:
        state.pem_lines.clear()
        state.pem_lines.append(_PEM_BEGIN)
        state.in_pem = True
    elif stripped == _PEM_END:
        state.pem_lines.append(_PEM_END)
        state.in_pem = False
    elif state.in_pem and stripped:
        state.pem_lines.append(stripped)


@register(OS.CISCO_IOSXE, "show crypto pki certificate pem")
class ShowCryptoPkiCertificatePemParser(
    BaseParser[ShowCryptoPkiCertificatePemResult],
):
    """Parser for 'show crypto pki certificate pem' on IOS-XE.

    Produces a mapping of trustpoint name to its certificates, each
    keyed by type label and containing the full PEM block.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiCertificatePemResult:
        """Parse 'show crypto pki certificate pem' output.

        Args:
            output: Raw CLI output from the device.

        Returns:
            Structured mapping of trustpoint name to certificate entries.

        Raises:
            ValueError: If no trustpoint header is found.
        """
        state = _ParseState()

        for line in output.splitlines():
            tp_match = _TRUSTPOINT_RE.match(line)
            if tp_match is not None:
                state.start_new_trustpoint(tp_match.group("name"))
                continue

            if state.current_tp is None:
                continue

            if _NOT_ENROLLED_RE.match(line):
                state.not_enrolled = True
                continue

            type_match = _CERT_TYPE_RE.match(line)
            if type_match is not None:
                state.start_new_cert_type(type_match.group("type"))
                continue

            _process_pem_line(state, line.strip())

        # Finalize last certificate and trustpoint.
        state.finalize_current_cert()
        if state.current_tp is not None and state.current_tp_name is not None:
            state.trustpoints[state.current_tp_name] = state.current_tp

        if not state.trustpoints:
            msg = (
                "Missing trustpoint header; output does not appear to "
                "be from 'show crypto pki certificate pem'."
            )
            raise ValueError(msg)
        return cast(
            ShowCryptoPkiCertificatePemResult,
            {"trustpoints": state.trustpoints},
        )
