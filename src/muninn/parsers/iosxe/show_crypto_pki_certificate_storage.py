"""Parser for 'show crypto pki certificate storage' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_ENTRY_RE = re.compile(
    r"^(?P<trustpoint>\S+)"
    r"\s+-\s+certificates will be stored\s+"
    r"(?P<storage>.+?)\s*$"
)


class TrustpointEntry(TypedDict):
    """A single trustpoint certificate storage entry."""

    storage: str


class ShowCryptoPkiCertificateStorageResult(TypedDict):
    """Schema for 'show crypto pki certificate storage' parsed output.

    Keyed by trustpoint name.
    """

    trustpoints: dict[str, TrustpointEntry]


@register(OS.CISCO_IOSXE, "show crypto pki certificate storage")
class ShowCryptoPkiCertificateStorageParser(
    BaseParser[ShowCryptoPkiCertificateStorageResult],
):
    """Parser for 'show crypto pki certificate storage' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoPkiCertificateStorageResult:
        """Parse 'show crypto pki certificate storage' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dictionary with trustpoints keyed by name, each containing
            the certificate storage location.

        Raises:
            ValueError: If no trustpoint entries are found in the output.
        """
        trustpoints: dict[str, TrustpointEntry] = {}
        for line in output.splitlines():
            match = _ENTRY_RE.match(line)
            if match is None:
                continue
            name = match.group("trustpoint")
            storage = match.group("storage")
            trustpoints[name] = TrustpointEntry(storage=storage)

        if not trustpoints:
            msg = "No trustpoint certificate storage entries found in output"
            raise ValueError(msg)

        return cast(
            ShowCryptoPkiCertificateStorageResult,
            {"trustpoints": trustpoints},
        )
