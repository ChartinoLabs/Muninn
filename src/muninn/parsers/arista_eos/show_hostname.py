"""Parser for 'show hostname' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowHostnameResult(TypedDict):
    """Schema for 'show hostname' parsed output on Arista EOS."""

    hostname: str
    fqdn: NotRequired[str]


@register(OS.ARISTA_EOS, "show hostname")
class ShowHostnameParser(BaseParser[ShowHostnameResult]):
    """Parser for 'show hostname' command on Arista EOS.

    Parses the device hostname and optional FQDN.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _HOSTNAME_PATTERN = re.compile(r"^Hostname:\s+(?P<hostname>\S+)")
    _FQDN_PATTERN = re.compile(r"^FQDN:\s+(?P<fqdn>\S+)")

    @classmethod
    def parse(cls, output: str) -> ShowHostnameResult:
        """Parse 'show hostname' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed hostname information.

        Raises:
            ValueError: If hostname cannot be parsed from output.
        """
        hostname: str | None = None
        fqdn: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := cls._HOSTNAME_PATTERN.match(stripped):
                hostname = match.group("hostname")
                continue

            if match := cls._FQDN_PATTERN.match(stripped):
                fqdn = match.group("fqdn")
                continue

        if hostname is None:
            msg = "No hostname found in output"
            raise ValueError(msg)

        result = ShowHostnameResult(hostname=hostname)

        # Only include FQDN if it differs from hostname
        # (i.e., it actually contains a domain)
        if fqdn is not None and fqdn != hostname:
            result["fqdn"] = fqdn

        return result
