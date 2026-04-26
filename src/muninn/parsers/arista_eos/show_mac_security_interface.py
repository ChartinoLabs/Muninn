"""Parser for 'show mac security interface' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_CONTROLLED_PORT_TRUE = "True"


class MacSecurityInterfaceEntry(TypedDict):
    """Schema for a single MACsec interface entry."""

    sci: str
    controlled_port: bool
    key_in_use: str


@register(OS.ARISTA_EOS, "show mac security interface")
class ShowMacSecurityInterfaceParser(
    BaseParser[dict[str, MacSecurityInterfaceEntry]],
):
    """Parser for 'show mac security interface' command on Arista EOS.

    Returns a dict-of-dicts keyed by interface name, each containing
    SCI, controlled port status, and key in use.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MACSEC})

    _HEADER_PATTERN = re.compile(
        r"^Interface\s+SCI\s+Controlled\s+Port\s+Key\s+in\s+Use",
    )

    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)"
        r"\s+(?P<sci>\S+)"
        r"\s+(?P<controlled_port>True|False)"
        r"\s+(?P<key_in_use>\S+)",
    )

    @classmethod
    def _parse_row(cls, match: re.Match[str]) -> tuple[str, MacSecurityInterfaceEntry]:
        """Extract interface name and entry from a regex match."""
        interface = canonical_interface_name(match.group("interface"), os=OS.ARISTA_EOS)
        return interface, cast(
            MacSecurityInterfaceEntry,
            {
                "sci": match.group("sci"),
                "controlled_port": match.group("controlled_port")
                == _CONTROLLED_PORT_TRUE,
                "key_in_use": match.group("key_in_use"),
            },
        )

    @classmethod
    def _find_data_lines(cls, output: str) -> list[str]:
        """Return lines after the header row, skipping blanks."""
        lines = output.splitlines()
        for idx, line in enumerate(lines):
            if cls._HEADER_PATTERN.match(line.strip()):
                return [ln for ln in lines[idx + 1 :] if ln.strip()]
        return []

    @classmethod
    def parse(cls, output: str) -> dict[str, MacSecurityInterfaceEntry]:
        """Parse 'show mac security interface' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by interface name with MACsec interface details.

        Raises:
            ValueError: If no valid entries are found in the output.
        """
        result: dict[str, MacSecurityInterfaceEntry] = {}

        for line in cls._find_data_lines(output):
            match = cls._ROW_PATTERN.match(line.strip())
            if match:
                interface, entry = cls._parse_row(match)
                result[interface] = entry

        if not result:
            msg = "No MACsec interface entries found in output"
            raise ValueError(msg)

        return result
