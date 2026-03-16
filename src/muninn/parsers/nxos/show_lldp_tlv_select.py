"""Parser for 'show lldp tlv-select' command on NX-OS."""

from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowLldpTlvSelectResult(TypedDict):
    """Schema for 'show lldp tlv-select' parsed output."""

    suppress_tlv_advertisement: dict[str, bool]


@register(OS.CISCO_NXOS, "show lldp tlv-select")
class ShowLldpTlvSelectParser(BaseParser[ShowLldpTlvSelectResult]):
    """Parser for 'show lldp tlv-select' command."""

    tags: ClassVar[frozenset[str]] = frozenset({"lldp"})

    @classmethod
    def parse(cls, output: str) -> ShowLldpTlvSelectResult:
        """Parse 'show lldp tlv-select' output.

        Args:
            output: Raw CLI output from 'show lldp tlv-select' command.

        Returns:
            Parsed TLV select data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        tlv_map: dict[str, bool] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            key = line.lower().replace("-", "_")
            tlv_map[key] = False

        if not tlv_map:
            msg = "No TLV selections found"
            raise ValueError(msg)

        return ShowLldpTlvSelectResult(suppress_tlv_advertisement=tlv_map)
