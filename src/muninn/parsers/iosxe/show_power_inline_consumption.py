"""Parser for 'show power inline consumption' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PowerInlineConsumptionEntry(TypedDict):
    """Schema for a single power inline consumption entry."""

    consumption_configured: str
    admin_consumption_watts: float


class ShowPowerInlineConsumptionResult(TypedDict):
    """Schema for 'show power inline consumption' parsed output."""

    interfaces: dict[str, PowerInlineConsumptionEntry]


@register(OS.CISCO_IOSXE, "show power inline consumption")
class ShowPowerInlineConsumptionParser(
    BaseParser[ShowPowerInlineConsumptionResult],
):
    """Parser for 'show power inline consumption' command.

    Example output:
        Interface  Consumption      Admin
                   Configured    Consumption (Watts)
        ---------- -----------  -------------------
        Gi1/3          NO                 0.0
        Gi1/4          NO                 0.0
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.POE, ParserTag.SYSTEM})

    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+(?P<configured>YES|NO)\s+(?P<watts>\d+(?:\.\d+)?)$",
    )

    _HEADER_PATTERN = re.compile(r"^-{2,}")

    @classmethod
    def parse(cls, output: str) -> ShowPowerInlineConsumptionResult:
        """Parse 'show power inline consumption' output.

        Args:
            output: Raw CLI output from 'show power inline consumption' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        interfaces: dict[str, PowerInlineConsumptionEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if cls._HEADER_PATTERN.match(line):
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                interface = canonical_interface_name(
                    match.group("interface"),
                    os=OS.CISCO_IOSXE,
                )
                interfaces[interface] = {
                    "consumption_configured": match.group("configured"),
                    "admin_consumption_watts": float(match.group("watts")),
                }

        if not interfaces:
            msg = "No power inline consumption entries found in output"
            raise ValueError(msg)

        return {"interfaces": interfaces}
