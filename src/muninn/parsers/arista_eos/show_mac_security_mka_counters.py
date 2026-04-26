"""Parser for 'show mac security mka counters' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MkaCountersEntry(TypedDict):
    """Schema for a single interface's MKA counters."""

    rx_success: int
    rx_failure: int
    tx_success: int
    tx_failure: int


@register(OS.ARISTA_EOS, "show mac security mka counters")
class ShowMacSecurityMkaCountersParser(
    BaseParser[dict[str, MkaCountersEntry]],
):
    """Parser for 'show mac security mka counters' on Arista EOS.

    Returns a dict-of-dicts keyed by interface name containing
    MKA PDU transmit and receive counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MACSEC})

    _COUNTER_LINE = re.compile(
        r"^(?P<interface>\S+)"
        r"\s+(?P<rx_success>\d+)"
        r"\s+(?P<rx_failure>\d+)"
        r"\s+(?P<tx_success>\d+)"
        r"\s+(?P<tx_failure>\d+)"
    )

    @classmethod
    def parse(cls, output: str) -> dict[str, MkaCountersEntry]:
        """Parse 'show mac security mka counters' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by interface name with MKA counter values.

        Raises:
            ValueError: If no counter data is found in output.
        """
        result: dict[str, MkaCountersEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = cls._COUNTER_LINE.match(stripped)
            if not match:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.ARISTA_EOS
            )

            result[interface] = MkaCountersEntry(
                rx_success=int(match.group("rx_success")),
                rx_failure=int(match.group("rx_failure")),
                tx_success=int(match.group("tx_success")),
                tx_failure=int(match.group("tx_failure")),
            )

        if not result:
            msg = "No MKA counter data found in output"
            raise ValueError(msg)

        return result
