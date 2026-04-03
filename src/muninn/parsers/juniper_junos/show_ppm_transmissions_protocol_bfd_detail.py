"""Parser for 'show ppm transmissions protocol bfd detail' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PpmBfdTransmissionEntry(TypedDict):
    """Schema for a single PPM BFD transmission entry."""

    protocol: str
    transmission_interval: int
    distributed: bool
    distribution_handle: int
    distribution_address: str
    ifl_index: int
    replicated: bool


@register(OS.JUNIPER_JUNOS, "show ppm transmissions protocol bfd detail")
class ShowPpmTransmissionsProtocolBfdDetailParser(
    BaseParser[dict[str, PpmBfdTransmissionEntry]],
):
    """Parser for 'show ppm transmissions protocol bfd detail' on Juniper Junos.

    Returns a dict-of-dicts keyed by destination address. Each entry contains
    protocol, transmission interval, distribution details, IFL index, and
    replication status.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BFD})

    _DESTINATION = re.compile(
        r"^Destination:\s+(?P<destination>\S+),\s+"
        r"Protocol:\s+(?P<protocol>\S+),\s+"
        r"Transmission interval:\s+(?P<interval>\d+)"
    )
    _DISTRIBUTED = re.compile(
        r"^Distributed:\s+(?P<distributed>\S+),\s+"
        r"Distribution handle:\s+(?P<handle>\d+),\s+"
        r"Distribution address:\s+(?P<address>\S+)"
    )
    _IFL_INDEX = re.compile(r"^IFL-index:\s+(?P<ifl_index>\d+)")
    _REPLICATED = re.compile(r"^Replicated\s*$")
    _NOT_REPLICATED = re.compile(r"^Not-Replicated\s*$")

    @classmethod
    def _parse_detail_line(cls, stripped: str, entry: dict[str, object]) -> None:
        """Parse a detail line (non-destination) into the current entry."""
        if match := cls._DISTRIBUTED.match(stripped):
            entry["distributed"] = match.group("distributed").upper() == "TRUE"
            entry["distribution_handle"] = int(match.group("handle"))
            entry["distribution_address"] = match.group("address")
        elif match := cls._IFL_INDEX.match(stripped):
            entry["ifl_index"] = int(match.group("ifl_index"))
        elif cls._REPLICATED.match(stripped):
            entry["replicated"] = True
        elif cls._NOT_REPLICATED.match(stripped):
            entry["replicated"] = False

    @classmethod
    def _flush_entry(
        cls,
        dest: str | None,
        entry: dict[str, object],
        result: dict[str, PpmBfdTransmissionEntry],
    ) -> None:
        """Store a completed entry in the result dict."""
        if dest is not None and entry:
            result[dest] = cast(PpmBfdTransmissionEntry, entry)

    @classmethod
    def parse(cls, output: str) -> dict[str, PpmBfdTransmissionEntry]:
        """Parse 'show ppm transmissions protocol bfd detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by destination address with transmission details.

        Raises:
            ValueError: If no transmission entries are found.
        """
        result: dict[str, PpmBfdTransmissionEntry] = {}
        current: dict[str, object] = {}
        current_dest: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := cls._DESTINATION.match(stripped):
                cls._flush_entry(current_dest, current, result)
                current_dest = match.group("destination")
                current = {
                    "protocol": match.group("protocol"),
                    "transmission_interval": int(match.group("interval")),
                }
            else:
                cls._parse_detail_line(stripped, current)

        cls._flush_entry(current_dest, current, result)

        if not result:
            msg = "No PPM BFD transmission entries found in output"
            raise ValueError(msg)

        return result
