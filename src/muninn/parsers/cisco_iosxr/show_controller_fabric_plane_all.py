"""Parser for 'show controller fabric plane all' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FabricPlaneEntry(TypedDict):
    """Schema for a single fabric plane entry."""

    admin_state: str
    plane_state: str
    up_to_dn_counter: int
    up_to_mcast_counter: int


ShowControllerFabricPlaneAllResult = dict[str, FabricPlaneEntry]


@register(OS.CISCO_IOSXR, "show controller fabric plane all")
class ShowControllerFabricPlaneAllParser(
    BaseParser[ShowControllerFabricPlaneAllResult],
):
    """Parser for 'show controller fabric plane all' command.

    Parses fabric plane status including admin state, plane state,
    and error counters for each plane ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    _PLANE_LINE = re.compile(
        r"^(?P<id>\d+)\s+"
        r"(?P<admin_state>\S+)\s+"
        r"(?P<plane_state>\S+)\s+"
        r"(?P<up_to_dn>\d+)\s+"
        r"(?P<up_to_mcast>\d+)\s*$",
    )

    @classmethod
    def parse(cls, output: str) -> ShowControllerFabricPlaneAllResult:
        """Parse 'show controller fabric plane all' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by plane ID with plane state information.

        Raises:
            ValueError: If no fabric plane entries are found.
        """
        result: ShowControllerFabricPlaneAllResult = {}

        for line in output.splitlines():
            match = cls._PLANE_LINE.match(line.strip())
            if match:
                plane_id = match.group("id")
                result[plane_id] = FabricPlaneEntry(
                    admin_state=match.group("admin_state"),
                    plane_state=match.group("plane_state"),
                    up_to_dn_counter=int(match.group("up_to_dn")),
                    up_to_mcast_counter=int(match.group("up_to_mcast")),
                )

        if not result:
            msg = "No fabric plane entries found in output"
            raise ValueError(msg)

        return result
