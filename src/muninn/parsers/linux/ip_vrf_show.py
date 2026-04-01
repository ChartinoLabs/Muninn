"""Parser for 'ip vrf show' command on Linux."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class VrfEntry(TypedDict):
    """Schema for a single VRF entry."""

    name: str
    table_id: int


IpVrfShowResult = dict[str, VrfEntry]

_VRF_LINE_RE = re.compile(r"^(?P<name>\S+)\s+(?P<table_id>\d+)\s*$")


@register(OS.LINUX, "ip vrf show")
class IpVrfShowParser(BaseParser[IpVrfShowResult]):
    """Parser for 'ip vrf show' command on Linux.

    Parses VRF information into a dict-of-dicts keyed by VRF name.
    Each entry contains the VRF name and its associated routing table ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.VRF,
        }
    )

    @classmethod
    def parse(cls, output: str) -> IpVrfShowResult:
        """Parse 'ip vrf show' output on Linux.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of VRF entries keyed by VRF name.

        Raises:
            ValueError: If no VRFs can be parsed from the output.
        """
        result: dict[str, VrfEntry] = {}

        for line in output.splitlines():
            match = _VRF_LINE_RE.match(line.strip())
            if match:
                name = match.group("name")
                table_id = int(match.group("table_id"))
                result[name] = VrfEntry(name=name, table_id=table_id)

        if not result:
            msg = "No VRFs found in output"
            raise ValueError(msg)

        return cast(IpVrfShowResult, result)
