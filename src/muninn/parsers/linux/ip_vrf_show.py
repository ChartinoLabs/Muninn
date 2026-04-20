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


class IpVrfShowResult(TypedDict):
    """Top-level schema for 'ip vrf show' output."""

    vrfs: dict[str, VrfEntry]


_VRF_LINE_RE = re.compile(r"^(?P<name>\S+)\s+(?P<table_id>\d+)\s*$")
_NO_VRF_SENTINEL = "No VRF has been configured"


@register(OS.LINUX, "ip vrf show")
class IpVrfShowParser(BaseParser[IpVrfShowResult]):
    """Parser for 'ip vrf show' command on Linux.

    Parses VRF information into a top-level dict with a 'vrfs' key, which
    maps to a dict-of-dicts keyed by VRF name. Each entry contains the VRF
    name and its associated routing table ID. The 'vrfs' dict is empty when
    no VRFs are configured on the host.
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
            Dict with a 'vrfs' key mapping to VRF entries keyed by VRF name.
            The 'vrfs' dict is empty when no VRFs are configured.

        Raises:
            ValueError: If the output cannot be recognized as 'ip vrf show'
                output (no data rows and no 'no VRFs' sentinel).
        """
        vrfs: dict[str, VrfEntry] = {}

        if _NO_VRF_SENTINEL in output:
            return cast(IpVrfShowResult, {"vrfs": vrfs})

        for line in output.splitlines():
            match = _VRF_LINE_RE.match(line.strip())
            if match:
                name = match.group("name")
                table_id = int(match.group("table_id"))
                vrfs[name] = VrfEntry(name=name, table_id=table_id)

        if not vrfs:
            msg = "No VRFs found in output"
            raise ValueError(msg)

        return cast(IpVrfShowResult, {"vrfs": vrfs})
