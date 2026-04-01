"""Parser for 'show isis neighbors' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisNeighborEntry(TypedDict):
    """Schema for a single IS-IS neighbor entry."""

    vrf: str
    neighbor_type: str
    snpa: str
    state: str
    hold_time: int
    circuit_id: str


class ShowIsisNeighborsResult(TypedDict):
    """Schema for 'show isis neighbors' parsed output on Arista EOS.

    Keyed by instance -> system_id -> interface.
    """

    instances: dict[str, dict[str, dict[str, IsisNeighborEntry]]]


_SKIP_PATTERN = re.compile(
    r"^\s*$"
    r"|^Instance\s+"
    r"|^-{3,}",
    re.IGNORECASE,
)

_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<instance>\S+)\s+"
    r"(?P<vrf>\S+)\s+"
    r"(?P<system_id>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<type>L[12])\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<snpa>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<hold_time>\d+)\s+"
    r"(?P<circuit_id>\S+)\s*$"
)


@register(OS.ARISTA_EOS, "show isis neighbors")
class ShowIsisNeighborsParser(BaseParser[ShowIsisNeighborsResult]):
    """Parser for 'show isis neighbors' command on Arista EOS.

    Parses IS-IS neighbor adjacencies including instance, system ID,
    adjacency type, interface, SNPA, state, hold time, and circuit ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.ISIS, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIsisNeighborsResult:
        """Parse 'show isis neighbors' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IS-IS neighbors keyed by instance, system ID, then interface.

        Raises:
            ValueError: If no IS-IS neighbors are found in the output.
        """
        instances: dict[str, dict[str, dict[str, IsisNeighborEntry]]] = {}

        for line in output.splitlines():
            if _SKIP_PATTERN.match(line):
                continue

            match = _NEIGHBOR_PATTERN.match(line)
            if not match:
                continue

            instance = match.group("instance")
            system_id = match.group("system_id")
            interface = match.group("interface")

            entry = IsisNeighborEntry(
                vrf=match.group("vrf"),
                neighbor_type=match.group("type"),
                snpa=match.group("snpa"),
                state=match.group("state"),
                hold_time=int(match.group("hold_time")),
                circuit_id=match.group("circuit_id"),
            )

            if instance not in instances:
                instances[instance] = {}
            if system_id not in instances[instance]:
                instances[instance][system_id] = {}
            instances[instance][system_id][interface] = entry

        if not instances:
            msg = "No IS-IS neighbors found in output"
            raise ValueError(msg)

        return cast(ShowIsisNeighborsResult, {"instances": instances})
